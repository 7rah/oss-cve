https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist/denylist bypassed via a `>&word` redirect whose target is promoted into command position

Affected Version: commit b867ec9 (v3.53.0) and commit 27001b2 (v3.54.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. Before matching, `getCommandDecision` strips shell redirections with the regex `/\d*>&\d*/`, intending to drop file-descriptor duplications such as `2>&1`. But the digits after `&` are optional (`\d*`, zero or more), so the regex also matches a bare `>&` — which in bash is not an fd-duplication but the "redirect stdout and stderr to a file" operator. Stripping the operator alone leaves its target word in command position: `>&echo touch /tmp/ROO_PWNED` is checked as `echo touch /tmp/ROO_PWNED`, matches the `echo` allowlist prefix, and is auto-approved. Bash instead parses the string as "redirect stdout+stderr to the file `echo`, then run `touch /tmp/ROO_PWNED`", so the denied command `touch` executes without approval. Confirmed against the `getCommandDecision` function.

### Details

The decision is made in `src/core/auto-approval/commands.ts`. `getCommandDecision` splits the command into sub-commands and, for each, strips redirections before checking it against the allow/deny lists (lines 267 to 273):

```ts
// Parse into sub-commands (split by &&, ||, ;, |)
const subCommands = parseCommand(command)

const decisions: CommandDecision[] = subCommands.map((cmd) => {
    // Remove simple PowerShell-like redirections (e.g. 2>&1) before checking
    const cmdWithoutRedirection = cmd.replace(/\d*>&\d*/, "").trim()
    return getSingleCommandDecision(cmdWithoutRedirection, allowedCommands, deniedCommands)
})
```

The regex `/\d*>&\d*/` targets fd-duplication redirections, whose operand after `&` is always a number (`2>&1`, `1>&2`). But `\d*` also matches zero digits, so it strips a bare `>&` as well. In bash these are two different constructs:

- `2>&1` — duplicate fd 2 onto fd 1 (target is a digit).
- `>&word` — redirect both stdout and stderr to the file `word` (target is a filename).

For the input `>&echo touch /tmp/ROO_PWNED`, the strip removes only the `>&` operator, leaving `echo touch /tmp/ROO_PWNED`, which is checked as-is. That string begins with the allowlisted prefix `echo`, so `getSingleCommandDecision` returns `auto_approve`.

Bash parses the untouched string differently. A redirection may precede the command, so `>&echo touch /tmp/ROO_PWNED` means: redirect stdout+stderr to the file named `echo`, then run the simple command `touch /tmp/ROO_PWNED`. The word the gate took for the command (`echo`) is a redirect target to bash, and the command bash actually runs (`touch`) never reaches the allow/deny check.

The defect is decision-side, independent of the tokenizer: `parse-command.ts` captures `>&` into a `__REDIR_N__` placeholder and restores it intact, so the sub-command still carries the redirect. It is the `getCommandDecision` strip at line 271 that discards the operator and promotes its target into command position.

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
  "echo hi 2>&1",                     // control -> auto_approve (legit fd-duplication, must stay approved)
  ">&notecho touch /tmp/ROO_PWNED",   // control -> ask_user     (redirect target is not allowlisted)
  ">&echo touch /tmp/ROO_PWNED",      // BYPASS  -> auto_approve  (should deny; bash runs `touch`)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_approve <- "echo hi 2>&1"
ask_user     <- ">&notecho touch /tmp/ROO_PWNED"
auto_approve <- ">&echo touch /tmp/ROO_PWNED"     (BYPASS, should deny)
```

The controls show the gate is otherwise sound: bare `touch` is caught, a real `2>&1` fd-duplication still auto-approves, and a redirect target that is not allowlisted (`notecho`) falls through to `ask_user`. Only the `>&echo touch /tmp/ROO_PWNED` form is wrongly approved.

Bash confirms which command actually runs:

```bash
bash -c '>&echo touch /tmp/ROO_PWNED'
# creates a file literally named "echo" (the redirect target)
# and runs `touch /tmp/ROO_PWNED` (the command after the redirect)
```

Both files appear: the denied command after the redirect executes, while the gate approved on the redirect target.

### Impact

A denied or unlisted command placed after a `>&<allowlisted-prefix>` redirect is auto-approved and executed without user consent, defeating the allow/deny control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `>&<allowed prefix> <denied command>`, which then auto-runs with the agent's auto-execute privileges on the developer's machine.

### Remediation

At `src/core/auto-approval/commands.ts` line 271, require at least one digit after `&`, so only true fd-duplications are stripped:

```ts
const cmdWithoutRedirection = cmd.replace(/\d*>&\d+/, "").trim()
```

With `>&word` left intact, the sub-command begins with `>&` (or a digit plus `>&`), matches no letter-starting allowlist prefix, and falls through to `ask_user`. Legitimate fd-duplication stripping (`2>&1`, `1>&2`) still works, so `echo hi 2>&1` continues to auto-approve. More robustly, parse redirections structurally rather than by regex, and never let a redirect target occupy command position in the allow/deny check.
