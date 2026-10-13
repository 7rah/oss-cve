https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via a `*` glob, whose token discards the word — including a nested command substitution — from the approval check

Affected Version: commit b867ec9 (v3.53.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. `parseCommand` masks a `$(...)` command substitution into a `__SUBSH_N__` placeholder and, when that placeholder survives tokenization as its own token, extracts the inner command and checks it against the lists. But when the substitution is written adjacent to a glob metacharacter — `*` or `?` — `shell-quote` folds the whole word into a single glob token whose text lives in a `pattern` field, e.g. `{ op: "glob", pattern: "*__SUBSH_0__" }`. `parseCommand`'s token loop handles a non-separator operator token by pushing only its `op` name (the literal string `"glob"`) and discarding every other field, so the `pattern` — and the `__SUBSH_0__` placeholder inside it — is thrown away. The inner command is never checked. So `echo *$(touch /tmp/ROO_PWNED)` is parsed to the single sub-command `echo glob`, matches the `echo` allowlist prefix, and is auto-approved, while bash runs the command substitution and executes `touch`. Removing the `*` makes the identical substitution surface as its own sub-command and be denied, so the gap is exactly the glob token. Confirmed against the `getCommandDecision` and `parseCommand` functions, with execution confirmed on bash 5.3.15 and bash 3.2.57.

### Details

The decision is made in `src/core/auto-approval/commands.ts`; `getCommandDecision` calls `parseCommand` (`src/shared/parse-command.ts`) to split the command into sub-commands, then checks each against the allow/deny lists. `parseCommand` first replaces each `$(...)` with a placeholder and stores the inner command (`parse-command.ts:101`):

```ts
processedCommand = processedCommand
    .replace(/\$\((.*?)\)/g, (_, inner) => {
        subshells.push(inner.trim())
        return `__SUBSH_${subshells.length - 1}__`
    })
```

For `echo *$(touch /tmp/ROO_PWNED)`, `subshells[0]` becomes `touch /tmp/ROO_PWNED` and the string becomes `echo *__SUBSH_0__`. The extraction that later *checks* that inner command only fires when the placeholder survives tokenization as a bare string token (`parse-command.ts:162`):

```ts
} else if (typeof token === "string") {
    const subshellMatch = token.match(/__SUBSH_(\d+)__/)
    if (subshellMatch) {
        // push subshells[...] as its own sub-command to be checked
    }
```

But `shell-quote` does not return `*__SUBSH_0__` as a string. The leading `*` makes it a glob:

```
parse("echo *__SUBSH_0__")  ->  ["echo", { op: "glob", pattern: "*__SUBSH_0__" }]
```

The placeholder is now buried in the token's `pattern` field. The token loop's operator branch (`parse-command.ts:149-159`) splits only on the separators `&&`, `||`, `;`, `|`, `&`; any other operator token falls to the `else`:

```ts
} else {
    // Other operators (>) are part of the command
    currentCommand.push(token.op)
}
```

It pushes `token.op` — the string `"glob"` — and discards `token.pattern` entirely. So `currentCommand` becomes `["echo", "glob"]`, joined to `echo glob`. At restore time there is no `__SUBSH_0__` left in the text (it was in the discarded pattern), so `subshells[0] = "touch /tmp/ROO_PWNED"` is never checked. The parser reports the single sub-command `echo glob`, which begins with the allowlisted prefix `echo`, and it is auto-approved.

Whether the inner command is checked therefore depends on the placeholder remaining a standalone token after `shell-quote` runs. That is a fragile invariant: a single glob metacharacter (`*` or `?`) adjacent to the substitution absorbs the placeholder into a glob token and the inner command vanishes from the check. The same defect is a sibling of the `|&` bypass: both come from the token loop's `else` branch reducing a non-separator operator token to its bare `op` string — `|&` is folded into the current command, and a glob token's real content is dropped.

bash runs the command substitution regardless of the surrounding glob. In `echo *$(touch /tmp/ROO_PWNED)`, bash first executes `$(touch /tmp/ROO_PWNED)` (creating the file, substituting its empty output), then expands `*` as a pathname glob, then runs `echo`. The denied `touch` has already run.

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
  "echo $(touch /tmp/ROO_PWNED)",     // control -> auto_deny    (no glob: $() inner surfaces and is denied)
  "echo *$(touch /tmp/ROO_PWNED)",    // BYPASS  -> auto_approve  (a leading * makes it a glob; pattern discarded)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_deny    <- "echo $(touch /tmp/ROO_PWNED)"
auto_approve <- "echo *$(touch /tmp/ROO_PWNED)"     (BYPASS, should deny)
```

The no-glob control isolates the root cause: the identical `$(touch ...)` is extracted as its own sub-command and denied; adding one `*` turns the word into a glob token and the inner `touch` disappears from the check. `?` behaves the same way (it yields the `echo glob` sub-command). Bracket globs `[...]` do **not** trigger it — `shell-quote` flags only `*` and `?` as globs (`parse.js`: `c === '*' || c === '?'`), so a bracketed word keeps the placeholder as a bare string token and its inner command is still extracted and denied.

Bash confirms the substitution runs under the glob:

```bash
bash -c 'echo $(touch /tmp/ROO_PWNED)'    # touch runs (substitution executed)
bash -c 'echo *$(touch /tmp/ROO_PWNED)'   # touch still runs; * is just a pathname glob around it
```

`/tmp/ROO_PWNED` is created, so the denied command executes while the gate approved only `echo`. Verified on GNU bash 5.3.15 and the macOS system bash 3.2.57 — the defect does not depend on any recent bash feature.

### Impact

A denied or unlisted command placed in a `$(...)` (or backtick) substitution that sits next to a glob metacharacter is dropped from the approval check but executed by bash, defeating the allow/deny control. Globs are ordinary in legitimate commands (`git log *.md`, `ls *`), so the shape `<allowed prefix> *$(<denied command>)` is unremarkable. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting such a command, which auto-runs with the agent's auto-execute privileges on the developer's machine. This is the single largest bypass family observed in the corpus.

This root cause is distinct from the command-substitution/parameter-expansion masking line (parse-command.ts masking `$(…)`/`${…}` before the `containsDangerousSubstitution` guard, e.g. CVE-2026-63108): here the substitution *is* masked and would normally be extracted, but a glob token produced during tokenization discards the placeholder afterward. The guard is not involved. The defect is in the token loop's handling of operator tokens, the same code path as the `|&` separator bypass.

### Remediation

In the token loop's `else` branch (`src/shared/parse-command.ts:156-158`), do not reduce a non-separator operator token to its `op` string and drop its payload. For a `glob` token, restore its `pattern` into the command text (so any `__SUBSH_N__` placeholder it contains is carried through and later extracted and checked), rather than emitting the literal word `"glob"`. More robustly, do not rely on "mask to a placeholder, tokenize with shell-quote, then only inspect string/operator tokens": whether a masked substitution is checked must not depend on it surviving as a standalone token, since glob, quote, and other tokens can absorb it. Re-extract command substitutions from each restored sub-command, or parse the command structurally, so an inner command cannot be discarded by an adjacent metacharacter. Any operator token the loop does not explicitly classify should fail closed (require approval) rather than be flattened to its name.
