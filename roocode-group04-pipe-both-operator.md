https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via the `|&` pipe operator, which is not treated as a command separator

Affected Version: commit b867ec9 (v3.53.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. `parseCommand` splits a command line into sub-commands on the operators it recognizes: `&&`, `||`, `;`, `|`, and `&`. It does not recognize `|&`, the bash pipe operator that connects both stdout and stderr. `shell-quote` tokenizes `|&` correctly as an operator, but `parseCommand`'s loop, not finding `|&` in its split list, folds the operator and everything after it into the current sub-command. So `echo hi |& touch /tmp/ROO_PWNED` is treated as the single sub-command `echo hi |& touch /tmp/ROO_PWNED`, matches the `echo` allowlist prefix, and is auto-approved. bash runs it as a pipeline, so the denied `touch` executes. The ordinary pipe `|` is split correctly and the same command is denied, so the gap is exactly the missing `|&`. Confirmed against the `getCommandDecision` and `parseCommand` functions.

### Details

The decision is made in `src/core/auto-approval/commands.ts`; `getCommandDecision` calls `parseCommand` (`src/shared/parse-command.ts`) to split the command into sub-commands, then checks each against the allow/deny lists. `parseCommand` tokenizes with `shell-quote` and, in its token loop, splits on operator tokens using a fixed list (`parse-command.ts:151`):

```ts
if (["&&", "||", ";", "|", "&"].includes(token.op)) {
    // start a new sub-command
} else {
    // Other operators (>) are part of the command
    currentCommand.push(token.op)
}
```

`|&` is absent from that list, so the `else` branch runs: the `|&` operator and the tokens after it are appended to the current sub-command rather than starting a new one. `shell-quote` itself parses the operator correctly — for `echo hi |& touch /tmp/ROO_PWNED` it returns:

```
["echo", "hi", { op: "|&" }, "touch", "/tmp/ROO_PWNED"]
```

Because the loop does not split on `{ op: "|&" }`, `parseCommand` returns the single sub-command `echo hi |& touch /tmp/ROO_PWNED`, which begins with the allowlisted prefix `echo` and is auto-approved. The denied `touch` is never surfaced as its own sub-command.

bash treats `|&` as `2>&1 |`: `echo hi |& touch /tmp/ROO_PWNED` pipes the stdout and stderr of `echo hi` into `touch /tmp/ROO_PWNED`, so `touch` runs. The ordinary pipe `|` is in the split list, so the otherwise-identical `echo hi | touch /tmp/ROO_PWNED` is split into `echo hi` and `touch /tmp/ROO_PWNED`, and the denied `touch` is caught — the controls below show this. The bypass is precisely the one operator the split list omits.

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
  "touch /tmp/ROO_PWNED",              // control -> auto_deny    (denied command is caught when bare)
  "echo hi | touch /tmp/ROO_PWNED",   // control -> auto_deny    (`|` is split; touch surfaced and denied)
  "echo hi |& touch /tmp/ROO_PWNED",  // BYPASS  -> auto_approve  (`|&` not split; touch folded into echo)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_deny    <- "echo hi | touch /tmp/ROO_PWNED"
auto_approve <- "echo hi |& touch /tmp/ROO_PWNED"     (BYPASS, should deny)
```

The single-pipe control is denied because `|` is split and `touch` is checked on its own; only the `|&` form, one operator away, is wrongly approved.

Bash confirms `touch` runs under `|&`:

```bash
bash -c 'echo hi |& touch /tmp/ROO_PWNED'
# |& is `2>&1 |`: echo's output is piped into `touch /tmp/ROO_PWNED`, which runs
```

The file `/tmp/ROO_PWNED` is created, so the denied command executes while the gate approved only `echo`.

### Impact

A denied or unlisted command placed after `|&` is folded into an allowlisted command by the parser but executed by bash, defeating the allow/deny control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `<allowed prefix> |& <denied command>`, which auto-runs with the agent's auto-execute privileges on the developer's machine.

### Remediation

Add `|&` to the operator split list in `src/shared/parse-command.ts` (line 151) so the pipeline is split into its component commands and each is checked:

```ts
if (["&&", "||", ";", "|", "|&", "&"].includes(token.op)) {
```

More robustly, derive the set of command separators from bash's grammar rather than an inline literal, so a newly handled operator cannot silently fold a following command into an allowlisted one. Any operator not explicitly classified should fail closed (require approval) rather than be appended to the current command.
