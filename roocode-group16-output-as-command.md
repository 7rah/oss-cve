https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via a command substitution at command position, whose output is executed as a command

Affected Version: commit b867ec9 (v3.53.0) and commit 27001b2 (v3.54.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. `parseCommand` decomposes a `$(...)` command substitution by extracting its inner command and checking that inner command against the lists. But when a command substitution sits at command position, bash does not run the inner command as the command — it runs the inner command and then executes its standard output as a command, a step the approval model never represents. So `$(echo touch /tmp/ROO_PWNED)` is checked as its inner `echo touch /tmp/ROO_PWNED`, matches the `echo` allowlist prefix, and is auto-approved; bash then runs `echo`, takes its output `touch /tmp/ROO_PWNED`, and executes that. An allowlist that contains only `echo` — a command chosen precisely because printing is harmless — therefore yields arbitrary command execution. Confirmed against the `getCommandDecision` function.

### Details

The decision is made in `src/core/auto-approval/commands.ts`. `getCommandDecision` splits the command into sub-commands and checks each against the allow/deny lists (lines 266 to 273):

```ts
const subCommands = parseCommand(command)

const decisions: CommandDecision[] = subCommands.map((cmd) => {
    const cmdWithoutRedirection = cmd.replace(/\d*>&\d*/, "").trim()
    return getSingleCommandDecision(cmdWithoutRedirection, allowedCommands, deniedCommands)
})
```

`parseCommand` (`src/shared/parse-command.ts`, lines 100 to 108) replaces each `$(...)` and backtick with a `__SUBSH_N__` placeholder and pushes the inner text as its own sub-command:

```ts
// Then handle subshell commands $() and back-ticks
processedCommand = processedCommand
    .replace(/\$\((.*?)\)/g, (_, inner) => {
        subshells.push(inner.trim())
        return `__SUBSH_${subshells.length - 1}__`
    })
```

For `$(echo touch /tmp/ROO_PWNED)`, the inner `echo touch /tmp/ROO_PWNED` becomes a sub-command; it begins with the allowlisted prefix `echo`, so `getSingleCommandDecision` returns `auto_approve`. The outer placeholder carries no command of its own.

That decomposition is correct for catching a command smuggled *inside* a substitution. It does not model command substitution *at command position*. In bash, `$(cmd)` used as the command first runs `cmd`, then executes `cmd`'s standard output as a new command. The approval check inspects the inner command (`echo ...`), but the command bash executes is the inner command's *output*. `echo <text>` prints `<text>` verbatim, so the executed command is entirely attacker-chosen while only `echo` had to be allowlisted.

The gap is visible in that the gate returns the same decision, from the same parsed sub-command, for two commands with opposite effects:

- `echo touch /tmp/ROO_PWNED` — bash prints the text; harmless.
- `$(echo touch /tmp/ROO_PWNED)` — bash executes that text; runs `touch`.

Both are parsed to the single sub-command `echo touch /tmp/ROO_PWNED` and auto-approved. The approval layer strips the `$()` and cannot tell printing from executing.

This is not merely a missing check. `getCommandDecision` does run a dedicated substitution guard, `containsDangerousSubstitution(command)` (`commands.ts:282`), which returns `ask_user` for a hand-enumerated set of dangerous substitution forms — parameter transforms (`${var@P}`), here-strings (`<<<$(...)`), and zsh process/glob substitutions (`=(...)`, `*(e:...:)`), among others. But its patterns do not match a plain `$(...)` in command position, so this case is never routed to `ask_user`; it falls through to `auto_approve`. The gap is therefore in a code path that already exists to catch dangerous substitutions — command substitution whose output becomes the command is simply outside its enumerated set.

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
  "touch /tmp/ROO_PWNED",           // control -> auto_deny    (denied command is caught when bare)
  "echo touch /tmp/ROO_PWNED",      // control -> auto_approve (echo prints its args; harmless)
  "$(echo touch /tmp/ROO_PWNED)",   // BYPASS  -> auto_approve  (same decision; but the output is executed)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_approve <- "echo touch /tmp/ROO_PWNED"
auto_approve <- "$(echo touch /tmp/ROO_PWNED)"     (BYPASS, should deny)
```

The denied `touch` is caught on its own, and the safe `echo touch /tmp/ROO_PWNED` is correctly approved. The bypass form `$(echo touch /tmp/ROO_PWNED)` receives the identical decision, because the gate checks the same inner command in both cases.

Bash confirms the output is what runs:

```bash
bash -c '$(echo touch /tmp/ROO_PWNED)'
# echo prints "touch /tmp/ROO_PWNED"; the command substitution at command
# position executes that output, so `touch /tmp/ROO_PWNED` runs
```

The file `/tmp/ROO_PWNED` is created, so the denied command executes while the gate approved only `echo`.

### Impact

An allowlist limited to a command as harmless as `echo` still permits arbitrary command execution: any `$(echo <command>)` is auto-approved and its output executed. The realistic trigger is indirect prompt injection — untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `$(echo <attacker command>)`, which auto-runs with the agent's auto-execute privileges on the developer's machine. The same defect applies to any allowlisted command that prints attacker-controlled bytes; for example `$(git diff --no-index --name-only /dev/null <path>)` executes a path the attacker controls in the workspace, needing no command word in the prompt at all.

### Remediation

A command substitution at command position must not be approved by inspecting its inner command, because the command that executes is the inner command's output, not the inner command itself. Treat any command substitution that occupies command position (the whole command, or the head of a pipeline or list) as requiring explicit user approval, or deny it, regardless of the inner command's allowlist status. Inspecting the inner command is only meaningful when the substitution is used as an argument to another command, not when its output becomes the command.
