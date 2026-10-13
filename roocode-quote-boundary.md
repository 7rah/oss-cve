https://github.com/RooCodeInc/Roo-Code - "This repository was archived by the owner on May 16, 2026. It is now read-only."

## Finding: Auto-approve command allowlist bypassed via a quote-masking regex that disagrees with bash on what a quote is (escaped `\"` and ANSI-C `$'…'`)

Affected Version: commit b867ec9 (v3.53.0) and commit 27001b2 (v3.54.0)

### Summary

When "always approve execute" is enabled, Roo Code auto-approves agent-proposed shell commands by matching each one against an allowlist and denylist. Before tokenizing, `parseCommand` masks double-quoted spans with the regex `/"[^"]*"/`, replacing each `"…"` with an opaque placeholder so quoted text cannot be misread as commands. That regex pairs `"` characters purely by counting them; it does not implement bash's quoting rules. In bash a backslash-escaped `\"` outside quotes is a literal character that does **not** open a quoted span, and `$'…'` (and `'…'`) are separate quoting contexts in which a `"` is literal. When such a `"` appears, the masker's pairing drifts out of step with bash's quote state: it treats two characters bash considers literal as a matched quote pair and swallows everything between them — including a command separator `;` and the denied command after it — into the placeholder. The separator therefore never surfaces, so `echo \";touch /tmp/ROO_PWNED;\"` is returned as the single sub-command `echo …`, matches the `echo` allowlist prefix, and is auto-approved, while bash runs `touch`. Confirmed against the `getCommandDecision` and `parseCommand` functions, with execution confirmed on bash 5.3.15 and bash 3.2.57.

### Details

The decision is made in `src/core/auto-approval/commands.ts`; `getCommandDecision` calls `parseCommand` (`src/shared/parse-command.ts`) to split the command into sub-commands, then checks each against the allow/deny lists. Before tokenizing, `parseCommand` masks double-quoted strings (`parse-command.ts:112`):

```ts
// Then handle quoted strings
processedCommand = processedCommand.replace(/"[^"]*"/g, (match) => {
    quotes.push(match)
    return `__QUOTE_${quotes.length - 1}__`
})
```

`/"[^"]*"/` matches from one `"` to the next `"`, treating every `"` as a quote delimiter. bash does not. Two cases where the two disagree:

- **Escaped quote.** In bash, `\"` outside a quoted span is a literal `"` character and does not start a quote. The masker ignores the backslash: in `echo \";touch /tmp/ROO_PWNED;\"` it pairs the `"` of the first `\"` with the `"` of the trailing `\"` and masks the whole span between them — `";touch /tmp/ROO_PWNED;\"`, which also absorbs the backslash just before the trailing quote — into `__QUOTE_0__`, leaving `echo \__QUOTE_0__`. The separator `;` and the `touch` command are now inside the placeholder. The token loop (`parse-command.ts:151`) only splits sub-commands on operator tokens, and there is no separator token left to split on, so `parseCommand` returns the single sub-command `echo \";touch /tmp/ROO_PWNED;\"`. It begins with the allowlisted prefix `echo`, so it is auto-approved. bash instead reads `\"` as a literal character, so the `;` is a real separator: it runs `echo \"`, then `touch /tmp/ROO_PWNED`, then `\"`.

- **ANSI-C / single quotes.** `parseCommand` masks double quotes only; it never handles `'…'` or the ANSI-C form `$'…'`, in which an inner `"` is a literal character. In `echo $'"';touch /tmp/ROO_PWNED;$'"'` the two `"` characters live inside `$'…'` and are literal to bash, but the masker pairs them and again swallows `';touch /tmp/ROO_PWNED;$'` into a placeholder, leaving a single `echo …` sub-command that is auto-approved. bash evaluates each `$'"'` to a literal `"`, so the `;` separators are real and `touch` runs.

The masker is correct for a genuine double-quoted span, which is why the control below is safe: in `echo ";touch /tmp/ROO_PWNED;"` the `;touch …;` really is inside double quotes, bash treats it as a literal argument to `echo` and does not run `touch`, and the masker masks the same span — parser and shell agree. The defect appears only when a `"` that bash does not treat as an opening quote (an escaped `\"`, or a `"` inside `'…'` / `$'…'`, or simply an odd count of unescaped quotes) makes the regex's pairing diverge from bash's quote state, so a separator that is outside quotes to bash is absorbed as if it were inside quotes.

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
  "touch /tmp/ROO_PWNED",                    // control -> auto_deny    (denied command is caught when bare)
  'echo ";touch /tmp/ROO_PWNED;"',           // control -> auto_approve (real double-quotes; bash also skips it, safe)
  'echo \\";touch /tmp/ROO_PWNED;\\"',       // BYPASS  -> auto_approve  (escaped quotes; bash runs touch)
  "echo $'\"';touch /tmp/ROO_PWNED;$'\"'",   // BYPASS  -> auto_approve  (ANSI-C $'…'; bash runs touch)
]) console.log(getCommandDecision(cmd, ALLOW, DENY).padEnd(12), "<-", JSON.stringify(cmd))
```

Results:

```
auto_deny    <- "touch /tmp/ROO_PWNED"
auto_approve <- "echo \";touch /tmp/ROO_PWNED;\""
auto_approve <- "echo \\\";touch /tmp/ROO_PWNED;\\\""
auto_approve <- "echo $'\"';touch /tmp/ROO_PWNED;$'\"'"
```

The genuine-quote control is approved and is also safe under bash; only the escaped-quote and ANSI-C forms, where the parser's quote pairing diverges from bash's, are wrongly approved with `touch` reachable.

Bash confirms which command actually runs:

```bash
bash -c 'echo ";touch /tmp/ROO_PWNED;"'          # prints ";touch /tmp/ROO_PWNED;"; real quotes -> touch does NOT run
bash -c 'echo \";touch /tmp/ROO_PWNED;\"'        # \" is literal; ; is a real separator -> touch RUNS
bash -c "echo \$'\"';touch /tmp/ROO_PWNED;\$'\"'" # $'"' is a literal "; ; is a real separator -> touch RUNS
```

Only the two bypass forms create `/tmp/ROO_PWNED`, yet all three received the same `auto_approve` decision. Verified on GNU bash 5.3.15 and on the macOS system bash 3.2.57 — the defect does not depend on any recent bash feature.

### Impact

A denied or unlisted command placed after a `;` (or any separator) that the quote-masking regex mistakenly folds into a quoted span is dropped from the approval check but executed by bash, defeating the allow/deny control. The realistic trigger is indirect prompt injection: untrusted content the agent reads (a file, web page, repository, or MCP result) steers it into emitting `<allowed prefix> \"<sep><denied command><sep>\"` (or the `$'…'` form), which auto-runs with the agent's auto-execute privileges on the developer's machine. Because the defect is in bash's oldest quoting rules (escaped quotes, single/ANSI-C quotes), it is shell-version-independent — both current and legacy bash execute the smuggled command.

This root cause is distinct from the command-substitution masking line (parse-command.ts masking `$(…)`/`${…}` before the `containsDangerousSubstitution` guard, e.g. CVE-2026-63108): here no command substitution is involved and the dangerous-substitution guard is irrelevant (it does not inspect quoting or separators). The bypass is a desynchronization between the quote-masking regex and bash's quote state that promotes an out-of-quotes separator into a quoted span.

### Remediation

Do not mask quotes with a `"[^"]*"` regex that counts `"` characters without regard to bash's quoting rules. Track quote state the way bash does: a `\"` outside quotes is a literal character that does not open a span; `'…'` and `$'…'` are separate quoting contexts in which `"` is literal; a `"` only opens a double-quoted span when it is itself unquoted and unescaped. Use a real shell lexer for this rather than a per-construct regex. Fail closed when quote state cannot be resolved unambiguously — for example an odd number of unescaped `"`, or `shell-quote` raising a parse error — by requiring explicit user approval instead of folding the remainder of the line into a single sub-command. Recognize `'…'` and `$'…'` explicitly so their contents are neither split nor mistaken for double-quote delimiters.
