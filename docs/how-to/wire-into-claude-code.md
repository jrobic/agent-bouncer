# Wire bouncer into Claude Code

Goal: point a Claude Code `settings.json` at the compiled `bouncer` binary so
every guarded tool call, every submitted prompt, every session start, every
successful tool output and every failed-tool alert goes through it.

Wiring a guard is a security decision, not a config tweak: an incomplete
hooks block leaves part of a session unguarded, silently. Verify with
`bouncer doctor` after writing the block and after every future edit to it.

Every command below (here and in the rest of `docs/`) is written as bare
`bouncer`, assuming it resolves on `PATH` (a symlink, an alias, or a future
package install). Before that's set up, substitute `./dist/bouncer` or the
absolute path from step 1.

## Homebrew

Installed with Homebrew? Use the stable `$(brew --prefix)/bin/bouncer` path
below; see [Install](install.md).

## Steps

1. Choose the compiled binary to wire:

   - Installed with Homebrew: use `$(brew --prefix)/bin/bouncer`.
   - From a checkout: build the binary from the repository root:

     ```sh
     bun run build
     ```

     This produces `dist/bouncer`. Resolve its absolute path:

     ```sh
     realpath dist/bouncer
     ```

2. Decide which `settings.json` to edit — project-level
   (`.claude/settings.json`) or user-level (`~/.claude/settings.json`).
   `bouncer doctor` (step 4) checks the user-level file by default; pass
   `--settings <path>` to check a project-level one instead.

3. Add a `hooks` block with all five entries — `PreToolUse`, `UserPromptSubmit`,
   `SessionStart`, `PostToolUse`, `PostToolUseFailure` — merging it into the
   file's existing `hooks` key if one already exists. Replace
   `/absolute/path/to/dist/bouncer` with the path from step 1:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep|Glob|mcp__.*",
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run"
             }
           ]
         }
       ],
       "UserPromptSubmit": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run"
             }
           ]
         }
       ],
       "SessionStart": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run"
             }
           ]
         }
       ],
       "PostToolUse": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run"
             }
           ]
         }
       ],
       "PostToolUseFailure": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run"
             }
           ]
         }
       ]
     }
   }
   ```

   The five `bouncer run` commands point at the same binary. The first
   `PreToolUse` entry is the primary guard; its matcher must cover every tool
   `bouncer` guards (`Bash`, the native file tools, and any `mcp__*` tool).
   `UserPromptSubmit` and `SessionStart` take no matcher; both apply
   unconditionally. `PostToolUse` and `PostToolUseFailure` take **no matcher**:
   the first redacts every successful tool output; the second adds a name-only
   alert for every failed tool whose error contains a protected value. A
   matcher on either entry leaves other tools uncovered.

4. Add the fail-closed `PreToolUse` canary. With the primary entry already in
   `settings.json`, print the canonical second entry:

   ```sh
   bouncer doctor --settings /path/to/settings.json --print-canary
   ```

   Paste the JSON object as a second item in `hooks.PreToolUse`, beside the
   primary entry. It copies that entry's matcher and binary path. The canary
   runs `bouncer ping`; if the binary is absent, not executable, or cannot
   load its policy, it emits a parseable deny and exits 0. Do not add
   `--shadow` to this command: it checks runnability, not a tool verdict.

5. Verify the wiring:

   ```sh
   bouncer doctor
   ```

   A fully wired, healthy setup prints nine `[pass]` lines (`settings`,
   `wiring:PreToolUse`, `wiring:canary`, `wiring:UserPromptSubmit`,
   `wiring:SessionStart`, `wiring:PostToolUse`,
   `wiring:PostToolUseFailure`, `policy`, `log`) and exits 0. Any `[fail]`
   line names exactly which part of the wiring is missing or misconfigured —
   fix it and re-run `doctor` until every check passes. A missing
   `PostToolUseFailure` entry is `[fail] wiring:PostToolUseFailure`, and the
   line ends with the entry to paste.

   Checking a `settings.json` at a non-default path (before merging it
   into a live config, or to check a project-level file):

   ```sh
   bouncer doctor --settings /path/to/settings.json
   ```

6. Start a new Claude Code session. If the wiring is healthy, `SessionStart`
   stays completely silent — no message, nothing added to context. If a
   hook entry is missing or a broken policy overlay forced the baseline
   active, the session's first turn receives an `additionalContext` message
   naming the problem, from the same checks `doctor` runs manually.

## Verify

- `bouncer doctor` exits 0 with every check `[pass]`.
- A guarded command inside the session (e.g. `rm -rf /tmp/some-test-dir`)
  is denied.
- A protected git command (e.g. `git push`) asks for confirmation instead
  of running immediately.
- A tool that prints the value of a protected variable reaches the model as
  `[redacted: NAME]` (try it with a made-up variable exported only for that
  session, never a real one).

- A failing tool whose error carries a protected value gets a
  `PostToolUseFailure` `additionalContext` notice naming the variable. Claude
  Code has already shown the original output; the alert does not redact it.

## Tool output redaction

The `PostToolUse` entry (ADR-0008) walks each successful tool's output —
`Bash`, `Read`, `Grep`, MCP tools, every tool — and replaces the value of a
protected environment variable (the same names and the same three spellings,
plain, base64 and hex, as the write guard) by `[redacted: NAME]`, keeping the
output's own shape. Nothing found: `bouncer` prints nothing and the output
goes through untouched. Each redaction is logged with the tool name and the
variable **name** (verdict `redact`, see
[the audit log reference](../reference/audit-log.md)); `--shadow` logs it
and redacts nothing.

The `PostToolUseFailure` entry (ADR-0008 § 9) scans the complete failed-tool
`error` for the same protected values. A hit adds a name-only
`additionalContext` notice and logs a `flag` with the tool and names. Claude
Code has already seen the original failed output: this is an alert, not a
redaction or replacement. `--shadow` logs the hit without adding context.

Measured live on 2026-10-13 with Claude Code 2.1.296, a throwaway
`CLAUDE_CONFIG_DIR` and a made-up variable:

- `Bash`, `Read`, `Grep` and an MCP tool reach the model redacted, and the
  session transcript (`projects/<slug>/<session>.jsonl`) holds the redacted
  output.
- **A tool that fails is not redacted.** A non-zero Bash exit fires
  `PostToolUseFailure`, not `PostToolUse`. If its `error` carries a protected
  value, the hook adds a name-only notice; the original error remains in the
  model context and transcript.
- **A failure of the hook process itself shows the original output and omits
  the notice**: a crash, a non-zero exit, a timeout, unreadable stdout or a
  missing binary. The success-path `PostToolUse` check withholds an output
  only for a failure Bouncer catches itself; a failed-output alert cannot
  withhold anything.
- **A withheld answer can still be ignored.** It keeps the output's shape and
  short strings, so `Bash`, `Read` and `Grep` in `content` mode accept it. A
  `Grep` in its default mode (`files_with_matches`) does not: Claude Code
  shows the original, a list of file names.
- **A large `Bash` output (above ~30 KB)** is written in full, unredacted, to
  `projects/<slug>/<session>/tool-results/<id>.txt` before the hook runs; the
  model gets a redacted preview and that path. Reading the file back is a tool
  call, redacted again; the file on disk keeps the value.
- **`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`** strips the variables from the hook
  too: `bouncer` then knows no value, and a file holding one reaches the model
  unredacted.
- **The tool already ran**: redaction protects the model's context, not what
  the tool did (a network call, a file written). Claude Code's own telemetry
  records the original output before the hook runs.

Measured live on 2026-10-14 with Claude Code 2.1.299 and the
rebuilt compiled `dist/bouncer` 1.10.0. The isolated rig used a temporary
`HOME`/`CLAUDE_CONFIG_DIR`, a local fake model server, and a fake protected
value passed to Claude Code through its child environment. One successful Bash
call exercised `PostToolUse` as a same-session witness, followed by three
warm-up failures and 80 measured `PostToolUseFailure` calls. `cc-timed-hook`
measured Bouncer spawn through stdout read and child exit; wrapper startup was
excluded.

| Case | n | p50 ms | p95 nearest-rank ms | p95 R type 7 ms | max ms |
|---|---:|---:|---:|---:|---:|
| Warm-up `PostToolUseFailure` | 3 | 22.53 | 22.95 | 22.908 | 22.95 |
| Measured `PostToolUseFailure` | 80 | 22.74 | 24.71 | 24.712 | 25.74 |

Nearest-rank is `sorted[ceil(p*n)-1]`; R type 7 is linear interpolation.
The maximum measured hook took 25.74 ms (failure index 75, measured sample 72).
The model endpoint received the original failed output in all 83 failure
requests. The exact notice count rose by one on each successive request,
from 1 through 83; the successful `PostToolUse` witness request contained 0.
All 83 audit rows were `flag` entries with `env-value`, fixed target
`(failed tool output)` and variable names only. The fake value appeared in
neither Bouncer hook output nor the audit log. The probe retained only
timings, per-request notice counts, and boolean checks, never request bodies.

The `env-value` row is the switch for writes, successful-output redaction and
failed-output alerts: `disable` or `relax` turns all three off. `replace`
governs writes only; both output scans ignore its `regex` and `except`
(`docs/reference/policy.md`).

## After upgrading to Bouncer 1.10.0

Add the `PostToolUse` entry of step 3 to every `settings.json` you wire
(`bouncer doctor` prints it on its `[fail] wiring:PostToolUse` line), then
re-run `bouncer doctor` until it reports eight `[pass]` lines.

## After upgrading to the release that adds `PostToolUseFailure`

Add the `PostToolUseFailure` entry of step 3 to every `settings.json` you
wire, with no matcher. `bouncer doctor` prints it on its
`[fail] wiring:PostToolUseFailure` line. Re-run the doctor until it reports
nine `[pass]` lines.

## Shadow first (recommended before cutover)

Migrating from an existing guard chain (e.g. the TS-generation
`guard-*` hooks)? Wire bouncer in `--shadow` mode ALONGSIDE the existing
hooks first, rather than replacing them outright — it evaluates every
event for real and logs every verdict, but never touches stdout, so it
cannot deny, ask, or scream on top of a chain that's already enforcing.

1. Add the five primary `bouncer run` hook entries from step 3 with
   `--shadow` appended to each command string. Keep the canary entry printed
   in step 4 unchanged: it never judges a tool call, so it remains enforcing
   while the primary guard observes only. Leave the existing hooks in place —
   they stay the real enforcement chain for the whole shadow window.
2. Use the session normally for a while, letting both chains observe the
   same traffic. bouncer writes every verdict it WOULD have produced to
   its own log, `mode:"shadow"` tagged.
3. Read the divergence report: `bouncer audit --diff` (add `--ts-logs
   <dir>` if the TS logs live under a different account config dir than
   bouncer's own). Every divergence is either tagged `[expected]`
   (already pre-triaged, cited by commit) or genuinely new and needs a
   look — see `docs/reference/cli.md`'s `audit --diff` section for the
   full output shape and what each divergence kind means.
4. At cutover: drop `--shadow` from the five primary command strings (and
   remove the old guard hooks, if replacing them). Re-run `bouncer doctor` —
   the `(shadow mode)` suffix disappears from the primary wiring line; the
   canary stays unchanged.

**Blind spot to keep in mind (measured live, 2026-08-16):** a tool
call denied by `settings.json`'s own `permissions` block short-circuits
BEFORE either guard chain's `PreToolUse` hooks ever run — neither bouncer
NOR the TS generation sees it, on either side. A `--diff` report reading
"0 divergence" only proves parity on traffic that actually REACHES the
hooks; it says nothing about calls `permissions` already stopped upstream.
If a permissions rule is doing real guarding work, that work stays
invisible to this whole comparison — worth a separate look before
concluding the migration is fully covered.

---
Source: src/adapter/canary.ts, src/adapter/doctor.ts, src/adapter/post-tool.ts, src/cli-commands.ts, src/cli.ts, src/adapter/run.ts
