# Wire bouncer into Claude Code

Goal: point a Claude Code `settings.json` at the compiled `bouncer` binary so
every guarded tool call, every submitted prompt, and every session start
goes through it.

Wiring a guard is a security decision, not a config tweak: an incomplete
hooks block leaves part of a session unguarded, silently. Verify with
`bouncer doctor` after writing the block and after every future edit to it.

Every command below (here and in the rest of `docs/`) is written as bare
`bouncer`, assuming it resolves on `PATH` (a symlink, an alias, or a future
package install). Before that's set up, substitute `./dist/bouncer` or the
absolute path from step 1.

## Steps

1. Build the binary from the repository root:

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

3. Add a `hooks` block with all three entries — `PreToolUse`, `UserPromptSubmit`,
   `SessionStart` — merging it into the file's existing `hooks` key if one
   already exists. Replace `/absolute/path/to/dist/bouncer` with the path
   from step 1:

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
       ]
     }
   }
   ```

   All three point at the same `bouncer run` command — `run` reads the
   event name from the hook envelope on stdin and dispatches internally.
   The `PreToolUse` matcher must cover every tool `bouncer` guards
   (`Bash`, the native file tools, and any `mcp__*` tool) — a narrower
   matcher lets some tool calls through unguarded. `UserPromptSubmit` and
   `SessionStart` take no matcher; both apply unconditionally.

4. Verify the wiring:

   ```sh
   bouncer doctor
   ```

   A fully wired, healthy setup prints five `[pass]` lines (`settings`,
   `wiring:PreToolUse`, `wiring:UserPromptSubmit`, `wiring:SessionStart`,
   `policy`, `log`) and exits 0. Any `[fail]` line names exactly which
   part of the wiring is missing or misconfigured — fix it and re-run
   `doctor` until every check passes.

   Checking a `settings.json` at a non-default path (before merging it
   into a live config, or to check a project-level file):

   ```sh
   bouncer doctor --settings /path/to/settings.json
   ```

5. Start a new Claude Code session. If the wiring is healthy, `SessionStart`
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

## Shadow first (recommended before cutover)

Migrating from an existing guard chain (e.g. the TS-generation
`guard-*` hooks)? Wire bouncer in `--shadow` mode ALONGSIDE the existing
hooks first, rather than replacing them outright — it evaluates every
event for real and logs every verdict, but never touches stdout, so it
cannot deny, ask, or scream on top of a chain that's already enforcing.

1. Add the SAME three hook entries as step 3 above, but append `--shadow`
   to every `command` string:
   `"/absolute/path/to/dist/bouncer run --shadow"`. Leave the existing
   hooks in place — they stay the real enforcement chain for the whole
   shadow window. `bouncer doctor`'s wiring checks accept `--shadow` as
   healthy wiring and say so explicitly (`... is correctly wired (shadow
   mode)`, informational, never a `[fail]`).
2. Use the session normally for a while, letting both chains observe the
   same traffic. bouncer writes every verdict it WOULD have produced to
   its own log, `mode:"shadow"` tagged.
3. Read the divergence report: `bouncer audit --diff` (add `--ts-logs
   <dir>` if the TS logs live under a different account config dir than
   bouncer's own). Every divergence is either tagged `[expected]`
   (already pre-triaged, cited by ticket) or genuinely new and needs a
   look — see `docs/reference/cli.md`'s `audit --diff` section for the
   full output shape and what each divergence kind means.
4. At cutover: drop `--shadow` from the command strings (and remove the
   old guard hooks, if replacing them). Re-run `bouncer doctor` — the
   `(shadow mode)` suffix disappears from any wiring line it was on;
   nothing else changes.

**Blind spot to keep in mind (measured, ticket 05's live demo):** a tool
call denied by `settings.json`'s own `permissions` block short-circuits
BEFORE either guard chain's `PreToolUse` hooks ever run — neither bouncer
NOR the TS generation sees it, on either side. A `--diff` report reading
"0 divergence" only proves parity on traffic that actually REACHES the
hooks; it says nothing about calls `permissions` already stopped upstream.
If a permissions rule is doing real guarding work, that work stays
invisible to this whole comparison — worth a separate look before
concluding the migration is fully covered.

---
Source: scratch/demo-settings.json (hooks block shape), src/adapter/doctor.ts, src/cli-commands.ts, src/cli.ts, src/adapter/run.ts, src/adapter/audit-diff.ts
