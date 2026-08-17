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

---
Source: scratch/demo-settings.json (hooks block shape), src/adapter/doctor.ts, src/cli-commands.ts, src/cli.ts
