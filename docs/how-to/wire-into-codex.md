# Wire bouncer into Codex CLI

Goal: point Codex's hook configuration (`hooks.json`, or the `[hooks]` table
of `config.toml`) at the compiled `bouncer` binary so every guarded tool
call, every submitted prompt, and every session start goes through it.

Codex hooks read the same stdin-JSON envelope shape Claude Code's do
(`hook_event_name`, `tool_name`, `tool_input`, `session_id`, plus `cwd`) and
answer with the same `hookSpecificOutput` JSON — `policy/harness/codex.toml`
is mostly Claude Code's own declaration with three measured differences
(ADR-0006 § 3/10):

1. **`confirm` degrades to `deny`, not `ask`.** Codex parses
   `permissionDecision: "ask"` but marks the hook run as failed and
   **continues the tool call** (measured 2026-09-07, Codex CLI 0.153.2 —
   see `policy/harness/codex.toml`'s own comment above `confirm` for the
   dated probe result). Every `confirm`-class verdict — a protected `git`
   subcommand, an MCP write — reaches you as `deny`, with no prompt.
2. **Edits arrive as `apply_patch` patch text**, not `Read`/`Edit`/`Write`.
   Codex has no native file tools; a file change is `tool_name:
   "apply_patch"` with `tool_input.command` holding the patch grammar
   (`*** Begin Patch` … `*** End Patch`). The `apply-patch` codec
   (`src/adapter/codecs/input/apply-patch.ts`) parses it into the paths it
   writes (both ends of a move) and the text it adds, the same vocabulary
   Claude Code's `Write`/`Edit` selectors produce.
3. **`doctor` reads two additive sources plus a trust ledger**, not one
   `settings.json`. `hooks.json` and `config.toml`'s own `[hooks]` table
   are BOTH loaded by Codex; a hook definition also needs to be trusted by
   hash (`/hooks` in the TUI) before it runs — an untrusted or stale entry
   is silently **skipped**, so a wiring that looks complete can still leave
   a session unguarded. The `codex-hooks` codec
   (`src/adapter/codecs/wiring/codex-hooks.ts`) checks both.

Every command below is written as bare `bouncer`, assuming it resolves on
`PATH`. Before that's set up, substitute `./dist/bouncer` or the absolute
path from step 1.

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

2. Decide the target `$CODEX_HOME` — `~/.codex` for your primary account,
   or a second directory (`CODEX_HOME=/path/to/other`) for a client seat
   running the same binary. `bouncer doctor --harness codex` checks
   `$CODEX_HOME/hooks.json` (and `$CODEX_HOME/config.toml`'s `[hooks]`
   table) by default — ONLY the account-level directory. A project-level
   `.codex/hooks.json` (Codex also loads hooks from the CURRENT project,
   not only the account dir) is out of `doctor`'s reach entirely (ticket
   15b non-goal): it is neither checked nor reported on, wired or not.

3. Add or merge a `hooks.json` at `$CODEX_HOME/hooks.json` — every entry
   carries `--harness codex` (ADR-0006 § 9: a bare `bouncer run` would
   judge against claude-code's table instead, silently keeping `confirm =
   "ask"`, which Codex fails open on):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|apply_patch|mcp__.*",
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run --harness codex"
             }
           ]
         }
       ],
       "UserPromptSubmit": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run --harness codex"
             }
           ]
         }
       ],
       "SessionStart": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "/absolute/path/to/dist/bouncer run --harness codex"
             }
           ]
         }
       ]
     }
   }
   ```

   The `PreToolUse` matcher must cover every tool `bouncer` guards under
   Codex: `Bash`, `apply_patch`, and any `mcp__*` tool. `UserPromptSubmit`
   and `SessionStart` take no matcher; both apply unconditionally.
   Equivalent content in `config.toml`'s own `[[hooks.PreToolUse]]`
   array-of-tables form works too — the two sources are additive, never a
   choice between them (a project wiring both is legal, if unusual).

   Once wired, `hooks.json` itself becomes a protected write (review
   round 1 L-1, `policy/harness/codex.toml`'s `codex-hooks` persistent
   row): editing or deleting it — directly, via a Bash redirect, or via
   `apply_patch` — asks for confirmation, the same protection Claude
   Code's own `hooks/` directory and Cursor's `hooks.json` already have.

4. Add the fail-closed `PreToolUse` canary. With the primary entry already
   in `hooks.json`, print the canonical second entry:

   ```sh
   bouncer doctor --harness codex --print-canary
   ```

   Paste the JSON object as a second item in `hooks.PreToolUse`, beside the
   primary entry. It copies that entry's matcher and binary path. The
   canary runs `bouncer ping`; if the binary is absent, not executable, or
   cannot load its policy, it emits a parseable deny and exits 0.

5. **Trust the hooks.** Codex requires every hook definition to be trusted
   by hash before it runs — open the Codex TUI in this `$CODEX_HOME` and
   run `/hooks`, then trust each of the three bouncer entries (and the
   canary). Until trusted, `doctor --harness codex` reports
   `wiring:trust` as failing and the session runs genuinely unguarded —
   this is not a bouncer bug to work around; it is Codex's own
   trust-on-first-use model, and skipping it defeats the guard silently.

6. Verify the wiring:

   ```sh
   bouncer doctor --harness codex
   ```

   A fully wired, healthy, and trusted setup prints `[pass]` for
   `settings`, `wiring:PreToolUse`, `wiring:canary`,
   `wiring:UserPromptSubmit`, `wiring:SessionStart`, `wiring:trust`,
   `policy`, and `log`, and exits 0. Any `[fail]` line names exactly which
   part of the wiring is missing, unrecognized, or untrusted — fix it and
   re-run `doctor` until every check passes.

7. Start a new Codex session in `$CODEX_HOME`. If the wiring is healthy,
   `SessionStart` stays completely silent. If a hook entry is missing, a
   handler is untrusted, or a broken policy overlay forced the baseline
   active, the session's first turn receives an `additionalContext`
   message naming the problem, from the same checks `doctor` runs
   manually.

## The `confirm → deny` consequence

Because Codex does not (yet) honour `permissionDecision: "ask"`, every
verdict that would prompt a human under Claude Code — a protected `git`
subcommand, an unrecognized MCP write — is a hard `deny` under Codex, with
no path to "confirm and proceed" short of editing the policy. An overlay
CANNOT relax this back to `ask` for the baseline `codex` harness (ADR-0006
§ 4 rule 6: a baseline `deny` is a measured fact, not a default to loosen);
if a future Codex release honours `ask`, the baseline itself will change,
with a fresh dated probe.

## `CODEX_HOME` for a second account

The same binary guards a second Codex account by pointing `CODEX_HOME` at
that account's own directory before invoking `bouncer` — its profile
overlay (`$CODEX_HOME/bouncer/`), audit log
(`$CODEX_HOME/logs/hooks/bouncer.log`), and `hooks.json`/`config.toml` stay
entirely separate from the primary account's.

## Verify

- `bouncer doctor --harness codex` exits 0 with every check `[pass]`.
- A guarded command inside the session (e.g. `rm -rf /tmp/some-test-dir`)
  is denied.
- A protected `git` command (e.g. `git branch -D some-branch`) is denied
  outright — never a prompt, unlike Claude Code.

## Shadow first (recommended before cutover)

It matters more here than for Claude Code: `confirm` degrades straight to
`deny` under Codex (§ above) — no `ask` prompt, no human recovery in the
moment. Wire `--shadow` first, validate your overlay against real
traffic, and only then cut over to real enforcement.

1. Append `--shadow` to the three primary `bouncer run --harness codex`
   command strings in `hooks.json` (step 3 above). Keep the canary entry
   unchanged — it never judges a tool call, so it stays enforcing while
   the primary guard observes only.
2. Use the session normally for a while. bouncer writes every verdict it
   WOULD have produced to its own log, `mode:"shadow"` tagged.
3. Read what it would have done: `bouncer audit --harness codex` (or
   `--diff` against a prior guard's own logs, if migrating from one — see
   `docs/reference/cli.md`'s `audit` section).
4. At cutover, drop `--shadow` from the three primary command strings.
   Re-run `bouncer doctor --harness codex` — the `(shadow mode)` suffix
   disappears from the primary wiring line; the canary stays unchanged.

---
Source: policy/harness/codex.toml, src/adapter/codecs/input/apply-patch.ts,
src/adapter/codecs/wiring/codex-hooks.ts, src/adapter/canary.ts,
src/adapter/doctor.ts, src/cli-commands.ts, src/cli.ts
