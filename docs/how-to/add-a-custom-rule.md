# Add a custom rule

Goal: add a new regex rule to your account's policy overlay without
touching the embedded baseline.

## Where personal rules go

Two places, merged together (`<configDir>` is `~/.claude` unless
`CLAUDE_CONFIG_DIR` is set — see `docs/reference/policy.md`):

- `<configDir>/bouncer/policy.toml` — a single file, fine for a handful
  of rules.
- `<configDir>/bouncer/policy.d/*.toml` — split by theme once
  `policy.toml` gets crowded (`10-npm.toml`, `20-client-x.toml`, ...),
  merged after `policy.toml` in lexicographic filename order. Same rule
  syntax, same validation, same fail-closed behavior — just a second
  place to put a `[[rules...]]`/`[[override]]`/`[[relax]]` block instead
  of appending to one growing file. The steps below use `policy.toml`;
  everything they show works identically in a `policy.d/` file.

## Declare an assistant

Use `[[harness]]` when the path is an assistant's configuration directory or
its session-start persistence. The loader derives protected-write rows from
the declaration, so a directory move and each persistent file receive the
same confirmation behavior.

To add a profile-specific directory for a baseline assistant, append the
known id. The persistent list is inherited and must not be copied:

```toml
[[harness]]
id = "claude-code"
dir = ["(^|/)\\.claude-[\\w.-]+"]
witness = "~/.claude-client"
```

After `bouncer rules lint`, `rm -rf ~/.claude-client` and writes to its
inherited `settings.json`, `hooks/`, `plugins/`, and `CLAUDE.md` confirm.
Without this overlay, the baseline protects only `~/.claude`.

For a new assistant id, provide `dir`, `env` (use `[]` when it has no
documented environment variable), and `reason`. Add `witness` when the
fragment's derived concrete path cannot be proved by lint; add one or more
`[[harness.persistent]]` tables when it loads paths at startup. See
[`policy.md`'s harness reference](../reference/policy.md#harness-assistant-configuration-declarations)
for the full field table, merge rules, exclusions, and known shell limits.

### Give it a protocol, so `bouncer run`/`check` can speak to it directly

A brand-new assistant id needs its own `[harness.protocol]` table before
`--harness <id>` works at all (ADR-0006) — without one, the id still
protects its configuration directory, but `bouncer run --harness <id>`
fails closed (exit 2, "declared harness has no usable protocol"). A new
id can only be introduced through the COMMON layer (`~/.agents/bouncer/`,
directly or via `harness.d/*.toml`), never the profile layer alone — a
brand-new harness has no profile root to resolve yet.

```toml
# ~/.agents/bouncer/harness.d/acme.toml
[[harness]]
id = "acme"
dir = ["(^|/)\\.acme"]
witness = "~/.acme"
env = ["ACME_CONFIG_DIR"]
reason = "Acme CLI configuration directory"

[harness.protocol]
transport = "stdin-json"
wiring = "hook-file"

[harness.protocol.input]
event = "hook_event_name"
tool = "tool_name"
input = "tool_input"
session = "session_id"
cwd = "cwd"

[harness.protocol.events]
pre_tool = "PreToolUse"

[harness.protocol.tools]
Bash = { role = "command", command = "command" }

[harness.protocol.output]
block = "deny"
confirm = "deny"
observe = "silent"
flag = "silent"
on_malformed = "allow"

[harness.protocol.output.deny]
stdout = '{"decision":"deny","reason":${reason}}'
```

This is the MINIMUM that lints (review round 2 R2-1) — `prompt` and
`session_start` are both optional: `input.prompt`/`events.prompt` are
needed together only once `acme`'s own hook sends a `UserPromptSubmit`-
shaped event to inspect (add both, plus `output.flag = "context"` and an
`[harness.protocol.output.context]` template, at that point — an
overlay declaring `events.prompt` without `input.prompt`, or leaving
`flag` at anything but `"silent"` without `events.prompt`, is rejected);
`events.session_start`/`output.session_start` are needed together only
once `doctor`'s wiring/policy/log checklist has a session-start hook to
announce through for this harness. Neither is required to make
`--harness acme` usable — a harness with just `pre_tool` + `deny` judges
every guarded tool call exactly like Claude Code does, just without a
prompt-injection surface or a doctor announcement.

Note the `stdout` line above: `${reason}` is written BARE, never
`"${reason}"` — `rules lint` JSON-encodes the substituted value itself
(quotes included), so a hand-written quote around the placeholder would
double up into invalid JSON the harness can't parse. `rules lint` rejects
a quoted placeholder outright, and separately checks every template
still parses as JSON after substitution.

`confirm = "deny"` needs no `ask_probe` — only `confirm = "ask"` does
(lint cannot verify a harness honours `ask`, so it forces the author to
record the evidence). After `bouncer rules lint`, `bouncer harness list`
shows `harness acme overlay [common:harness.d/acme.toml]
transport=stdin-json confirm=deny`, and `bouncer check --harness acme "rm
-rf /"` dry-runs the SAME dispatch a real `acme` hook invocation would
get. See [`policy.md`'s `[harness.protocol]`
reference](../reference/policy.md#harnessprotocol-the-pipeline-a-generic-adapter-reads-adr-0006)
for the full field table (roles, selectors, output-table lint rules) and
the codecs a `transport`/`wiring` string can name.

## Steps

1. Open (or create) the overlay file — `<configDir>/bouncer/policy.toml`,
   or a themed file under `<configDir>/bouncer/policy.d/` (see above).

2. Pick the table that matches what you're guarding — one of the six
   regex tables:

   | You want to block/flag... | Table |
   |---|---|
   | a shell command | `rules.command.bash` |
   | reading a file path | `rules.secret.path` |
   | a shell command that leaks a secret | `rules.secret.bash` |
   | writing text matching a secret shape | `rules.write_secret` |
   | a submitted prompt matching an injection shape | `rules.prompt` |
   | a handwritten harness, persistence, or shell-startup path being written | `rules.protected_write` |

3. Add a `[[<table>]]` entry with `id`, `regex`, and `reason`. Every
   effective regex-table id is global across the six tables; `rules lint`
   rejects a duplicate so an `[[override]]` can never target two entries.
   Example, blocking `npm publish` in `rules.command.bash`:

   ```toml
   [[rules.command.bash]]
   id = "block-npm-publish"
   regex = "\\bnpm\\s+publish\\b"
   reason = "npm publish should go through CI, not an agent session"
   ```

   An addition to any of the six regex tables only ever adds a new
   BLOCK/confirm signature — it can't relax an existing one. It's active
   as soon as it validates, no restart needed (the policy is loaded fresh
   on every hook invocation).

4. Validate the overlay:

   ```sh
   bouncer rules lint
   ```

   `lint: OK` means the regex compiled, stays inside the RE2-like dialect
   (no lookaround, no backreferences — see `docs/reference/policy.md`),
   and every required field is present. Any failure rejects the WHOLE
   overlay file SET (both `policy.toml` and every `policy.d/*.toml`
   file), not just the broken entry or file — the baseline stays active in
   the meantime (see `docs/reference/policy.md`'s fail-closed behavior).

5. Check the verdict the new rule actually produces, without a live session:

   ```sh
   bouncer check "npm publish"
   ```

   Expect: `block [block-npm-publish] npm publish should go through CI, not an agent session`

6. Confirm the rule is live and see its provenance:

   ```sh
   bouncer rules list | grep block-npm-publish
   ```

   Expect: `rule command.bash block-npm-publish overlay [profile:policy.toml]` —
   `overlay` marks it as coming from your account's files (not
   `baseline`), and `[profile:policy.toml]` names the layer and file —
   `[profile:policy.d/10-npm.toml]` instead, had the rule been added
   there, or `[common:...]` had it lived in the shared common layer
   (`~/.agents/bouncer/` — see `docs/reference/policy.md`'s § Baseline
   vs. overlay) instead of your own profile's.

## Verify

- `bouncer rules lint` exits 0.
- `bouncer check "<a command your rule should catch>"` reports the verdict
  and rule id you expect.
- `bouncer rules list` shows the new rule with provenance `overlay` and
  the file it came from.

---
Source: src/policy/schema.ts, src/policy/lint.ts, src/policy/load.ts, src/adapter/policy.ts, src/cli-commands.ts, policy/harness/claude-code.toml
