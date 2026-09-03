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

## Steps

1. Open (or create) the overlay file — `<configDir>/bouncer/policy.toml`,
   or a themed file under `<configDir>/bouncer/policy.d/` (see above).

2. Pick the table that matches what you're guarding — one of the five
   regex tables:

   | You want to block/flag... | Table |
   |---|---|
   | a shell command | `rules.command.bash` |
   | reading a file path | `rules.secret.path` |
   | a shell command that leaks a secret | `rules.secret.bash` |
   | writing text matching a secret shape | `rules.write_secret` |
   | a submitted prompt matching an injection shape | `rules.prompt` |

3. Add a `[[<table>]]` entry with `id`, `regex`, and `reason`. `id` must be
   unique inside its table — `rules lint` (next step) doesn't enforce
   this, but a duplicate id makes an `[[override]]` targeting either
   entry apply to both. Example, blocking `npm publish` in
   `rules.command.bash`:

   ```toml
   [[rules.command.bash]]
   id = "block-npm-publish"
   regex = "\\bnpm\\s+publish\\b"
   reason = "npm publish should go through CI, not an agent session"
   ```

   An addition to any of the five regex tables only ever adds a new
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
Source: src/policy/schema.ts, src/policy/lint.ts, src/policy/load.ts, src/adapter/policy.ts, src/cli-commands.ts
