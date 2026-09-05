# Override a baseline rule

Goal: disable, narrow, or soften a rule that ships in the embedded
baseline, or widen one of the three safe allowlists — with the change
visible in `rules list`, never silent.

## Disable, replace, or relax a regex rule with `[[override]]`

`[[override]]` targets a rule id from one of the six regex tables
(`rules.command.bash`, `rules.secret.path`, `rules.secret.bash`,
`rules.write_secret`, `rules.protected_write`, `rules.prompt`). Every entry
needs a non-empty `reason` — `rules lint` rejects one without it.

1. Find the rule id to target:

   ```sh
   bouncer rules list | grep <keyword>
   ```

2. Add an `[[override]]` block to `<configDir>/bouncer/policy.toml`, in
   one of three forms:

   **`disable`** — remove the rule entirely:

   ```toml
   [[override]]
   rule = "curl-file-upload"
   action = "disable"
   reason = "our CI legitimately uploads build artifacts via curl in every deploy"
   ```

   **`replace`** — swap the rule's regex, keeping its id and reason
   fields (the override's own `reason` explains why the regex was
   narrowed, not the original rule's `reason`, which stops applying):

   ```toml
   [[override]]
   rule = "chmod-root"
   action = "replace"
   regex = "\\bchmod\\s+-R\\s+777\\s+\\/(?:\\s|$)"
   reason = "narrow to mode 777 only — other recursive modes on / are fine in our sandbox"
   ```

   **`relax`** — keep the rule firing, but soften its verdict
   (`block` -> `confirm` -> `observe`):

   ```toml
   [[override]]
   rule = "curl-file-upload"
   action = "relax"
   verdict = "confirm"
   reason = "we want a confirmation prompt, not a hard block, for curl uploads"
   ```

3. Lint, then check the effect:

   ```sh
   bouncer rules lint
   bouncer check "<a command the rule matches>"
   ```

4. Confirm it's listed:

   ```sh
   bouncer rules list | grep <rule id>
   ```

   An active override shows twice: once as its own `override <action> <rule> — <reason>` summary line, once on the rule's own `rule ... override(<action>) — <reason>` line.

## Widen a safe allowlist with `[[relax]]`

`safe_subcommands`, `config_read_modes` (both `command.git`), and
`mcp_write.read_prefixes` can't be extended by adding to the table
directly — `rules lint` rejects that outright. Widen them through
`[[relax]]` instead, reason mandatory:

```toml
[[relax]]
list = "command.git.safe_subcommands"
value = "push"
reason = "our CI force-pushes to a scratch branch and the confirm prompt blocks the pipeline"
```

This makes `git push` in every form silent-allow, `--force` included —
`safe_subcommands` membership skips the git-conditional dispatch
entirely, not just the shape you had in mind. Narrower relaxation isn't
available for this list; if that's too wide, override `git-protected`
with `action = "relax"` instead (previous section) to soften its verdict
without removing confirmation altogether.

Lint and list the same way:

```sh
bouncer rules lint
bouncer rules list | grep overlay-relax
```

Expect a line like:
`overlay-relax command.git.safe_subcommands push — our CI force-pushes to a scratch branch and the confirm prompt blocks the pipeline`

## The limit: three rules aren't override-able

`rm-rf-dangerous`, `sudo` (privilege escalation), and `git-protected`
(the git conditional dispatch itself) are produced by engine algorithms,
not by a `{id, regex, reason}` table row — `[[override]]` only resolves
against the six regex tables, so targeting any of these three fails
lint:

```sh
$ bouncer rules lint
lint: FAILED (common: /path/to/.agents/bouncer, profile: /path/to/.claude/bouncer)
  - profile layer rejected — policy.toml: override rule "rm-rf-dangerous" does not resolve to any known rule id
  layers: common: active (0 files), profile: rejected (policy.toml)
```

Each is governed by its own named TOML table instead:
`command.rm_rf.dangerous_targets` (additive only — new entries widen what
counts as dangerous, never narrow it), `command.privilege_escalation.commands`
(same), and the three declarative git-conditional forms
(`command.git.ask_flags` / `safe_first_arg` / `safe_grammar`, plus
`safe_subcommands` via `[[relax]]` above) for `git-protected`. See
`docs/reference/policy.md` for each table's shape.

## The self-protection loop: overriding `bouncer-policy`

`bouncer-policy` (`rules.protected_write`) confirms writes to
`<configDir>/bouncer/policy.toml` and `<configDir>/bouncer/policy.d/` — the
policy the binary itself runs on. Reads remain free. It is override-able like
any other regex-table rule, which means an `[[override]]` block that disables
it is itself a write to a `policy.d/*.toml` file, so the live rule confirms
that write before it lands. Once it is on disk (after human approval), the
rule is gone from the effective set and further policy edits are
unconfirmed — intentional ordinary, override-able protection rather than a
hard seal. A stronger sealed rule is a backlog idea, not built here.

## Verify

- `bouncer rules lint` exits 0 after every edit.
- `bouncer check "<command>"` reports the verdict you expect (or `allow`,
  for a disabled/relaxed-to-nothing rule).
- `bouncer rules list` shows the override or relaxation, with its reason.

---
Source: src/policy/lint.ts, src/policy/load.ts, src/policy/schema.ts, src/cli-commands.ts, .scratch/bouncer/spec.md (Implementation Decisions § Overlay powers)
