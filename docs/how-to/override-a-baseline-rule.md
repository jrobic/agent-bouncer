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

`safe_subcommands`, `config_read_modes`, `allowed_global_options`,
`allowed_config` and `allowed_env` (all `command.git`),
`mcp_write.read_prefixes`, and `mcp_write.allowed_tools` can't be extended
by adding to the table directly. `rules lint` rejects that outright.
Widen them through `[[relax]]` instead, reason mandatory:

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

## Let one `-c` key or environment variable through before `git`

A `-c` setting, `--config-env`, a global option or an environment prefix that
is not on an allow-list asks with `git-config-exec`, even in front of an
allowed subcommand (`GIT_SSH_COMMAND='ssh -o BatchMode=yes' git ls-remote
ssh://h/r`). The refusal names the first offender. Widen the list that
holds it, in the profile layer:

```toml
[[relax]]
list = "command.git.allowed_env"   # or allowed_config, allowed_global_options
value = "GIT_SSH_COMMAND=ssh -o BatchMode=yes"
reason = "CI probes reach hosts over ssh and must not prompt"
```

`value` is a name, which allows it at any value (`GIT_SSH_COMMAND`), or
`name=value`, which allows that one value. Prefer the pair for anything that
runs a program: the bare name also lets `GIT_SSH_COMMAND=/tmp/evil` through.
`rules lint` rejects an entry without a `reason`, and
`bouncer rules list | grep overlay-relax` shows the relaxation like any other.
See [`git-config-exec`](../reference/policy.md#git-config-exec-what-may-stand-before-git)
for the entry grammar and the baseline lists.

## Authorize one MCP tool without widening other servers

Add a full-name permission to the target profile's
`<configDir>/bouncer/policy.d/`:

```toml
[[relax]]
list = "mcp_write.allowed_tools"
value = "mcp__chrome-devtools__click"
reason = "Human-approved Chrome interaction, including application writes"
```

Run `bouncer rules lint` and `bouncer rules list` with that profile's
configuration directory. The permission applies to this exact tool name
with any arguments, not to `click` on another server or to `click_extra`.
Do not use `mcp_write.read_prefixes` for a server-specific permission.

The opt-in [Chrome overlay](../../examples/chrome-devtools-overlay.toml)
contains explicit capture, browser-control, and emulation permissions,
including `click`, `fill_form`, `evaluate_script`, and `emulate`.
Script execution can change
application data and issue network requests. Unlisted Chrome tools retain
their existing rules. Copy the overlay only into the intended profile;
it is not part of the baseline.

## Opt out of the env-value write guard

`env-value` (`rules.write_secret`) blocks a `Write` / `Edit` whose text carries
the value of a protected environment variable
([the env-value row](../reference/policy.md#the-env-value-row)). Its
recognition is the engine's, but the row is an ordinary override target:

```toml
# switch it off — a shared dev password also sits in fixtures the agent edits
[[override]]
rule = "env-value"
action = "disable"
reason = "the dev database password is also written into compose and test fixtures"

# or keep it, and ask instead of blocking (the reason still names the variable)
[[override]]
rule = "env-value"
action = "relax"
verdict = "confirm"
reason = "review every write that carries a protected value"
```

`action = "replace"` is not the tool for a shared dev password: it changes only
the row's `regex`, which is matched against the **text** being written (the
baseline's `[\s\S]` accepts every non-empty text) and can only narrow which
texts the guard looks at. It cannot exempt a path or a file, and it cannot
change what counts as a protected value. For a dev password that a compose file
or a test fixture legitimately repeats, use `relax` to `confirm` or `disable`.

The same row also redacts every tool's **output** before the model sees it
(ADR-0008). `disable` and `relax` turn that redaction off too. `replace`
applies to writes only: the redaction ignores the row's `regex` and `except`
and always scans the whole output, so an override written for the write guard
never narrows what is hidden from the model.

## The limit: four rules aren't override-able

`rm-rf-dangerous`, `sudo` (privilege escalation), `git-protected`
(the git conditional dispatch itself) and `git-config-exec` (what stands
before `git`) are produced by engine algorithms,
not by a `{id, regex, reason}` table row — `[[override]]` only resolves
against the six regex tables, so targeting any of these four fails
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
(same), the four declarative git-conditional forms
(`command.git.ask_flags` / `safe_first_arg` / `safe_grammar` /
`safe_flags`, plus `safe_subcommands` via `[[relax]]` above) for
`git-protected`, and the three allow-lists `command.git.allowed_global_options` /
`allowed_config` / `allowed_env` (widened via `[[relax]]` above) for
`git-config-exec`. See
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
Source: src/policy/lint.ts, src/policy/load.ts, src/policy/schema.ts, src/cli-commands.ts
