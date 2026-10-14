# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Upgrade:** a personal `ask_flags` overlay that replaces the baseline
  `branch` entry must add `-C` to keep force-copy protected. An overlay that
  omits it would allow `git branch -C` to overwrite an existing branch.

### Security

- **Git destructive-option checks now confirm branch force-copies, forced tag
  moves, and destructive checkout option spellings.** Baseline `branch -C`
  and tag `-f` / `--force` ask, as do grouped, abbreviated, and `=value`
  spellings of checkout's destructive options. `checkout` pathspec and `--`
  handling, safe branch-switch/create forms, and `switch --orphan` are
  unchanged. Glued values can over-confirm: `git checkout -bfix` and
  `git tag -mfix v1`; write `git checkout -b fix` or `git tag -m fix v1`.
  Corpus replay: six command strings changed from allow to confirm under the
  baseline and four under the effective personal policy; all were probes.
  Details: [`rules.command.git`](docs/reference/policy.md#rulescommandgit-the-four-declarative-conditional-forms)

## [1.10.0] - 2026-10-14

### Added

- **Tool output is redacted before the model sees it** (ADR-0008). After
  every tool — Bash, Read, Grep, MCP tools, every tool — Bouncer replaces each
  occurrence of the value of a protected environment variable (the 1.9.0
  `env-value` definition: protected names, at least 8 characters, in clear,
  base64 or hex) by `[redacted: NAME]`, keeping the output's own shape. Under
  Claude Code it is a new `PostToolUse` hook (`updatedToolOutput`); under
  pi/omp the shim relays every `tool_result` and returns Bouncer's `{ content
  }`. Nothing found, nothing changes. Each redaction is logged with the tool
  name and the variable names (a new verdict, `redact`; the value reaches no
  log field, message or stderr line); `--shadow` logs it and prints nothing.
  One switch: an `[[override]]` that disables or relaxes `env-value` turns
  redaction off too; a `replace` of `env-value` governs writes only — the
  redaction always scans the whole output. When the check itself fails, the
  output is withheld — `bouncer: post-tool check failed — output withheld` —
  under pi/omp on every failure, under Claude Code only on a failure Bouncer
  catches itself.
  **Limits:** the tool already ran (only the model's context is protected);
  under Claude Code a tool that fails (a non-zero Bash exit included) and any
  failure of the hook process itself (crash, timeout, missing binary) leave
  the original output in front of the model; Claude Code's large-output files
  (`tool-results/*.txt`), omp's session artifacts and the pi/omp `details`
  kept in session files hold the original on disk; images are not matched.
  Details: [Claude Code](docs/how-to/wire-into-claude-code.md#tool-output-redaction),
  [pi-agent](docs/how-to/wire-into-pi-agent.md#tool-output-redaction).
- `bouncer doctor` checks the new `PostToolUse` entry (`wiring:PostToolUse`):
  missing, or with a matcher that leaves a tool out, it is `[fail]` and names
  the entry to paste; the session-start notice lists it like any other wiring
  failure. A harness declaration may now declare a post-tool event
  (`events.post_tool`, `input.response`, an `output.redact` template with the
  structured `${response}` placeholder), kept consistent by `bouncer rules
  lint` (`docs/reference/policy.md`).

### Changed

- **Upgrade (Claude Code):** add the `PostToolUse` entry to every
  `settings.json` Bouncer is wired into — `{"hooks":[{"type":"command",
  "command":"<bouncer> run"}]}` under `hooks.PostToolUse`, no matcher — until
  `bouncer doctor` is `[pass]` again (it prints the entry on its
  `[fail] wiring:PostToolUse` line). Until then no tool output is redacted and
  every session starts with a wiring notice.
- The pi/omp session-start doctor notice is folded. The `Warning:` toast and
  the `bouncer-doctor` message show its headline lines and a count of the
  detail lines under them (one per active override or relaxation, failing
  check or warning) instead of every line twice. Press ctrl+o to expand the
  message to the full text, and again to fold it back; the toast does not
  expand. The model still receives the full notice. Measured live on omp
  18.10.3 and pi 0.84.1.
- **Upgrade (pi/omp):** the shim's bytes changed (the folded notice above and
  the `tool_result` relay that redacts tool output), so reprint it for each
  install and each omp profile —
  `bouncer harness shim pi-agent > <dir>/extensions/bouncer.ts` (the same
  `--bin` as at install time; `~/.pi/agent`, `~/.omp/agent`,
  `~/.omp/profiles/<name>/agent`) — and restart the session. `bouncer doctor
  --harness pi-agent` reports `[fail] wiring:shim` until the installed copy
  matches again.
- **Upgrade:** a personal `ask_flags` overlay becomes stricter without being
  rewritten. A command that spells a listed flag grouped, as `--name=value` or
  abbreviated now asks, where it used to pass.
- **Upgrade:** a git command can now ask where it used to pass. A `-c`
  setting, a `--config-env` setting, a global option or an environment prefix
  (`GIT_SSH_COMMAND=… git ls-remote`, `HOME=… git status`, `PATH=… git …`,
  `git -c core.fsmonitor=… status`) that is not on the new allow-lists asks
  with `git-config-exec`. To let one through, add a `[[relax]]` on
  `command.git.allowed_env`, `command.git.allowed_config` or
  `command.git.allowed_global_options` with a `reason`; run `bouncer rules
  lint` and `bouncer doctor` after upgrading; `rules list` shows an added
  entry as an `overlay-relax command.git.allowed_env …` line.

### Fixed

- `bouncer run` exited as soon as it had written its answer, and a pipe write
  is asynchronous on macOS: an answer larger than the pipe buffer (64 KiB under
  a node reader) reached the harness truncated. No verdict was ever that large;
  a redacted tool output can be, so `run` now exits once stdout is flushed.

### Security

- **`ask_flags` no longer lets a flag through because of how it is spelled.**
  A listed flag was recognised only when written exactly as listed, but git
  accepts three other spellings of the same option, and each of them skipped the
  confirmation: grouped short options (`git branch -qD foo`, `git branch -fd
  foo`, `git tag -fd v1`, `git switch -C=x main`), `--long=value` (`git switch
  --force-create=x main`) and an abbreviated long option (`git branch --forc
  x`, `git switch --force-c x main`, `git switch --discard`, `git tag --del
  v1`). All of them now ask with `git-protected`, as the standard spelling
  does. An argument after the subcommand matches a listed flag when it is
  identical, when it is `--name=value` and `--name` is listed, when it is a
  strict prefix of a listed long option (a `--x`, however short; combined with
  `=value` it still matches, as `--force-c=x` does), or when it is a
  single-dash group that is not a number and holds a listed short option as
  any of its letters before a `=`. The rule covers every `ask_flags` entry, the
  baseline's (`branch`, `tag`, `switch`, `symbolic-ref`) and an overlay's
  (`worktree`, a replaced `branch`). Known limit: `ask_flags` does not know
  which options take a value, so a value glued to a short option
  (`git switch -cfix`, `git tag -mdone`) or a separated value that starts with
  `-` (`git branch --sort -committerdate`) can contain a listed letter and ask
  once too often; a separated value that does not start with `-`
  (`git switch -c fix`) does not ask, and `--opt=value` is the way to write one
  that does (`git branch --sort=-committerdate`). `max_positionals`,
  `safe_first_arg`, `safe_grammar` and `safe_flags` are unchanged. Replayed on
  22,913 distinct commands from real agent sessions that mention git, no real
  agent command changes verdict: the only ones that do are the probes written
  to exhibit this bypass. Details:
  [`ask_flags`](docs/reference/policy.md#rulescommandgit-the-four-declarative-conditional-forms).
- **A git command no longer runs code of the caller's choosing because of what
  stands before the subcommand.** The git analysis skipped global options and
  environment assignments and judged only the subcommand, so an allowed one
  (`status`, `diff`, `commit`, `log`…) executed arbitrary code without a
  prompt: `git -c core.fsmonitor='<shell>' status` ran the shell command,
  `git -c core.hooksPath=/tmp/h commit -m x` the hook found there,
  `GIT_EXTERNAL_DIFF=/x git diff` the program, `git --config-env=core.pager=X
  diff` and `git --exec-path=/tmp/x status` a pager or a `git-*` helper. Such a
  command now answers `confirm [git-config-exec]`, a new rule id, unless every
  item is on an allow-list. Three lists of `command.git` hold them
  (`allowed_global_options`, `allowed_config`, `allowed_env`): an entry is a
  name, which allows it at any value (`user.*`, `GIT_AUTHOR_*`), or
  `name=value`, which allows that one value (`core.pager=cat`,
  `core.hooksPath=/dev/null`, `GIT_EDITOR=true`). The baseline lists identity,
  colour, signing and locale settings, `-C`, `--no-pager` and the like, and the
  harmless value of the editor, pager, hooks, fsmonitor and `GIT_TRACE` keys
  (`GIT_TRACE` only at `0`, `1`, `2`, `true` or `false`: any other value is a
  file git appends its trace to; the other `GIT_TRACE*` variables are not
  listed); everything else asks, `PATH`, `HOME`, `GIT_SSH_COMMAND` and
  `GIT_CONFIG_GLOBAL` included. A `--config-env` setting is judged by its key
  only, as its value is read from the environment when git runs. `--config-env`
  joins the global options that take a value, so `git --config-env core.pager=X
  diff` is no longer read with `core.pager=X` as the subcommand. A subcommand
  that asks on its own keeps `git-protected` (`git -c core.pager=x push`,
  `git -c user.name=x init -q`): the new rule only turns an allow into a
  confirm. The three lists are widened through `[[relax]]` only, reason
  mandatory, shown by `bouncer doctor` and `bouncer rules list`. Known limits:
  an `export` in the same line or an
  earlier call is not read, `GIT_INDEX_FILE` is allowed at any value although
  git writes its index where it points (a new file at most with the
  subcommands the baseline allows), and a config file written into a
  directory named by `--git-dir` or `GIT_DIR` is not seen. Replayed on 20,554
  distinct commands from real agent sessions that mention git, 11 commands
  change from allow to confirm: ten are probes and tests (ssh, config and
  trace experiments, a stub-`git` test), one is `GIT_EDITOR="cp <message
  file>" git commit --fixup=…`. Details:
  [`git-config-exec`](docs/reference/policy.md#git-config-exec-what-may-stand-before-git).

## [1.9.0] - 2026-10-13

### Added

- `git init` no longer asks when its options are on a short allow-list: `-q` /
  `--quiet`, `-b <name>` / `--initial-branch <name>` / `--initial-branch=<name>`,
  and at most one directory. `git init`, `git init -q`, `git init --quiet <dir>`,
  `git init -q -b develop .`, `git -C <dir> init -q` and `git init -q
  2>/dev/null` pass; every other form (`--bare`, `--template`,
  `--separate-git-dir`, `--shared`, `--object-format`, `--ref-format`, an
  abbreviated long option, grouped short options such as `-qb main`, a glued
  value such as `-bmain`, `--`, two directories, a global option other than
  `-C <dir>` such as `git --bare init` or `git -c … init`) still asks with
  `git-protected`. An allowed `init` is logged as `observe
  git-conditional-init`, so `bouncer audit` keeps showing what the change lets
  through.
- `safe_flags`, a fourth declarative git-conditional form
  (`[[rules.command.git.safe_flags]]`): an allow-list of options for one git
  subcommand — `flags`, `value_flags` and `max_positionals` — the inverse of
  `ask_flags`. It is the mechanism behind the `init` entry and is available to
  overlays and the `bouncer-policy` skill. An unknown or abbreviated option
  asks by construction, and so does any global option other than `-C <dir>`
  written before the subcommand. Entries are shape-checked on load (any unknown key
  rejects the layer), two files of one layer declaring the same `sub` conflict,
  an overlay entry wins over the baseline, and an entry that replaces a
  governed subcommand needs a `reason`, is listed by `bouncer doctor` as an
  active relaxation and appears in `bouncer rules list` as an `overlay-relax`
  line.
- `docs/how-to/keep-env-secrets-away-from-agents.md` shows an operator what
  the 1.8.0 environment rows do, how to check and relax them, and how to
  close the gap at the launcher. `docs/adr/0007-environment-secrets-baseline-net.md`
  records why they are a net and not a barrier.
- **A write that carries the value of a protected environment variable is
  blocked** (`env-value`, in `rules.write_secret`). Before a `Write` / `Edit`
  (also `MultiEdit`, the pi-agent `write` / `edit` and a Codex patch's added
  lines), Bouncer reads the environment of the hook process — the agent's own —
  keeps the variables whose name is protected (the 1.8.0 definition: `TOKEN`,
  `PASSWORD`, `PASSWD`, `SECRET`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`,
  `ACCESS_KEY`, `CREDENTIALS`) and whose value has at least 8 characters, and
  blocks the call when the text contains such a value in clear, in base64
  (standard and URL-safe alphabets, padded or not, at any alignment inside a
  longer stream) or in hex (all lowercase or all uppercase). It catches the
  secret an agent copies into a file after a script printed it. The reason
  names the variable and tells the agent to reference it by name; the audit
  log records the names in a new optional `env_vars` field, and on an
  `env-value` verdict the value — in clear, base64 or hex — reaches no log field, message
  or stderr line (a Bash command that carries a literal value and is blocked by
  another rule is still logged as written). It is a net,
  not a barrier: a value that is split, reversed or re-encoded evades, and
  under Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` the hook sees no
  value for the stripped variables. The row can be disabled or relaxed with
  `[[override]]` like any baseline row. Details:
  [The env-value row](docs/reference/policy.md#the-env-value-row).

### Changed

- **Upgrade:** the baseline gains one row with a new id, `env-value`
  (`rules.write_secret`). An overlay layer that already carries a row with that
  id is rejected as a unit: run `bouncer rules lint` and `bouncer doctor`
  after upgrading. `bouncer rules list` now counts 112 baseline rules. A
  workflow whose files legitimately carry a variable's value (a shared dev
  password in a compose file) disables or relaxes `env-value` with an
  `[[override]]`.
- **Upgrade:** `init` is now a baseline-governed git subcommand. An overlay
  entry for `init` in `ask_flags`, `safe_first_arg`, `safe_grammar` or
  `safe_flags` without a `reason` is rejected as a unit: run `bouncer rules
  lint` and `bouncer doctor` after upgrading.
- `bouncer audit --suggest` no longer proposes a blanket `[[relax]]` of
  `command.git.safe_subcommands` for a git subcommand the effective policy
  already governs (baseline or overlay: `init`, `branch`, `tag`, … in any of
  the four tables, plus `checkout` and `restore`): that block would cancel
  the conditional rule rather than widen it. A comment names the governing
  form and says to edit or substitute it instead. A subcommand no table
  governs (`gc`, `push`) is suggested as before.

## [1.8.0] - 2026-10-13

### Added

- Environment rows in the secret baseline. The agent's own environment holds
  what its launcher exported (direnv, a profile, a CI runner) and, until now,
  every way of reading it was allowed. The rows are a net, not a barrier:
  Bouncer judges command text and cannot remove a variable.
  - **Dumps of the whole environment are blocked** (`env-dump`,
    `env-dump-ps`, `env-dump-launchctl`, `env-dump-jq`, `env-dump-docker`):
    `env` / `printenv` that run no command, `export` and `export -p`,
    `declare` / `typeset` with `-x` / `-p`, bare `set`, `compgen -e`,
    `${!PREFIX@}`, `ps` with the BSD `e` operand or macOS `-E`,
    `launchctl getenv`, jq's `env` / `$ENV`, `docker exec … env` and
    `docker compose config` (not with `-q` / `--quiet`, `--services` and the
    other flags that print no environment). These rows read command position
    (after `;`, `&&`, a pipe, `$(`, `sh -c`, a wrapper such as `command` or
    `time`): a search or a sentence that merely spells `launchctl getenv`,
    `jq -n env` or `docker exec c env` is not the command.
    `/proc/<pid>/environ` is a secret path
    (`proc-environ`): the Read tool is covered, not only Bash. `env FOO=1 make`,
    `set -e`, `export FOO=bar`, `ps -ef` and `ps aux` stay allowed;
    `docker inspect` asks (`env-dump-docker-inspect`).
  - **References to a protected variable name** — uppercase, equal to or
    ending in `_` plus `TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `API_KEY`,
    `APIKEY`, `PRIVATE_KEY`, `ACCESS_KEY` or `CREDENTIALS` — in `$NAME`,
    `process.env.NAME`, `os.environ[…]`, `ENV[…]`, `getenv(…)` and the like
    are blocked when they feed a display (`echo`, `printf`, `print`, `puts`,
    `console.log`: `env-ref-display`) and ask otherwise (`env-ref`:
    `curl -H "Authorization: Bearer $TOKEN"` is legitimate use). The whole
    environment object (`process.env`, `os.environ`, `ENV` alone) and a name
    computed at runtime are blocked (`env-ref-whole`, `env-ref-computed`),
    because a name rebuilt from pieces would slip past every name rule. A
    non-protected name (`$HOME`, `process.env.NODE_ENV`) and a search pattern
    (`rg 'process.env' src`) stay allowed.
  - The protected-name definition is written once (`src/protected-names.ts`)
    and documented in `docs/reference/policy.md`, "The environment rows".
    The long alternations the rows share are load-time fragments
    (`src/policy/fragments.ts`, a `{{name}}` in a baseline regex): an unknown
    or unfilled placeholder makes the baseline refuse to load, and `rules
    lint` rejects any `{{…}}` in an overlay layer.

### Changed

- `credential-printer` (still `confirm`, same id: an overlay that relaxed it
  keeps working) also covers `gh` / `glab auth status -t`,
  `glab config get token`, `git credential fill`, `docker-credential-* get`,
  `npm` / `pnpm config get …_auth[Token]`, `aws configure get` of a secret
  key or session token, and `aws configure export-credentials`.
- **Upgrade:** the baseline gains rows with new ids (`env-dump`,
  `env-dump-ps`, `env-dump-launchctl`, `env-dump-jq`, `env-dump-docker`,
  `env-dump-docker-inspect`, `env-ref-display`, `env-ref-whole`,
  `env-ref-computed`, `env-ref`, `proc-environ`). An overlay layer that
  already carries a row with one of these ids is rejected as a unit: run
  `bouncer rules lint` and `bouncer doctor` after upgrading. A workflow that
  inspects containers all day relaxes `env-dump-docker-inspect` with an
  `[[override]]`.

## [1.7.0] - 2026-10-13

### Fixed

- `bouncer harness shim pi-agent` without `--bin` baked Bun's resolved binary
  path, so under Homebrew the printed pi/omp extension pointed into
  `…/Cellar/bouncer/<version>/bin/bouncer` — a directory `brew upgrade`
  removes, after which the shim failed closed on every tool call. It now bakes
  the path bouncer was invoked through (`/opt/homebrew/bin/bouncer`, or the
  symlink found on `PATH`), falling back to the resolved path when that cannot
  be told; `--bin` is unchanged. `bun run src/cli.ts` still bakes `bun`'s path.
- `doctor --harness pi-agent` now fails `wiring:binary` for a shim that bakes
  a versioned Homebrew Cellar path, even while the file still exists, and
  names the reprint command with `--bin <prefix>/bin/bouncer`. The Homebrew
  caveats now say to print through `$(brew --prefix)/bin/bouncer` instead of
  claiming the path changes on upgrade.
- **Upgrade:** a shim printed under Homebrew without `--bin` bakes
  `…/Cellar/bouncer/<old version>/bin/bouncer`, which this very upgrade
  removes. Check before `brew upgrade`:
  `grep 'const BOUNCER' <dir>/extensions/bouncer.ts`. If it names a Cellar
  path, reprint it first with
  `bouncer harness shim pi-agent --bin "$(brew --prefix)/bin/bouncer" > <dir>/extensions/bouncer.ts`.
  Already upgraded? pi/omp block every tool call until the reprint: run the
  same command from a plain shell, then restart the session.

## [1.6.0] - 2026-10-12

### Added

- `doctor --harness pi-agent` reports omp profiles (`~/.omp/profiles/*/agent`)
  that miss the shim or carry a stale one. omp loads no extension from
  `~/.omp/agent` in a profiled session, so such a profile runs without
  bouncer: one `wiring:shim (profile <name>)` line per profile (folders omp
  refuses as a profile name are skipped), with the reprint command, exit code
  1 while one fails. The session-start notice names a failing profile on a
  line of its own — "another omp profile has no Bouncer shim: <name> — …" —
  never as this session being unguarded. Nothing is installed automatically.

### Changed

- The pi/omp shim's ask dialog is a numbered, one-key select — `1. Allow` /
  `2. Block` — instead of Yes/No. Only the exact answer `1. Allow` runs the
  call; `2. Block`, Esc, an abort or a failing dialog block, as before. Under
  omp 18.9.1 `1`/`2` answer instantly and `2. Block` is highlighted by
  default, so a stray Enter never approves; under pi 0.84.1 the digits do
  nothing and `1. Allow` stays highlighted, so a stray Enter allows — as it
  did with the former Yes/No dialog (measured live, recorded in
  `pi-agent.toml`'s `ask_probe`).
- **Upgrade:** the shim's bytes changed, so reprint it for each install —
  `bouncer harness shim pi-agent > <dir>/extensions/bouncer.ts` (the same
  `--bin` as at install time; `~/.pi/agent` and `~/.omp/agent`) — and
  restart the session. `bouncer doctor --harness pi-agent` reports
  `[fail] wiring:shim` until the installed copy matches again.

### Fixed

- Herdr kept the agent `working` for the whole wait of a Bouncer ask in omp:
  the shim now emits omp's `herdr:blocked` event around the dialog (when a UI
  exists) — the event Herdr's own omp integration turns into `blocked` — and
  releases it after the answer. The signal changes no verdict. Known limit:
  vibe-island listens to omp's `tool_approval_*` events, not to
  `herdr:blocked`, so it stays blind to a Bouncer ask.

## [1.5.0] - 2026-09-22

### Added

- Git `safe_grammar` accepts `{ kind = "sha" }` argument slots for 7–64
  hexadecimal characters, without resolving Git objects.

### Fixed

- Shell redirections no longer hide following Git options or count as Git
  arguments; protected write destinations remain checked.

## [1.4.0] - 2026-09-17

### Added

- Audit-log `target_truncated: true` marks entries whose targets were cut.
- `audit` reports a Policy delta section and replay headers.

### Changed

- `audit` and `audit --suggest` replay the selected window against the current
  policy before reporting friction or suggestions.

### Fixed

- Audit-log targets are capped at 4,096 characters instead of 200, retaining
  matching tokens that previously fell past the old cap.

## [1.3.0] - 2026-09-16

### Added

- `bouncer skill <id>` prints an embedded, version-matched agent skill; `policy`
  is the first id.
- The `bouncer-policy` skill: human-gated workstation policy tuning from a
  request or from `audit --suggest` — narrowest lever first, profile layer by
  default, two gates, lint/provenance/verdict proofs, strict refusals.

## [1.2.0] - 2026-09-14

### Added

- `docs/how-to/install.md` describes Homebrew and checkout installation paths.

### Changed

- `scripts/tag-release.sh` is the maintainer's build, checksum, provenance, and
  local-tag guard.

### Removed

- `scripts/install.sh`, the local installer. Use Homebrew, or run `bun run
  build` and wire `dist/bouncer`.

## [1.1.2] - 2026-09-14

### Fixed

- The release workflow's Homebrew install gate now puts the runner's
  preinstalled Homebrew on `PATH`; the 1.1.1 tap update failed before running
  (`brew: command not found`), so the tap still served the 1.1.0 formula.

## [1.1.1] - 2026-09-14

### Fixed

- The published Homebrew formula declared its caveats as a block, which
  Homebrew rejects (`brew install jrobic/tap/bouncer` failed on 1.1.0). The
  formula now defines `caveats` as a method, and the release workflow installs
  and tests the rendered formula on the runner before pushing it to the tap.

## [1.1.0] - 2026-09-14

### Added

- Homebrew tap: `brew install jrobic/tap/bouncer` on macOS Apple Silicon and
  Linux x64; the release workflow publishes the formula on every tag.
- `bouncer harness shim <id> --bin <path>` bakes a chosen absolute binary path
  into the printed pi/omp extension (a stable symlink such as
  `$(brew --prefix)/bin/bouncer`) instead of the process's real path.

### Changed

- Release artefacts are `bouncer-<version>-<target>.tar.gz` archives with a
  `.sha256` checksum each, instead of bare binaries.

## [1.0.0] - 2026-09-14

First public release.

### What it does

- One standalone binary judges a coding agent's tool calls before they run:
  `run` (the hook), `check` (a dry run), `rules`, `harness`, `audit`, `doctor`,
  `--version`.
- An embedded baseline of 100 rules in six families: shell commands (32 regex
  rows plus algorithmic matchers for `rm -rf`, privilege escalation, protected
  git operations and destructive Docker calls), secret paths (17) and
  secret-reading commands (7), protected writes (29, including one row per
  declared harness configuration directory), secret writes (8), MCP writes
  (a read-prefix allow list) and prompt-injection signatures (7).
- Three adapted harnesses — Claude Code (hook file), Codex (hooks), pi/omp
  (extension shim) — and three declared ones (opencode, Gemini CLI, Cursor)
  whose configuration directories are write-guarded.
- Fail-closed liveness in three layers, a shadow mode with `audit --diff` for a
  cutover, a JSONL audit log, a two-layer TOML overlay (common, then profile)
  with reasoned overrides and relaxations, and build identity plus policy
  digest in `--version`, `doctor` and every log line.

### Added

- Tagged versions are published as GitHub Releases with Linux x64 and macOS
  arm64 binaries and their SHA-256 checksums (`.github/workflows/release.yml`).

### Changed

- Version 1.0.0 marks the public release; no rule or engine change since 0.2.0.

## [0.2.0] - 2026-09-13

### Changed

- Excluded `ask_probe` provenance notes from the policy digest; the baseline digest reported by `--version`, `doctor`, and the audit log changes from `e2bf59f955ba` to `0b41bf352a2a`.
- Preserved command heads in shell substitutions.
- Rewrote the README for external readers and refreshed the terminal recording.
- Removed private repository references from `bouncer harness list`.

## [0.1.1] - 2026-09-13

### Added

- Added `scripts/install.sh` for building, backing up, atomically installing, tagging, and checking releases.

## [0.1.0] - 2026-09-12

### Added

- Added `bouncer --version` (and `--version --json`).
- Added the policy digest and build identity to the audit log.
- Added the `binary` doctor check, `dist/bouncer.sha256`, and the first release tag.

[Unreleased]: https://github.com/jrobic/agent-bouncer/compare/v1.10.0...HEAD
[1.10.0]: https://github.com/jrobic/agent-bouncer/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/jrobic/agent-bouncer/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/jrobic/agent-bouncer/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/jrobic/agent-bouncer/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/jrobic/agent-bouncer/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/jrobic/agent-bouncer/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/jrobic/agent-bouncer/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/jrobic/agent-bouncer/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/jrobic/agent-bouncer/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/jrobic/agent-bouncer/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/jrobic/agent-bouncer/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jrobic/agent-bouncer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jrobic/agent-bouncer/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/jrobic/agent-bouncer/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jrobic/agent-bouncer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jrobic/agent-bouncer/releases/tag/v0.1.0
