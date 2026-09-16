# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Audit-log `target_truncated: true` marks entries whose targets were cut.

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

[Unreleased]: https://github.com/jrobic/agent-bouncer/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/jrobic/agent-bouncer/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/jrobic/agent-bouncer/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/jrobic/agent-bouncer/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/jrobic/agent-bouncer/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jrobic/agent-bouncer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jrobic/agent-bouncer/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/jrobic/agent-bouncer/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jrobic/agent-bouncer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jrobic/agent-bouncer/releases/tag/v0.1.0
