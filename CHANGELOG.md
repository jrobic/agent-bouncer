# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the Homebrew tap for `brew install jrobic/tap/bouncer`.

### Changed

- Release artefacts are now `.tar.gz` archives with SHA-256 checksums.

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

[Unreleased]: https://github.com/jrobic/agent-bouncer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jrobic/agent-bouncer/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/jrobic/agent-bouncer/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jrobic/agent-bouncer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jrobic/agent-bouncer/releases/tag/v0.1.0
