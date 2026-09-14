# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jrobic/agent-bouncer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jrobic/agent-bouncer/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jrobic/agent-bouncer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jrobic/agent-bouncer/releases/tag/v0.1.0
