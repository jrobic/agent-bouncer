# Build, tag, and publish a bouncer release

Goal: produce an identifiable executable, verify its checksum, create its
annotated release tag, and publish the tagged version as a GitHub Release and
Homebrew update.

## Prerequisites

- A committed version bump in `package.json`.
- Bun and the repository dependencies installed.

## Steps

1. Choose the version bump before building. Use a patch version for policy rows,
   fixtures, documentation, build tooling, or scripts; use a minor version for
   engine, adapter, CLI, or audit-log format changes; use a major version when
   a documented contract breaks (CLI grammar, policy TOML schema, audit-log
   shape, hook wiring).
   Add the `CHANGELOG.md` entry under the new version and move completed
   `Unreleased` items into it.

2. From the repository root, run:

   ```sh
   scripts/tag-release.sh
   ```

   The script builds `dist/bouncer`, verifies `dist/bouncer.sha256`, reads the
   artifact's version metadata, rejects a dirty build, rejects an artifact whose
   build SHA differs from `HEAD`, rejects an existing `v<version>` tag, and
   creates the annotated local tag. It never pushes a tag.

3. Publish. Push the tag to the repository:

   ```sh
   git push origin v<version>
   ```

   The `Release` workflow (`.github/workflows/release.yml`) builds the tagged
   commit on Linux x64 and macOS arm64, verifies each checksum, checks that
   every artefact reports the tagged version without `-dirty`, and packages
   each executable as `bouncer-<version>-<target>.tar.gz` with its `.sha256`.
   It creates the GitHub Release from those archives, then the `homebrew` job
   renders the tap formula from the downloaded checksums, installs it from a
   throwaway tap on the runner (`brew install`, `brew test`, `--version` equals
   the tag) and only then pushes it to `jrobic/homebrew-tap`. The job fails
   when `HOMEBREW_TAP_TOKEN` is empty; it never skips the tap update. The
   release body is the `CHANGELOG.md` section of that version
   (`scripts/changelog-section.sh <version>`); the workflow fails before
   publishing when that section is missing or empty.

   Verify the tap after the workflow completes:

   ```sh
   brew update && brew info jrobic/tap/bouncer
   ```

4. [Update your own machine](install.md#homebrew):

   ```sh
   brew upgrade jrobic/tap/bouncer
   bouncer doctor
   ```

## Verify

- `shasum -a 256 -c dist/bouncer.sha256` reports `dist/bouncer: OK`.
- `bouncer --version --json` reports the expected version, clean SHA, and build
  date.
- The GitHub Release `v<version>` lists two `.tar.gz` archives and two
  `.sha256` files; a downloaded archive and checksum pass `shasum -a 256 -c`.
- After the Homebrew upgrade, `bouncer doctor` reports `[pass] binary` for the
  installed executable.

---
Source: package.json, scripts/build.ts, scripts/tag-release.sh,
scripts/changelog-section.sh, scripts/brew-formula.sh,
.github/workflows/release.yml, src/build-info.ts, src/adapter/doctor.ts,
docs/reference/cli.md
