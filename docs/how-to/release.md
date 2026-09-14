# Build, install and publish a bouncer release

Goal: produce an identifiable executable, verify its checksum, install it at one
chosen destination, verify the current profile against that executable, and
publish the tagged version as a GitHub Release.

## Prerequisites

- A committed version bump in `package.json`.
- Bun and the repository dependencies installed.
- The destination path where the executable will be installed.

## Steps

1. Choose the version bump before building. Use a patch version for policy rows,
   fixtures, documentation, build tooling, or scripts; use a minor version for
   engine, adapter, CLI, or audit-log format changes. Do not create a major
   version before the public release.
   Add the `CHANGELOG.md` entry under the new version and move completed `Unreleased` items into it.

2. From the repository root, run:

   ```sh
   scripts/install.sh --tag
   ```

   The script builds `dist/bouncer`, verifies `dist/bouncer.sha256`, rejects a
   dirty artifact unless `--allow-dirty` is explicit, retains one backup of an
   existing destination, atomically installs the verified executable, creates
   the annotated local `v<version>` tag, and runs `doctor` for the current
   profile. It never pushes a tag.

   The default destination is `$HOME/.local/bin/bouncer`. Pass `--dest <path>`
   for another destination, or `--from <dir>` to install an already-built
   artifact containing `bouncer` and `bouncer.sha256`.

   With `--tag`, the script refuses a dirty tree, an existing `v<version>` tag,
   or an artifact whose build SHA differs from `HEAD`. `--from` accepts the
   `dist/` output produced by `bun run build`.

3. Publish. Push the tag to the repository:

   ```sh
   git push origin v<version>
   ```

   The `Release` workflow (`.github/workflows/release.yml`) builds the tagged
   commit on Linux x64 and macOS arm64, verifies each checksum, checks that
   every artefact reports the tagged version without `-dirty`, and creates the
   GitHub Release `v<version>` with `bouncer-<version>-<target>` and its
   `.sha256` for both targets. The release body is the `CHANGELOG.md` section
   of that version (`scripts/changelog-section.sh <version>`); the workflow
   fails before publishing when that section is missing or empty.

## Verify

- `shasum -a 256 -c dist/bouncer.sha256` reports `dist/bouncer: OK`.
- The GitHub Release `v<version>` lists two binaries and two `.sha256` files;
  a downloaded pair passes `shasum -a 256 -c`.
- `bouncer --version --json` reports the expected version, clean SHA, and build
  date.
- `bouncer doctor` reports `[pass] binary` for the installed executable.

  A `[warn] binary` means the executable is a source or dirty build. It remains
  usable for development, but is not a verified release.

---
Source: package.json, scripts/build.ts, scripts/install.sh,
scripts/changelog-section.sh, .github/workflows/release.yml, src/build-info.ts,
src/adapter/doctor.ts, docs/reference/cli.md
