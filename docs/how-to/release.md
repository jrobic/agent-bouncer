# Build and install a bouncer release

Goal: produce an identifiable executable, verify its checksum, install it at one
chosen destination, and verify the current profile against that executable.

## Prerequisites

- A committed version bump in `package.json`.
- Bun and the repository dependencies installed.
- The destination path where the executable will be installed.

## Steps

1. Choose the version bump before building. Use a patch version for policy rows,
   fixtures, documentation, build tooling, or scripts; use a minor version for
   engine, adapter, CLI, or audit-log format changes. Do not create a major
   version before the public release.

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

## Verify

- `shasum -a 256 -c dist/bouncer.sha256` reports `dist/bouncer: OK`.
- `bouncer --version --json` reports the expected version, clean SHA, and build
  date.
- `bouncer doctor` reports `[pass] binary` for the installed executable.

  A `[warn] binary` means the executable is a source or dirty build. It remains
  usable for development, but is not a verified release.

---
Source: package.json, scripts/build.ts, scripts/install.sh, src/build-info.ts,
src/adapter/doctor.ts, docs/reference/cli.md
