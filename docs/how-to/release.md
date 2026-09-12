# Build and install a bouncer release

Goal: produce an identifiable executable, verify its checksum, install it at one
chosen destination, and verify the current profile against that executable.

## Prerequisites

- A committed version bump in `package.json`.
- Bun and the repository dependencies installed.
- The destination path where the executable will be installed.

## Steps

1. Choose the version bump before building. Use a patch version for policy rows,
   fixtures, or documentation; use a minor version for engine, adapter, CLI, or
   audit-log format changes. Do not create a major version before the public
   release.

2. Build from the repository root:

   ```sh
   bun run build
   ```

   The build records the committed short SHA, whether the tree is dirty, and the
   UTC build date in `dist/bouncer`. It also writes `dist/bouncer.sha256`.

3. Verify the executable and checksum:

   ```sh
   ./dist/bouncer --version
   shasum -a 256 -c dist/bouncer.sha256
   ```

   A release build should identify a clean SHA. A `-dirty` suffix is factual but
   should not be installed as a release.

4. Install the checked executable at the chosen destination:

   ```sh
   install -m 0755 dist/bouncer /path/to/destination/bouncer
   /path/to/destination/bouncer --version --json
   ```

   Preserve the JSON output with the release record when the destination is
   managed outside this repository.

5. Create the local tag for the version chosen in step 1. Tags are local release
   markers; do not push one as part of this procedure.

   ```sh
   git tag v<version>
   ```

6. Start a session in the current profile, then run:

   ```sh
   bouncer doctor
   ```

   The `binary` line should be `[pass]` and name the installed build plus the
   effective policy digest. `[warn] binary` means the process is a source or
   dirty build; it is usable for development but not a verified release.

## Verify

- `shasum -a 256 -c dist/bouncer.sha256` reports `dist/bouncer: OK`.
- `bouncer --version --json` reports the expected version, clean SHA, and build
  date.
- `bouncer doctor` reports `[pass] binary` for the installed executable.

---
Source: package.json, scripts/build.ts, src/build-info.ts, src/adapter/doctor.ts,
docs/reference/cli.md
