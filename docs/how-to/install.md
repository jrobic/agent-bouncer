# Install bouncer

Goal: install a verified `bouncer` binary and wire a stable executable path into
your coding-agent harness.

## Prerequisites

- Homebrew on macOS Apple Silicon or Linux x64, or a checkout on a platform Bun
  supports.
- A harness wiring destination. See the relevant wiring how-to before changing
  its configuration.

## Steps

1. On macOS Apple Silicon or Linux x64, install the published release with
   Homebrew:

   ```sh
   brew install jrobic/tap/bouncer
   ```

2. Use Homebrew's stable prefix path when wiring the binary. Never wire a
   versioned Cellar path: Homebrew replaces it on upgrade.

   ```sh
   "$(brew --prefix)/bin/bouncer" --version
   ```

3. For pi-agent or omp, print the extension with that stable path baked in:

   ```sh
   bouncer harness shim pi-agent --bin "$(brew --prefix)/bin/bouncer" > ~/.omp/agent/extensions/bouncer.ts
   ```

   You can instead export `BOUNCER_BIN` for the process that starts pi-agent or
   omp.

4. Upgrade the installed release when a newer one is available:

   ```sh
   brew upgrade jrobic/tap/bouncer
   ```

5. On another platform, build from a checkout instead:

   ```sh
   bun install
   bun run build
   shasum -a 256 -c dist/bouncer.sha256
   ```

   Wire the absolute path of `dist/bouncer`, or copy it to a location you
   control with `install -m 0755` before wiring that copy.

## Verify

```sh
bouncer --version
bouncer doctor
```

The version line identifies the release version, clean build SHA, and policy
digest. After wiring, `doctor` reports `[pass] binary` for the executable your
harness starts.

---
Source: package.json, scripts/build.ts, docs/how-to/wire-into-claude-code.md,
docs/how-to/wire-into-codex.md, docs/how-to/wire-into-pi-agent.md
