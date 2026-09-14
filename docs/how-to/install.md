# Install bouncer

Goal: install a verified `bouncer` binary, preserve a stable executable path,
and wire that path into a coding-agent harness.

## Prerequisites

- [Homebrew](https://brew.sh/) for the published macOS Apple Silicon or Linux
  x64 release.
- [Bun](https://bun.sh/) to build from a checkout on any platform Bun supports.
- One harness configuration to wire. The harness-specific how-tos define the
  configuration each harness needs.

## Homebrew

Homebrew publishes releases for macOS Apple Silicon and Linux x64. Install the
current release, then keep its prefix path rather than a versioned Cellar path:

```sh
brew install jrobic/tap/bouncer
export BOUNCER_BIN="$(brew --prefix)/bin/bouncer"
"$BOUNCER_BIN" --version
```

Upgrade the installed release when a newer one is available:

```sh
brew upgrade jrobic/tap/bouncer
```

## From a checkout

On another platform, build and verify the binary from a checkout:

```sh
git clone https://github.com/jrobic/agent-bouncer.git
cd agent-bouncer
bun install
bun run build
shasum -a 256 -c dist/bouncer.sha256
export BOUNCER_BIN="$PWD/dist/bouncer"
"$BOUNCER_BIN" --version
```

`BOUNCER_BIN` is the absolute path to the verified `dist/bouncer` binary. Copy
that binary with `install -m 0755` only if the copied location is the path you
will wire instead.

## Wire the binary

Choose the relevant harness guide for its configuration:

- [Claude Code](wire-into-claude-code.md)
- [Codex CLI](wire-into-codex.md)
- [pi-agent and omp](wire-into-pi-agent.md)

For pi-agent or omp, choose its agent directory, create the extensions
directory, and print the shim with the selected binary path baked in:

```sh
export PI_CODING_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.omp/agent}"
mkdir -p "$PI_CODING_AGENT_DIR/extensions"
"$BOUNCER_BIN" harness shim pi-agent --bin "$BOUNCER_BIN" > "$PI_CODING_AGENT_DIR/extensions/bouncer.ts"
```

## Verify

The two installation routes set `BOUNCER_BIN` above. Verify that binary and the
wiring that invokes it:

```sh
"$BOUNCER_BIN" --version
"$BOUNCER_BIN" doctor
PI_CODING_AGENT_DIR="$PI_CODING_AGENT_DIR" "$BOUNCER_BIN" doctor --harness pi-agent
```

The version line identifies the release version, clean build SHA, and policy
digest. After wiring, the relevant `doctor` command reports `[pass] binary` for
the executable the harness starts.

---
Source: package.json, scripts/build.ts, scripts/tag-release.sh,
docs/how-to/wire-into-claude-code.md, docs/how-to/wire-into-codex.md,
docs/how-to/wire-into-pi-agent.md
