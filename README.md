# agent-bouncer

**The bouncer for your coding agent's tool calls.**

`bouncer` is a single standalone binary that guards the tool calls of coding
agent harnesses (Claude Code first): destructive commands, secret reads and
writes, MCP writes, prompt-injection signatures — one process, one verdict
path, one audit log. The engine is compiled; the policy is TOML (an embedded
vetted baseline plus a user overlay with loud, reasoned overrides).

> **Status: pre-v1, spec-driven.** Nothing to install yet. The spec and the
> ticket breakdown live in `.scratch/bouncer/` — a local, untracked tracker
> (same convention as the author's other repos). Read the spec first; it
> records every design decision and its rationale.

## Naming

- **Package:** `@jrobic/agent-bouncer` (personal npm scope — squat-proof);
  **repository:** `agent-bouncer`. The bare name was verified free on npm,
  crates.io, and Homebrew on 2026-08-16 (fallback name was `customs`);
  crates.io has no namespaces, so a future Rust crate would be bare
  `agent-bouncer`.
- **Binary on PATH:** `bouncer` — short, self-explanatory. No conflict with
  the CrowdSec ecosystem's bouncers: those binaries are named
  `crowdsec-*-bouncer`, never bare `bouncer`.

## Design in one paragraph

Guard logic that a declarative permission list cannot express (shell
tokenization, git subcommand extraction, conditional flag grammars,
default-ask inversion) lives in a compiled engine. Everything table-shaped
(regex rules, path rules, safe-git allowlists, MCP read prefixes) lives in
TOML. A harness adapter maps the engine's abstract verdicts
(block / confirm / flag / observe) onto the harness's real capabilities with
an explicit fail-closed degradation table — a harness that cannot ask,
blocks. Conformance is held by language-agnostic golden fixtures: any
reimplementation proves parity by passing the same cases.

## Provenance

These guards were initiated and designed by Jonathan Robic, evolved across
two prior private codebases (a workstation hook set and a catalog
generation) that this repository unifies. The
disler/claude-code-hooks-multi-agent-observability repository served as an
early comparison point on specific aspects (rm -rf detection), not as the
origin.

## License

Not chosen yet — required before the repository goes public.
