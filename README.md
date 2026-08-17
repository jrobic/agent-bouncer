# agent-bouncer

**The bouncer for your coding agent's tool calls.**

`bouncer` is a single standalone binary that guards the tool calls of coding
agent harnesses (Claude Code first): destructive commands, secret reads and
writes, MCP writes, prompt-injection signatures — one process, one verdict
path, one audit log. The engine is compiled; the policy is TOML (an embedded
vetted baseline plus a user overlay with loud, reasoned overrides).

> **Status: pre-v1, spec-driven.** No packaged release yet — build it from
> this checkout (Quickstart below). The spec and the ticket breakdown live
> in `.scratch/bouncer/` — a local, untracked tracker (same convention as
> the author's other repos) — for the design rationale behind anything not
> covered in `docs/`.

## Quickstart

```sh
bun run build   # produces dist/bouncer
```

Wire `dist/bouncer` into a Claude Code `settings.json`
(`docs/how-to/wire-into-claude-code.md` has the exact hooks block), then
verify:

```sh
./dist/bouncer doctor
```

## Documentation

| I want to... | Read |
|---|---|
| wire bouncer into a Claude Code session | [`docs/how-to/wire-into-claude-code.md`](docs/how-to/wire-into-claude-code.md) |
| add a rule of my own | [`docs/how-to/add-a-custom-rule.md`](docs/how-to/add-a-custom-rule.md) |
| disable/soften a baseline rule, or widen a safe list | [`docs/how-to/override-a-baseline-rule.md`](docs/how-to/override-a-baseline-rule.md) |
| find frequent friction and dead rules | [`docs/how-to/tune-rules-with-audit.md`](docs/how-to/tune-rules-with-audit.md) |
| look up a subcommand's flags, output, exit code | [`docs/reference/cli.md`](docs/reference/cli.md) |
| look up the TOML policy format | [`docs/reference/policy.md`](docs/reference/policy.md) |
| look up the audit log's JSONL shape | [`docs/reference/audit-log.md`](docs/reference/audit-log.md) |

## Provenance

These guards were initiated and designed by Jonathan Robic, evolved across
two prior private codebases (a workstation hook set and a catalog
generation) that this repository unifies. The
disler/claude-code-hooks-multi-agent-observability repository served as an
early comparison point on specific aspects (rm -rf detection), not as the
origin.

## License

Not chosen yet — required before the repository goes public.
