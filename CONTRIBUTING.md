# Contributing

## Build

```sh
bun install
bun run build
```

## Verify

```sh
bun run verify
```

`bun run verify` runs TypeScript type checking, oxlint, dprint, and the test suite.

## Propose a Rule

Add a behavior fixture to the relevant family under `fixtures/` (for example, `fixtures/command.json` or `fixtures/secret.json`) before implementing a rule. Follow [Add a custom rule](docs/how-to/add-a-custom-rule.md) for the policy shape and validation steps.

Tracked files never cite an internal ticket number, an internal decision ID, an internal review finding ID or `.scratch/`. Cite an ADR section, a documentation page, a merged PR or a commit on `main`, or state the reason or the measured fact. When a comment or a test title only names its origin, remove the reference instead of replacing it.

One exception: `policy/harness/pi-agent.shim.ts` is compared byte for byte with every installed copy, so its references are cleaned only with the next behaviour change to the shim.

## Declare a Harness

Follow the [harness declaration reference](docs/reference/policy.md#harness-assistant-configuration-declarations) and [ADR-0006](docs/adr/0006-declarative-harness-adapters.md).

## Commit and Format

Use Conventional Commits. Run dprint only on files you changed; do not format unrelated files.
