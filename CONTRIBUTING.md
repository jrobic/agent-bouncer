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

## Declare a Harness

Follow the [harness declaration reference](docs/reference/policy.md#harness-assistant-configuration-declarations) and [ADR-0006](docs/adr/0006-declarative-harness-adapters.md).

## Commit and Format

Use Conventional Commits. Run dprint only on files you changed; do not format unrelated files.
