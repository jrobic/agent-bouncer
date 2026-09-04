# Architecture Decision Records

Decisions that shape `bouncer` beyond one ticket. One file per decision,
Nygard format, never edited into a different decision — a change of mind is
a new ADR that supersedes the old one.

## Index

| # | Title | Status | Date |
|---|---|---|---|
| [ADR-0001](0001-layered-policy-common-then-profile.md) | Layered policy — a harness-neutral common layer read natively, the profile layer wins | Accepted | 2026-09-03 |
| [ADR-0002](0002-sops-age-decryption-is-a-human-act.md) | sops/age decryption is a human act — the baseline blocks it for the agent | Accepted | 2026-09-04 |
| [ADR-0003](0003-liveness-fail-closed-in-three-layers.md) | Liveness — Claude Code runs hooks fail-open, so bouncer fails closed in three layers | Accepted | 2026-09-04 |

## Statuses

- **Proposed** — under discussion.
- **Accepted** — decided; the implementation plan inside is the contract.
- **Deprecated** — no longer applies.
- **Superseded by ADR-XXXX** — replaced.
