# Audit log reference

One JSONL file per account, per harness (ADR-0006 § 8): `<configDir>/logs/hooks/bouncer.log`,
where `<configDir>` is resolved from the TARGET harness's own declaration
(`policy/harness/<id>.toml` — the first of its `env` names actually set in
the environment, falling back to its `witness`; for the default harness,
`claude-code`, that's `CLAUDE_CONFIG_DIR`, falling back to `~/.claude` —
see `docs/reference/policy.md`). A second account (a separate config dir)
gets its own file; a different harness on the SAME account gets its own
file too — nothing is ever shared or interleaved.

Every line is one JSON object and carries a `harness` field (the target
harness's own id — always present since ticket 15a; an entry without one
predates ADR-0006). Three shapes share the file, distinguished by their
OTHER fields (there's no second `kind` field common to all three — a
verdict entry is recognized by having `rule_id`, `verdict`, and `family`
all present as strings; the other two carry a `kind` field instead).

## Verdict entry

Written for every `block`/`confirm`/`observe` verdict from `PreToolUse`,
and every `flag` from `UserPromptSubmit` — including `observe`, which
never reaches the model and never appears on stdout (see
`docs/reference/cli.md`'s `run` section). A clean, unremarkable tool call
produces no line at all.

```json
{"timestamp":"2026-08-17T08:56:56.332Z","harness":"claude-code","session_id":null,"tool_name":"Bash","family":"command","verdict":"block","rule_id":"rm-rf-dangerous","target":"rm -rf /"}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601, set when the line is written. |
| `harness` | string | The target harness's own declaration id (e.g. `"claude-code"`). |
| `session_id` | string \| null | From the hook envelope; `null` when absent. |
| `tool_name` | string \| null | From the hook envelope; `null` when absent. |
| `family` | string | `"command"` \| `"secret"` \| `"mcp-write"` \| `"write-secret"` \| `"protected-write"` \| `"prompt"`. |
| `verdict` | string | `"block"` \| `"confirm"` \| `"observe"` \| `"flag"`. |
| `rule_id` | string | The id of the rule (or engine algorithm name, e.g. `rm-rf-dangerous`) that fired. |
| `target` | string | The command/path/URL/prompt text the rule matched against, truncated to 200 characters (`...` appended when cut). |

## Audit-header entry

Written once, as the FIRST line of a newly created or freshly rotated
log file, when the policy that produced the entry about to follow it has
at least one of: an active override, an active relaxation, OR (ADR-0006
§ 5, ticket 15a) a harness this account's overlay declared or extended —
`overlay_harnesses` below. Never written into an existing, non-empty
file, and never written at all when none of the three is true — a
healthy, unmodified baseline account never gets one, even one running a
harness whose own declaration ships no `[harness.protocol]`.

```json
{"timestamp":"2026-08-17T08:57:11.249Z","harness":"claude-code","kind":"audit-header","overrides":[{"id":"curl-file-upload","action":"disable","reason":"our CI legitimately uploads build artifacts via curl in every deploy"}],"relaxations":[],"overlay_harnesses":[]}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601. |
| `harness` | string | The target harness's own declaration id. |
| `kind` | string | Always `"audit-header"`. |
| `overrides` | array | One `{id, action, reason}` per active `[[override]]` — `id` is the overridden rule's id. |
| `relaxations` | array | One `{id, action, reason}` per active `[[relax]]` (or governed-`sub` substitution) — `id` is `"<list>:<value>"`, `action` is always `"relax"`. |
| `overlay_harnesses` | array of string | Every harness id declared or extended by this account's overlay (never a pure-baseline harness untouched by any layer) — `[]` when none, which is still a legal, distinct-from-absent header when an override/relaxation alone triggered it. |

## Policy-warning entry

Written once per warning: one entry per REJECTED LAYER (ADR-0001
§ Rejection — a broken common file and a broken profile file each get
their own entry, naming their own layer and file), one for the migration
guard (see `docs/reference/policy.md`'s fail-closed behavior), one when a
dispatch throw forced a retry against the embedded baseline, one when the
`SessionStart` doctor check itself failed and fell back to silence, or
one when `run` was invoked with an unknown or protocol-less `--harness
<id>` (ADR-0006 § 6 — logged only when a log path can be resolved for it,
which an UNDECLARED id cannot be).

```json
{"timestamp":"2026-08-17T08:57:04.656Z","harness":"claude-code","kind":"policy-warning","message":"profile layer rejected — policy.d/20-broken.toml: Failed to parse toml"}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601. |
| `harness` | string | The target harness's own declaration id. |
| `kind` | string | Always `"policy-warning"`. |
| `message` | string | Free-form — the same rejection reason `bouncer rules lint` prints, a dispatch-retry message, a doctor-check-failure message, or the unknown/protocol-less-harness message. |

## Rotation

Size-based: before any append, if the file is at or above 5 MB, it's
renamed to `bouncer.log.1` (overwriting a previous `.1` if one exists)
and a fresh file is started. No time-based rotation, no count beyond the
one `.1` generation.

## File modes

The `logs/hooks/` directory is created (if absent) with mode `0700`. The
log file is created with mode `0600` — owner read/write only, no group
or world access — but that mode is a creation-time default, not
re-applied on later appends: `bouncer` never re-`chmod`s an existing
log file, so a mode changed by hand (or inherited from a restored
backup) stays changed until something else fixes it.

## Per-harness routing (ADR-0006 § 8)

The config directory a harness's log lives under is read from that
harness's OWN declaration, in declaration order: the first name in its
`env` array that's actually set in the environment, falling back to its
`witness`. For the default harness, `claude-code`, that's
`CLAUDE_CONFIG_DIR` (falling back to `~/.claude`) — unchanged from
before ADR-0006. `--harness <id>` on `run`/`check`/`doctor`/`audit`
resolves a DIFFERENT harness's own env names instead (`docs/reference/cli.md`);
two harnesses never share a log file, even on the same account.

---
Source: src/adapter/log.ts, src/adapter/log-path.ts, src/policy/load.ts, src/policy/schema.ts
