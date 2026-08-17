# Audit log reference

One JSONL file per account: `<configDir>/logs/hooks/bouncer.log`.
`<configDir>` is `~/.claude` unless `CLAUDE_CONFIG_DIR` is set — see
`docs/reference/policy.md`. A second account (a separate
`CLAUDE_CONFIG_DIR`) gets its own file; nothing is ever shared or
interleaved between accounts.

Every line is one JSON object. Three shapes share the file, distinguished
by their fields (there's no `kind` field common to all three — a verdict
entry is recognized by having `rule_id`, `verdict`, and `family` all
present as strings; the other two carry a `kind` field instead).

## Verdict entry

Written for every `block`/`confirm`/`observe` verdict from `PreToolUse`,
and every `flag` from `UserPromptSubmit` — including `observe`, which
never reaches the model and never appears on stdout (see
`docs/reference/cli.md`'s `run` section). A clean, unremarkable tool call
produces no line at all.

```json
{"timestamp":"2026-08-17T08:56:56.332Z","session_id":null,"tool_name":"Bash","family":"command","verdict":"block","rule_id":"rm-rf-dangerous","target":"rm -rf /"}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601, set when the line is written. |
| `session_id` | string \| null | From the hook envelope; `null` when absent. |
| `tool_name` | string \| null | From the hook envelope; `null` when absent. |
| `family` | string | `"command"` \| `"secret"` \| `"mcp-write"` \| `"write-secret"` \| `"prompt"`. |
| `verdict` | string | `"block"` \| `"confirm"` \| `"observe"` \| `"flag"`. |
| `rule_id` | string | The id of the rule (or engine algorithm name, e.g. `rm-rf-dangerous`) that fired. |
| `target` | string | The command/path/URL/prompt text the rule matched against, truncated to 200 characters (`...` appended when cut). |

## Audit-header entry

Written once, as the FIRST line of a newly created or freshly rotated
log file, when at least one override or relaxation is active in the
policy that produced the entry about to follow it. Never written into an
existing, non-empty file, and never written at all when nothing is
active — a healthy, unmodified baseline account never gets one.

```json
{"timestamp":"2026-08-17T08:57:11.249Z","kind":"audit-header","overrides":[{"id":"curl-file-upload","action":"disable","reason":"our CI legitimately uploads build artifacts via curl in every deploy"}],"relaxations":[]}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601. |
| `kind` | string | Always `"audit-header"`. |
| `overrides` | array | One `{id, action, reason}` per active `[[override]]` — `id` is the overridden rule's id. |
| `relaxations` | array | One `{id, action, reason}` per active `[[relax]]` (or governed-`sub` substitution) — `id` is `"<list>:<value>"`, `action` is always `"relax"`. |

## Policy-warning entry

Written once per warning: when the current overlay was rejected (see
`docs/reference/policy.md`'s fail-closed behavior), when a dispatch
throw forced a retry against the embedded baseline, or when the
`SessionStart` doctor check itself failed and fell back to silence.

```json
{"timestamp":"2026-08-17T08:57:04.656Z","kind":"policy-warning","message":"overlay policy rejected — falling back to the embedded baseline: Failed to parse toml"}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601. |
| `kind` | string | Always `"policy-warning"`. |
| `message` | string | Free-form — the same rejection reason `bouncer rules lint` prints, a dispatch-retry message, or a doctor-check-failure message. |

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

## `CLAUDE_CONFIG_DIR`

Read directly from the environment on every invocation. A leading `~` is
expanded against the real home directory; a trailing slash is
normalized. Unset or empty falls back to `~/.claude`.

---
Source: src/adapter/log.ts, src/adapter/log-path.ts
