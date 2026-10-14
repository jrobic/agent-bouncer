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
every `flag` from `UserPromptSubmit` or a `PostToolUseFailure` name-only
alert, and every `redact` from the successful post-tool event (ADR-0008) —
including `observe`, which never reaches the model and never appears on
stdout (see `docs/reference/cli.md`'s `run` section). A clean, unremarkable
tool call produces no line at all; neither does a tool output with no
protected value in it.
```json
{"timestamp":"2026-08-17T08:56:56.332Z","harness":"claude-code","session_id":null,"tool_name":"Bash","family":"command","verdict":"block","rule_id":"rm-rf-dangerous","target":"rm -rf /","build":"56b1e5a","policy":"0123456789ab"}
```

A harness whose `[harness.protocol.input]` declares an optional
`permission` selector (review round 1 P-4 — Codex's own `permission_mode`
is the only one today) adds a `permission` field carrying that value
verbatim, whenever the envelope actually sent one:

```json
{"timestamp":"2026-09-08T20:00:00.000Z","harness":"codex","session_id":"01a...","tool_name":"Bash","permission":"bypassPermissions","family":"command","verdict":"block","rule_id":"rm-rf-dangerous","target":"rm -rf /","build":"56b1e5a","policy":"0123456789ab"}
```

A post-tool redaction (ADR-0008): the tool's output carried the value of a
protected environment variable and reached the model with it replaced by
`[redacted: NAME]`. The output itself is never logged — `target` is the fixed
`(tool output)`, and `env_vars` names the variables. This keeps the 1.10.0
verdict-entry shape; no `reason` field is written:

```json
{"timestamp":"2026-10-13T16:24:59.069Z","harness":"claude-code","session_id":"01a...","tool_name":"Bash","family":"write-secret","verdict":"redact","rule_id":"env-value","target":"(tool output)","build":"56b1e5a","policy":"0123456789ab","env_vars":["FAKE_API_TOKEN"]}
```

A failed-tool alert (ADR-0008 § 9) may add context but cannot replace the
original failure output. It writes `verdict: "flag"` and fixed
`target: "(failed tool output)"`; `env_vars` carries names only. The alert
uses the existing verdict-entry fields and adds no alert-specific field:

```json
{"timestamp":"2026-10-14T09:00:00.000Z","harness":"claude-code","session_id":"01a...","tool_name":"Bash","family":"write-secret","verdict":"flag","rule_id":"env-value","target":"(failed tool output)","build":"source","policy":"0123456789ab","env_vars":["FAKE_API_TOKEN"]}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601, set when the line is written. |
| `harness` | string | The target harness's own declaration id (e.g. `"claude-code"`). When replay is available, `audit` replays it only under the selected harness; a differing id remains `(as logged)`. |
| `session_id` | string \| null | From the hook envelope; `null` when absent. |
| `tool_name` | string \| null | From the hook envelope; `null` when absent. |
| `permission` | string | OPTIONAL — only present when the harness declares `input.permission` AND the envelope sent a value for it. Logged verbatim, never read for a decision anywhere in this codebase. |
| `family` | string | `"command"` \| `"secret"` \| `"mcp-write"` \| `"write-secret"` \| `"protected-write"` \| `"prompt"`. |
| `verdict` | string | `"block"` \| `"confirm"` \| `"observe"` \| `"flag"` \| `"redact"` (`flag` is advisory, not a rewrite; a PostToolUseFailure `flag` may add context or be logged only). |
| `rule_id` | string | The id of the rule (or engine algorithm name, e.g. `rm-rf-dangerous`) that fired. |
| `target` | string | The command/path/URL/prompt text the rule matched against, capped at 4,096 characters (`...` appended when cut). A `redact` entry always uses `(tool output)`; a PostToolUseFailure `flag` always uses `(failed tool output)`. |
| `target_truncated` | boolean | OPTIONAL — `true` only when `target` was cut. Entries before 1.4.0 carry no marker; their legacy cut shape is a 200-character target ending in `...`. |
| `env_vars` | array of string | OPTIONAL — on an env-value `write-secret` entry, the protected variable names whose value the written text carries, in environment order; on a `redact` entry, names whose values the successful tool output carried, in first-found order; on a PostToolUseFailure `flag`, names whose values the complete error carried, in first-found order. These verdicts never store those values in another field. An env-value `target` path that carries a value is `(path withheld: …)`. Other rules still log `target` verbatim, so a blocked Bash command carrying a literal value is logged in clear. See `docs/reference/policy.md`'s env-value row. |
| `build` | string | `"source"` for source execution; otherwise the short SHA with `-dirty` when the build tree was dirty. |
| `policy` | string | First 12 hexadecimal characters of the SHA-256 digest of the effective policy that produced this verdict. |

Entries that predate build provenance have neither `build` nor `policy`;
`audit`, `audit --diff`, and `audit --suggest` ignore both fields, so mixed
logs remain readable. An entry without `harness` predates ADR-0006 and is
replayed as the selected harness. Entries written before 1.4.0 have no
`target_truncated`; a 200-character `target` ending in `...` is their legacy
truncation signature and remains `(as logged)` during replay. An `env-value`
entry (and its `env_vars` field) is read by `audit`, `audit --diff` and replay
like any other verdict line — the unknown field is ignored — and replay leaves
it `(as logged)` as a `write-secret` entry: the written text was never logged,
so it cannot be re-judged. A `redact` entry is the same: `audit` counts it as no
friction, `audit --diff` as a silent verdict, replay leaves it `(as logged)`.
A PostToolUseFailure `flag` records a fixed target and variable names only;
the original error is not retained in the log, so replay cannot re-judge it.

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
dispatch throw forced a retry against the embedded baseline, one when a
post-tool check failed and the output was withheld (ADR-0008), one when a
failed-output alert check failed and the notice was omitted (ADR-0008 § 9),
one when the `SessionStart` doctor check itself failed and fell back to
silence, or one when `run` was invoked with an unknown or protocol-less
`--harness <id>` (ADR-0006 § 6 — logged only when a log path can be resolved
for it, which an UNDECLARED id cannot).

Failed-output alert warnings use only these fixed messages; they never contain
an exception message:

- `post-tool failure alert check failed, retrying with the embedded baseline`
- `post-tool failure alert check failed`
- `post-tool failure alert render failed`

```json
{"timestamp":"2026-08-17T08:57:04.656Z","harness":"claude-code","kind":"policy-warning","message":"profile layer rejected — policy.d/20-broken.toml: Failed to parse toml"}
```

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | ISO 8601. |
| `harness` | string | The target harness's own declaration id. |
| `kind` | string | Always `"policy-warning"`. |
| `message` | string | Free-form — the same rejection reason `bouncer rules lint` prints, a dispatch-retry message, a doctor-check-failure message, a post-tool check failure (`post-tool check failed, output withheld: …`, ADR-0008), a failed-output alert check/retry/render failure (the fixed messages above, ADR-0008 § 9), or the unknown/protocol-less-harness message. General dispatch-retry and post-tool warning messages are scrubbed when their exception text carries a protected value. Failed-output alert warnings never use exception text, so neither the error text nor its values enter this field. |

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
Source: src/adapter/log.ts, src/adapter/log-path.ts, src/build-info.ts, src/policy/digest.ts, src/policy/load.ts, src/policy/schema.ts
