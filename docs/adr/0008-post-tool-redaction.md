# ADR-0008: Post-tool redaction — a post-tool event in the adapter model

**Date**: 2026-10-13
**Status**: Accepted
**Deciders**: Jonathan Robic

## Context

### Current situation

Tickets 57 and 58 (ADR-0007) refuse the commands that print a protected
environment variable and the writes that carry its value. Neither can stop a
value that already sits in a tool result: a test that prints `process.env`, a
log line, a configuration file the agent legitimately read. Once the value is in
a tool result it is in the agent's context, in the transcript, and in anything
the model says next.

ADR-0006 gave every harness one generic adapter driven by a declaration:
transport → input map → event names → tools map → engine → output table →
template. It judges three events — `pre_tool`, `prompt`, `session_start` — and
a well-formed envelope naming any other event is silent. Its templates take
JSON-encoded **string** placeholders (`${reason}`, `${context}`, `${rule}`,
`${verdict}`, § 3).

### Measured facts (ticket 59, Scope 0, 2026-10-13)

A local fake model server stood in for the model API. The request body a
harness sends is what the model sees, and every verdict below is read from it.
The harnesses ran under a temporary `HOME` and temporary config dirs, with a
made-up variable. The handlers were stand-ins doing the replacement in-process
(evidence: ticket 59's report).

1. **Claude Code 2.1.296.** A `PostToolUse` command hook with no matcher
   answering `hookSpecificOutput.updatedToolOutput` replaces what the model sees
   for Bash, Read, Grep and an MCP tool. The on-disk transcript then holds the
   replaced output, and it also records the hook's own stdout (an `attachment`,
   `hook_success`).
   - The rewrite must keep the tool's own output shape: Bash `{stdout, stderr,
     interrupted, isImage, noOutputExpected}`, Read `{type: "text", file:
     {filePath, content, …}}`, Grep `{mode, numFiles, filenames, content, …}`,
     MCP an array of content blocks. A built-in tool given a value of another
     shape **ignores it and shows the original**; MCP output is not validated.
   - A tool that **fails** (a non-zero Bash exit included) fires
     `PostToolUseFailure` only, which has no replacement field: its output
     reaches the model.
   - When the hook process itself fails — exit 1, exit 2, non-JSON stdout,
     timeout, missing binary — the original reaches the model every time.
   - A Bash output above ~30 KB is saved in full, unredacted, to
     `<config>/projects/<slug>/<session>/tool-results/<id>.txt` before the hook
     runs. The hook receives the first ~30 KB; the model gets a 2 KB preview of
     the rewritten output and the file path.
2. **omp 18.10.3 and pi 0.84.1.** A `tool_result` extension handler returning
   `{ content }` replaces what the model sees for every tool tested (bash,
   read, grep, an extension tool, MCP — omp natively, at top level or through
   `write xd://<tool>`, pi through `pi-mcp-adapter`), **failed tools
   included** (`isError: true`).
   - A handler that **throws** is logged by the harness, and the original
     content is kept.
   - `details` never reaches the model but is written to the session file.
   - Large outputs are truncated by the harness before the event (~50 KB of
     content).
   - omp's `xd://` route fires `tool_result` twice: once for the inner MCP tool,
     then for the outer `write`.
3. **Cost.** One `bouncer run` spawn costs ~20 ms wall time (p50) on the
   measuring machine, and a full pre-tool decision costs 24 ms p50 / 26–28 ms
   p95.

### Problem

Add the one hook that removes a protected value from what the model is shown,
whatever printed it (decision F2, "1b"), on every harness whose protocol allows
it, without giving the in-process shim policy and without opening a fail-open
path that lint cannot see.

### Constraints

- **Bouncer judges alone** (doctrine 2026-09-04; ADR-0006 § 7). The shim
  forwards and returns; it knows no name, value or pattern.
- **One definition of a protected value**: ticket 58's detector, i.e. the
  protected-name suffix list, the 8-character floor, and the plain, base64 and
  hex forms. A value never leaves the detector's closure, never becomes a
  `RegExp`, and never appears in a message.
- **Shape or nothing**: under Claude Code a rewrite that breaks the built-in
  tool's shape is ignored, so it fails open.
- **Latency**: p95 ≤ 50 ms per tool result on both harnesses (decision F4).

## Decision

### 1. The declaration gains an optional post-tool event

```toml
[harness.protocol.input]
response = "tool_response"     # claude-code; "content" for pi-agent

[harness.protocol.events]
post_tool = "PostToolUse"      # claude-code; "tool_result" for pi-agent

[harness.protocol.output.redact]
stdout = '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":${response}}}'
# pi-agent: stdout = '{"content":${response}}'
```

`events.post_tool` names the event. `input.response` is the selector of the
tool's own result in the envelope. `output.redact` is the template rendered
when the response is rewritten. A harness that declares no `post_tool` is never
reached (ADR-0006 § 3: an unjudged event stays silent). Codex declares none:
whether it can replace a result is unmeasured.

### 2. `${response}` is a structured placeholder

ADR-0006 § 3's placeholders are JSON-encoded strings. `${response}` is the
**JSON encoding of a JSON value**: the rewritten response, of whatever type the
envelope carried (an object for Claude Code's built-ins, an array for MCP and
for pi/omp `content`). The renderer has one rule for every placeholder,
`JSON.stringify(value)`; for the string placeholders it yields what § 3 always
said. No codec is needed: the rewrite is not harness knowledge but a walk of the
value the selector returned (§ 4).

### 3. Fail-closed by lint (§ 4 style)

`rules lint` rejects the protocol block as a unit when:

- `events.post_tool` is declared without `input.response`, or `input.response`
  without `events.post_tool` (a dead selector). This is the lockstep pattern of
  `prompt`.
- `events.post_tool` is declared without an `output.redact` template, or
  `output.redact` exists without `events.post_tool` (a dead template).
- the `redact` template does not set `stdout`, does not carry `${response}`,
  names any other placeholder, or sets `exit`. An answer that drops the
  response, or that exits instead of answering, would show the original.
- `events.post_tool` equals another declared event name. That would route a
  pre-tool call to the post-tool branch, so it would never be judged.

### 4. What is replaced, and how

Each occurrence of the value of a protected variable — ticket 58's forms: plain,
base64 (standard and URL-safe, three alignments), hex (lower and upper) — is
replaced by `[redacted: NAME]` (decision F2).

- **Walk the received value, keep its shape.** Every key, array position and
  non-string value is kept; replacement happens inside string leaves only.
- **Images are forwarded and returned untouched** (decision H5). An object
  whose `type` is `"image"` — an image content block, a Claude Code Read
  image's `{type, file: {base64, …}}` — is not text: it travels to bouncer
  with the rest of the response (neither the shim nor the hook entry knows
  a shape to strip) and is never matched. It is printed back, as received,
  only when a text leaf of the same response carried a value; otherwise the
  answer is silence. Its cost is bounded, not measured: under omp and pi the
  shim reads up to 64 MiB of answer (`maxBuffer`, above Node's 1 MiB
  default), and an answer above that is a spawn failure, i.e. the withheld
  answer (§ 6). The latency sample of § 7 holds no image result.
- **Decoded leaves.** The walk runs over the parsed envelope, so a value
  containing `"`, `\` or a newline is matched as the environment holds it, not
  as JSON escapes it.
- **One pass, longest first.** All occurrences of all needles are located in the
  original leaf.
  - Longer needles take precedence. An occurrence contained in an
    already-kept one is dropped. Occurrences that partially overlap are merged
    into one span that names every variable involved (`[redacted: A, B]`), so no
    tail of a value stays in clear.
  - Two variables with the same value are named once, by the name that sorts
    first.
  - Markers are spliced in a single pass over the original text and are never
    re-scanned: a marker cannot be matched again by a later needle.
- **A base64 needle is the inner run of an encoded value** (ticket 58's
  three alignments): the characters that carry only the value's bits. Its
  occurrence is widened over the encoded value's PARTIAL edges only — one
  character on a side where the value's bits share a character with a
  neighbour's (an alignment other than 0 on the left; a length that does
  not close a group on the right), then, after a partial last character,
  its padding. A complete edge is never widened, so a neighbour from the
  base64 alphabet (`/`, `_`, `-`, a letter) stays. A standalone encoding is
  replaced whole, padding included; inside a longer base64 stream exactly
  the characters that carry a bit of the value go, which breaks the stream.
  That is on purpose: the stream carried the value. (A needle text that two
  alignments of one value share takes the partial edges of both.)
- **Nothing found → silent**: no output, no rewrite, the response is shown as
  the harness has it. This is the common case.

### 5. Policy: one switch (decisions H3 and H6)

Post-tool redaction is the env-value row's second use: baseline row
`env-value` (`policy/write-secret.toml`, `special = "env_value"`) governs both.
`[[override]]` `disable` **or** `relax` on that row turns redaction off as well.
A relaxed row means the operator chose not to be stopped by the guard, and a
softer post-tool verdict has no meaning.

`replace` governs **writes only** (decision H6). The row's `regex` / `except`
gate which written texts the guard looks at; redaction ignores them and always
scans the whole output. It reads nothing of the row but its presence, its
relax and its id (the audit entry's `rule_id`). Reason: an override written for
the write guard — narrowing which texts block a write — must not silently
narrow what is hidden from the model. Everything else in the policy is
irrelevant here.

### 6. Failure: in-process only under Claude Code (decisions F5 and H1)

- **Bouncer.** Two failure points, two paths, never silence:
  - Building the guard (reading the environment) or walking the response
    goes through the shared retry — the current policy, then the embedded
    baseline, over the same environment record. If both fail, bouncer
    answers with **the withheld answer** below.
  - Rendering an answer goes straight to the withheld answer: a baseline
    retry would render through the same template.

  The withheld answer is the response in its own shape with every string
  leaf that could hold a value replaced by `bouncer: post-tool check failed
  — output withheld`. Kept as received: leaves under a `type` key
  (discriminators), image objects, and strings shorter than the env-value
  floor (8 characters — no value fits in fewer, in any form), where enum
  leaves such as Grep's `mode: "content"` live. If the withheld answer
  cannot be rendered either, the process exits 2 with one stderr line: the
  shim withholds on any non-zero exit, and Claude Code shows the original
  (the limit below). Each failure is logged as a policy-warning whose error
  text is withheld when it carries a value.
- **The shim (omp / pi).** Bouncer missing, timing out, exiting non-zero, or
  writing stdout that is not a JSON object carrying a `content` array → `{
  content: [{ type: "text", text: "bouncer: post-tool check failed — output
  withheld" }] }`. Empty stdout → `undefined` (nothing to redact). The handler
  catches everything: a throwing handler would leave the original in place
  (measured on both binaries).
- **Claude Code** gives a command hook no way to replace a failed tool's output.
  The original remains in the model context. Any failure of the hook process
  also leaves the original and omits the notice. Both are documented limits,
  not bugs; § 9 adds a name-only alert but does not redact the failed output.
- **A withheld answer under Claude Code can still be ignored.** Measured
  with the real withheld answer (Claude Code 2.1.296, review round 1): Bash,
  Read (its `filePath` withheld) and Grep in `content` mode accept it — the
  model sees the withheld text, never the value. Grep's default mode does
  not: its `mode: "files_with_matches"` leaf is longer than the floor, is
  withheld, fails the tool's schema, and Claude Code shows the original (a
  list of file names). `[inference]` Any built-in tool whose schema
  constrains a string leaf of eight characters or more behaves the same —
  measured for Grep only. Same residual as above.

### 7. All tools, one spawn per result (decisions F6 and F4, option A)

There is no tool allow-list: any result can carry a protected value, including
one from a future tool or MCP integration. Only a matcher intended to cover
all tools is acceptable; enumerating today's tool names would leave later
tools unredacted.

- **Claude Code**: one `PostToolUse` entry with no matcher. `doctor` reports a
  missing entry, or a matcher that does not cover every tool, as `[fail]
  wiring:PostToolUse`. The SessionStart notice lists it like every other
  `wiring:*` failure, with no new tier (decision H2).
- **omp / pi**: the shim relays every `tool_result` to `bouncer run --harness
  pi-agent` through the same blocking `spawnSync` as `tool_call`. ADR-0006
  § 7's fixed rules gain the post-tool rule of § 6.
- **The budget is p95 ≤ 50 ms per tool result**, measured by ticket 59 on both
  harnesses through the real shim and a real hook.

### 8. Audit log

Each post-tool redaction writes one verdict entry:

- `family: "write-secret"`, `rule_id: "env-value"` (the row of § 5),
  `verdict: "redact"` (a new verdict kind, see below);
- `tool_name` from the envelope, `target: "(tool output)"`;
- `env_vars`: the **names**, never a value. The log never held output text.

`--shadow` logs the same entry and prints nothing.

`redact` is a new verdict kind rather than a reuse:

- `block` would claim the call was stopped, and `observe` that nothing changed;
  both would mislead an audit.
- `audit` counts `redact` as no friction, `audit --diff` as a silent verdict.
- Replay leaves it `(as logged)`: it is a `write-secret` entry, and the output
  was never logged, so it cannot be re-judged.

### Alternatives considered

- **Option B — Bouncer hands the shim the protected-name regex at
  `session_start`; the shim redacts in-process through `process.env`.** Zero
  spawns per result, but it gives the shim policy (names, forms, matching), the
  exact thing ADR-0006 § 7 forbids, and a second implementation of ticket 58's
  detector to keep in lockstep. **Trigger to reopen:** the measured p95 per tool
  result exceeds 50 ms on either harness. It then needs an amendment to this ADR
  decided with the operator, never a silent change.
- **A per-tool rewriter** (a codec reached by name, ADR-0006 § 6) that knows
  Bash, Read, Grep, … shapes. It would duplicate Claude Code's schemas, drift
  with every release, and still not cover MCP. The shape-preserving walk needs
  no tool knowledge.
- **Match on the raw stdin text.** Escapes in JSON hide values containing `"`,
  `\` or newlines. Rejected (§ 4).
- **Use `decision: "block"` or `additionalContext` as a substitute for rewriting a tool result under Claude Code.** Both leave the original output in front of the model (hooks reference). Rejected as redaction; § 9 uses `additionalContext` only as an advisory failure alert.
- **Rewrite `details` too (omp / pi).** `details` never reaches the model; it
  doubles the payload (pi's bash `details.truncation` repeats the content) and
  its shape is per tool. Rejected; the on-disk residue is a limit (decision
  H4).

## Consequences

### Positive

- A protected value printed by any tool on the success path never reaches the
  model under Claude Code, omp or pi, nor their transcripts' tool-result entries.
- Under omp and pi it also covers failed tools, and every failure of the check
  withholds the output.
- One detector and one policy switch for both directions (writes and outputs).
- The adapter model gains a post-tool event without a codec; a future harness
  with a rewritable post-tool event is a declaration, not code.

### Negative

- One more process per tool call under Claude Code (`PreToolUse` and
  `PostToolUse`), and one more blocking spawn per result under omp and pi
  (two per omp `xd://` MCP call).
- Every install must act: add the `PostToolUse` entry to Claude Code's
  `settings.json`, and reprint the shim in the default omp/pi agent dir and in
  every omp profile (`wiring:shim` is `[fail]` until then).

### Limits (recorded, not fixed)

- **The tool already ran.** Network exfiltration, a file already written and a
  command already executed are not prevented; only the agent's context is
  protected. Claude Code's telemetry (OpenTelemetry tool spans, analytics)
  captures the original output before the hook runs.
- **Claude Code's failure path** (§ 6): a failed tool's output and any failure
  of the hook process reach the model unredacted.
- **On-disk residue** (decision H4): Claude Code's `tool-results/*.txt` for
  large outputs, omp's session artifacts (`0.bash.log`), and omp/pi `details`
  in session files keep the original. They are outside the `session-transcripts`
  row. Reading them back through a tool is redacted again.
- **`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`** strips the variables from the hook
  too, which then knows no value: a file holding one reaches the model
  unredacted (measured).
- **Only variables present in the hook's (or the shim-spawned process's)
  environment are known.**
- **Split or transformed values** — concatenated, reversed, ROT13, re-encoded,
  a different base64 alignment, a hash — evade, as for ticket 58.
- **Images** and other non-text content are not matched (decision H5).

## References

- ADR-0006 § 3 (declaration, placeholders), § 4 (lint), § 6 (codecs), § 7 (shim)
- ADR-0007 (environment secrets net), ticket 58 (`src/env-value-rules.ts`)
- Claude Code hooks reference: PostToolUse, PostToolUse decision control,
  PostToolUseFailure — https://code.claude.com/docs/en/hooks (checked
  2026-10-13)
- `@earendil-works/pi-coding-agent` 0.84.1 `dist/core/extensions/types.d.ts`
  (`tool_result`, `ToolResultEventResult`)
- Ticket 59 and its report (Scope 0 measurements, latency acceptance)

---

## History

| Date | Action | By |
|---|---|---|
| 2026-10-13 | Created, Accepted (ticket 59, decisions F2–F6 and H1–H6). | Jonathan Robic |
| 2026-10-14 | Added the Claude Code `PostToolUseFailure` name-only alert and its `error`/`failure_context` protocol fields. | Jonathan Robic |

## 9. Amendment — Claude Code failed-tool name-only alert (2026-10-14)

### Decision

Claude Code declares the optional `events.post_tool_failure =
"PostToolUseFailure"`, `input.error = "error"` and
`[harness.protocol.output.failure_context]` template. Lint requires the event,
selector and template in lockstep, rejects a dead selector or template, and
rejects an event name shared with another declared event. No other harness
declares this event.

The failure alert scans the complete `error` with the shared env-value
scanner: plain, base64 and hex forms. `disable` and `relax` turn it off;
`replace` remains write-only and cannot narrow the scan. A match is logged as
a `write-secret` `flag` verdict with the effective env-value row id, tool
name, fixed target `(failed tool output)`, and protected variable names only.
The error text and every value spelling stay out of the log.

The verdict chooses the action; the event chooses the rendering template.
`output.flag = "silent"` records the hit but returns no context.
`output.flag = "context"` renders `failure_context`, not the
`UserPromptSubmit` context template. `--shadow` logs without rendering.
A clean error is silent. With one matching variable, the notice is:

> bouncer: the failed tool output above contains the value of NAME, a protected environment variable. Do not repeat, store or send it; reference the variable by name.

With several matching variables, the notice is:

> bouncer: the failed tool output above contains the values of A, B, protected environment variables. Do not repeat, store or send them; reference the variables by name.

The failed output itself cannot be replaced: it already reaches the model and
remains visible in Claude Code's context and transcript. An in-process scan or
render failure therefore stays silent rather than pretending to withhold the
output. The scan runs through `withPolicyLikeRun` and retries against the
embedded baseline; audit entries use the effective loaded policy. Failure
warnings are fixed strings documented in `docs/reference/audit-log.md`; no
exception message is logged.

`doctor` requires a `PostToolUseFailure` command hook with no matcher. A
missing or partial entry is `[fail] wiring:PostToolUseFailure` and includes
the entry to paste; `SessionStart` reports it through the existing wiring
notice.

### Consequences

- The alert makes a failed-output value visible by variable name without
  placing the value or the failed output in Bouncer's audit log.
- The alert costs one additional Bouncer spawn per failed Claude Code tool
  call. Measured live on 2026-10-14 with Claude Code 2.1.299: 80 failed-tool
  calls, p95 24.71 ms nearest-rank.
- The event is advisory. The tool already ran, and the original failure
  output remains visible; a missing or failed hook cannot prevent that leak.
