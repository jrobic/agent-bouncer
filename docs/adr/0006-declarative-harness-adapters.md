# ADR-0006: One generic adapter, driven by a harness declaration file

**Date**: 2026-09-07
**Status**: Accepted
**Deciders**: Jonathan Robic

## Context

### Current situation

`bouncer` is wired into one assistant. The engine (`src/*.ts`) emits abstract
verdicts (`block | confirm | observe | flag`) and consumes a narrow
`GuardedToolCall`, as the spec required. Everything between the process
boundary and the engine, however, is written for Claude Code:

- `src/adapter/protocol.ts` is the Claude Code envelope (`hook_event_name`,
  `tool_name`, `tool_input`, `session_id`).
- `src/adapter/dispatch.ts` keys on Claude Code tool names and field names
  (`Read.file_path`, `Write.content`, `MultiEdit.edits[].new_string`,
  `Grep.path`, `Glob.pattern`, the `mcp__` prefix), and `src/targets.ts`
  does the same for `Bash.command` and the context-mode `ctx_*` tools.
- `src/adapter/degradation.ts` is the Claude Code degradation table
  (`confirm → ask`), `envelopes.ts` the Claude Code stdout shapes,
  `doctor.ts` the `settings.json` wiring check, `log-path.ts` the
  `CLAUDE_CONFIG_DIR` routing.

ADR-0005 gave the policy a `[[harness]]` table that names six assistants by
their configuration directory, their environment variable and their
persistent files. That table protects those directories from writes; it
does not describe how any of them talks to a hook.

Facts measured on the installed binary on 2026-09-07, all feeding the decision:

1. **omp 18.1.10 does not run the Claude Code hook.** In an omp session, a
   `confirm`-class command (`git branch -D no-such-branch-zzz`) ran with no
   prompt and no audit-log entry in either profile; an `observe`-class one
   (`git reflog show -n 1`) left no entry either, while the same envelope
   through `bouncer run` logs it. omp's `claude` discovery provider loads
   `hooks/pre/*.ts` factories, not the `command` hooks of `settings.json`.
   The primary assistant was unguarded.
2. **Codex CLI 0.153.2 has stable hooks with a Claude-Code-shaped
   envelope.** `codex features list` reports `hooks stable true`. The hook
   reads stdin JSON with `session_id`, `hook_event_name`, `tool_name`,
   `tool_input`, `tool_use_id`, and answers with
   `hookSpecificOutput.permissionDecision: "deny"` or exit code 2 plus
   stderr. `UserPromptSubmit` and `SessionStart` take `additionalContext`
   in the same shape. Wiring lives in `~/.codex/hooks.json` or a `[hooks]`
   table of `config.toml`; a hook definition must be trusted by hash
   (`/hooks`) before it runs, and an untrusted hook is skipped.
   `~/.codex/hooks.json.backup` (2026-08-15) shows the previous TypeScript
   guards wired there with the Claude Code matchers.
3. **On Codex, `permissionDecision: "ask"` is fail-open.** The hooks
   reference states it is "parsed but not supported yet. Codex marks the
   hook run as failed, reports the error, and continues the tool call". A
   `bouncer run` wired under Codex with the Claude Code table would let
   every `confirm` verdict through.
4. **Codex has no `Read`/`Edit`/`Write` tools.** Edits arrive as
   `tool_name: "apply_patch"` with `tool_input.command` holding the patch
   text; reads go through Bash. Matching the file families needs a patch
   parser, not a field name.
5. **pi-agent 0.84.1 and omp share one extension API.** omp is a layer on
   pi-agent (the relation of oh-my-zsh to zsh). Both intercept tools in
   process: `pi.on("tool_call", …)` returning `{ block, reason }`, with
   `ctx.ui.confirm` available when a UI is attached and `confirm`
   returning `false` without one. There is no stdin envelope; a guard
   binary is reached only through an extension. opencode 1.18.5 is the
   same kind of surface (`tool.execute.before`, `throw` to block, no ask).

### Problem

Ticket 15 asked for "the second adapter and the shape that makes N
adapters sustainable". Coding one adapter module per assistant answers the
first half and makes the second a release per assistant: every new
harness is a TypeScript change, a review, a rebuild, and a user who runs a
harness the maintainer does not know cannot try it at all. The `[[harness]]`
table already proved the other shape works for directories: one block per
assistant, the rows derived, overlays merging by `id`.

### Constraints carried over

- Bouncer judges alone (doctrine 2026-09-04): no decision may rest on the
  target harness's classifier, permission mode or sandbox. Fact 3 is the
  concrete form of this constraint: an adapter must know what the harness
  does with each answer it can give.
- Fail-closed degradation (spec § core/adapter split, story 20): a harness
  without an interactive confirm degrades `confirm` to `block`, by
  contract, never by accident.
- No second adapter ships before a dedicated test phase (doctrine
  2026-08-16). A declaration is an adapter.
- Overlay semantics are ADR-0001's: an invalid block is rejected as a unit,
  the baseline stands alone, and everything the baseline does not know
  must still degrade to a correct baseline.
- The golden fixtures are the conformance contract. The Claude Code
  behaviour of the installed binary (`253b06d`) must not change while the
  seam is extracted.

## Decision

1. **One adapter, generic.** `src/adapter/` becomes a pipeline that reads
   a harness declaration and applies it: transport reads stdin, an input
   map extracts event, tool, input, session and prompt, a tools map turns
   the call into a neutral call, the engine judges it, an output table
   turns the verdict into an action, and the action's template goes to
   stdout or the exit code. Nothing in `src/adapter/` or `src/targets.ts`
   names a harness, a tool name or a field name any more. The only code
   that knows a harness is a **codec** (§ 6), and a codec is reached by
   name from a declaration.

2. **One file per assistant.** The `[[harness]]` block of ADR-0005 moves
   from `policy/harness.toml` to `policy/harness/<id>.toml` (baseline,
   embedded at compile time like every other policy file) and gains a
   `[harness.protocol]` table. Overlays declare or extend a harness in
   `harness.d/<id>.toml` under either layer of ADR-0001 (common
   `~/.agents/bouncer/`, profile `<configDir>/bouncer/`). Merge is by `id`
   as in ADR-0005; an `id` unknown to the baseline is a **new harness**,
   accepted, and announced everywhere an override is (§ 5). The `omp`
   block is renamed `pi-agent` (the file name is the id; derived row ids
   follow: `pi-agent-config-dir`, `pi-agent-config`, `pi-agent-models`,
   `pi-agent-extensions`).

3. **The declaration.** Claude Code, written so that it reproduces today's
   binary:

   ```toml
   [harness.protocol]
   transport = "stdin-json"
   wiring    = "hook-file"          # doctor: a JSON hook file naming the events

   [harness.protocol.input]
   event   = "hook_event_name"
   tool    = "tool_name"
   input   = "tool_input"
   session = "session_id"
   prompt  = "prompt"
   cwd     = "cwd"

   [harness.protocol.events]
   pre_tool      = "PreToolUse"
   prompt        = "UserPromptSubmit"
   session_start = "SessionStart"

   [harness.protocol.tools]                  # name → role + field selectors
   Bash         = { role = "command", command = "command" }
   Read         = { role = "read",    path = "file_path" }
   Grep         = { role = "read",    path = "path" }
   Glob         = { role = "read",    path = "path", pattern = "pattern" }
   Write        = { role = "write",   path = "file_path", text = "content" }
   Edit         = { role = "write",   path = "file_path", text = "new_string" }
   MultiEdit    = { role = "write",   path = "file_path", text = "edits[].new_string" }
   NotebookEdit = { role = "write",   path = "notebook_path" }
   "mcp__plugin_context-mode_context-mode__ctx_execute"         = { role = "command", command = "code" }
   "mcp__plugin_context-mode_context-mode__ctx_execute_file"    = { role = "command", command = "code", path = "path" }
   "mcp__plugin_context-mode_context-mode__ctx_batch_execute"   = { role = "command", command = "commands[].command" }
   "mcp__plugin_context-mode_context-mode__ctx_index"           = { role = "read",    path = "path" }
   "mcp__plugin_context-mode_context-mode__ctx_fetch_and_index" = { role = "fetch",   url = "url", urls = "requests[].url" }
   "mcp__*"     = { role = "mcp" }

   [harness.protocol.output]
   block = "deny"
   confirm = "ask"
   observe = "silent"
   flag = "context"
   on_malformed = "allow"
   ask_probe = "2026-08-16, Claude Code (version unrecorded): an unanswerable ask under --dangerously-skip-permissions is enforced as deny"

   [harness.protocol.output.deny]
   stdout = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":${reason}}}'
   [harness.protocol.output.ask]
   stdout = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":${reason}}}'
   [harness.protocol.output.context]
   stdout = '{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":${context}}}'
   [harness.protocol.output.session_start]
   stdout = '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":${context}}}'
   ```

   Roles are the engine's whole vocabulary of a tool call: `command`
   (strings judged by the command and secret families), `read` (paths
   judged by the secret family; `pattern` is matched literally, `path`
   after canonicalisation), `write` (paths judged by secret and
   protected-write, `text` scanned by write-secret), `fetch` (urls),
   `mcp` (the name judged by mcp-write, for any name not claimed by an
   explicit row). A selector is a dotted path into the input; `[]` maps
   over an array, and an array element that is itself a string is taken as
   the value (`ctx_batch_execute` mixes both). A relative `path` is
   resolved against the envelope's `cwd` before canonicalisation (Claude
   Code sends absolute paths; Codex patches are relative to the session
   directory). A name that matches no row is not judged, as today. Exact
   rows win over glob rows.

   Placeholders in templates are JSON-encoded strings: `${reason}` is
   `<ruleId>: <reason>`, `${context}` the assembled context text,
   `${rule}` and `${verdict}` the raw fields. One exception, ADR-0008's
   `${response}` (the post-tool `redact` template): the JSON encoding of a
   structured value, not of a string. A template may set `exit` instead
   of, or with, `stdout`.

4. **Output table, fail-closed by lint.** Each abstract verdict maps to one
   action: `deny`, `ask`, `context`, `silent`. `rules lint` rejects the
   block as a unit when `block` maps to anything but `deny`; when
   `confirm` maps to anything but `deny` or `ask`; when `observe` is not
   `silent`; when `flag` is not `context` or `silent`; when `ask` is used
   without a non-empty `ask_probe` (the written measured fact, in the
   same spirit as `reason` on a rule: lint cannot verify that a harness
   honours `ask`, so it forces the author to say on what evidence they
   believe it does); when an overlay moves a **baseline** harness's
   `confirm` from `deny` to `ask` (a baseline `deny` is a measured fact,
   fact 3 for Codex); when a codec, transport or wiring name is unknown.
   The verdict chooses the action; the routed event chooses its context
   template (`context` for `UserPromptSubmit`, `failure_context` for
   `PostToolUseFailure`). Thus `flag = "silent"` logs without rendering,
   and `flag = "context"` renders the template for that event.
   `on_malformed` is `allow` or `deny`; Claude Code keeps `allow`, the
   spec's fail-open-on-bad-envelope contract, and every other baseline
   harness decides it in its test phase.

5. **Unknown harness is a hard stop, declared harness is announced.**
   `bouncer run --harness <id>` with an id no layer declares, or whose
   block was rejected, exits 2 with the reason on stderr and no stdout.
   Claude Code and Codex both document exit code 2 as a blocking error
   fed back to the model; shims (§ 7) treat any non-zero exit as block.
   This is the one fail-closed signal that needs no declaration. A harness
   declared or extended by an overlay is listed by `rules list`
   (`harness pi-agent overlay [common:harness.d/pi-agent.toml]`), named by
   `doctor`, and written in the audit-log header (story 19): possible,
   never silent.

6. **Codecs: the code a file names.** Three kinds, in a registry keyed by
   name, each a small module with its own tests:
   - transport — `stdin-json` (the only one today);
   - input codec on a tool row — `apply-patch` (fact 4: patch text to
     written paths and added lines), `hashline` (pi-agent's `edit` takes
     one patch string with `[PATH#TAG]` sections); a row with `codec` needs
     no field selectors;
   - wiring, for `doctor` — `hook-file` (generic: a JSON file whose events
     name a command containing `bouncer run --harness <id>`, given by
     `wiring.file` and `wiring.events`), `codex-hooks` (the same plus the
     `[hooks.state]` trust table of `config.toml`: an untrusted entry is a
     skipped hook, so an unguarded session, so a scream), and `shim-file`
     (the installed shim of § 7 exists and is byte-identical to the one the
     binary prints).
   A harness declared without `wiring` gets `wiring: not checkable
   (declared harness)` in `doctor`, visible rather than green. A new
   parser or a new wiring check is a codec pull request; a new assistant
   that fits existing codecs is a file.

7. **In-process harnesses: a dumb shim, printed by the binary.** For
   pi-agent, omp and opencode the harness never writes stdin; an extension
   does. The shim carries no policy: it serialises the harness's own event
   object as is (`{ toolName, input, sessionId }` for pi-agent), spawns
   `bouncer run --harness <id>`, and returns what bouncer writes on stdout
   as is. The declaration therefore describes the harness's event object
   on the input side and the harness's expected return object on the
   output side (`deny.stdout = '{"block":true,"reason":${reason}}'`), and
   the file stays the single place that knows both APIs. Fixed rules in
   every shim, never a per-harness choice. The canary enforces three:
   (1) bouncer missing, not executable, exiting non-zero or timing out →
   block; (2) empty stdout → allow; (3) an `ask` action → with a UI, a
   numbered one-key `ctx.ui.select` (`1. Allow` / `2. Block`, `initialIndex`
   1 so that Block is the default highlight where the harness honours it:
   `omp` does, `pi` 0.84.1 ignores it and opens on `1. Allow`; only the
   exact `1. Allow` allows — Esc, an abort, any other answer or a failing
   select block; no timeout), without one a block that opens nothing
   (ticket 55). (4) ADR-0008's post-tool rule (§ 6 there): a `tool_result`
   is relayed the same way; empty stdout → `undefined`, a `{ content }`
   answer → returned as is, any failure → the output withheld, never the
   original. Separately, a `session_start` action is delivered two ways,
   also fixed: `ctx.ui.notify` of the doctor context AND, once, on the
   session's FIRST `before_agent_start` turn, the same context as a
   delivered message — the first renders as a toast under `pi` and,
   measured 2026-10-13, as a `Warning:` line under `omp`'s own TUI; the
   second reaches the model's own context on BOTH binaries, and headless,
   where a toast never does (ticket 15c review round 1 S-2/P-4). Both are
   folded for display only (headline lines kept, indented detail lines
   counted); a message renderer expands the message with ctrl+o, and the
   model always gets the full text.
   `bouncer harness shim <id>` prints
   the shim source embedded with the binary; the documentation says where
   to write it (`<dir>/extensions/bouncer.ts` for pi-agent and omp,
   `~/.config/opencode/plugins/` for opencode). One protocol, two
   binaries for pi-agent: the test phase of its ticket runs the same shim,
   unmodified, under `pi` and under `omp`.

   The ask dialog's keys are measured per binary, not iso (ticket 55, live
   2026-10-11, re-run 2026-10-12): `omp` 18.9.1 selects instantly on a
   digit and honours `initialIndex` (a stray Enter blocks); `pi` 0.84.1
   honours neither (its first option, `1. Allow`, is always highlighted: a
   stray Enter allows, as with the former Yes/No `ctx.ui.confirm`).

   Beyond those rules — not one of them, and nothing the canary enforces —
   the shim emits `herdr:blocked` on the extension bus around the ask
   dialog's wait, UI only: `{ active: true, label: "bouncer: <reason>" }`
   before the dialog, `{ active: false }` in a `finally` that runs
   whenever the dialog settles. It is an observability signal, not policy
   (ticket 55): it gates nothing and changes no verdict, one guarded
   helper swallows a missing bus or a throwing `emit`, and it is always
   emitted — no `HERDR_*` sniffing. It exists because omp's own `ctx.ui`
   dialogs emit no bus event and Herdr's omp integration — herdr-managed,
   overwritten on reinstall — flips an agent to `blocked` only on
   `herdr:blocked`, native tool approvals and omp's own `ask` tool; a
   neutral `bouncer:ask` event plus a local bridge extension was rejected
   (one more unchecked file, outside `doctor`'s byte check, and a silent
   failure if it is missing). Measured live (2026-10-12): the `finally`
   runs on Esc, on Ctrl+C and, under `omp`, when the process receives
   SIGINT, SIGTERM or SIGHUP (omp settles the pending dialog while it
   shuts down); under `pi` 0.84.1 a signalled process exits with the
   dialog still pending, so nothing releases the signal, which dies with
   the process. Known limit: vibe-island listens to omp's
   `tool_approval_*` events, not to `herdr:blocked`, and stays blind to a
   Bouncer ask.

8. **Routing.** The `env` list of the block gives the account directory
   (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `PI_CODING_AGENT_DIR`), the
   `witness` its fallback. The profile layer is `<dir>/bouncer/` and the
   audit log `<dir>/logs/hooks/bouncer.log`, as today for Claude Code; the
   common layer stays `~/.agents/bouncer/`. Every log entry gains
   `harness: "<id>"`; an entry without it is a Claude Code entry from
   before this ADR. `audit --harness <id>` reads that harness's log.

9. **CLI.** A flag, not a namespace: `--harness <id>` on `run`, `check`,
   `doctor` and `audit`, default `claude-code`, so the v1 wiring is
   untouched. `check` prints the degraded action after the verdict
   (`confirm [git-protected] … → deny (codex)`). Two new subcommands:
   `harness list` (id, provenance, transport, `confirm` mapping,
   `ask_probe`) and `harness shim <id>`. `doctor --harness <id>` for any
   harness other than `claude-code` fails the wiring check when the hook
   command does not carry `--harness <id>`: a bare `bouncer run` under
   Codex would run with the Claude Code table and its fail-open `ask`.

10. **Sequencing.** Three tickets, each `Mode: gate`:
    - **15a** extracts the seam with zero Claude Code change:
      `policy/harness/claude-code.toml`, the pipeline, the codec registry
      with `stdin-json` and `hook-file`, the `pi-agent` rename, `--harness`,
      `harness list`. Proof: the engine fixtures stay green through the
      declaration; a new protocol fixture set recorded from the installed
      binary matches byte for byte on stdout and exit code, `doctor` output
      is unchanged under the inspected settings.
    - **15b** Codex: `codex.toml`, `apply-patch`, `codex-hooks`, a test
      phase under a temporary `CODEX_HOME` that records the `ask` probe in
      the file.
    - **15c** pi-agent: `pi-agent.toml`, the shim, `harness shim`, a test
      phase under `pi` and `omp`.
    opencode follows the same path later; it is not scheduled.

### Alternatives considered

- **One adapter module per assistant in code** (`interface Adapter {
  parse, degrade, emit, logPath, doctor }`), the shape ticket 15 first
  sketched. Every assistant is a release; a user on an unknown harness
  has nothing to try; the table ADR-0005 already keeps in TOML would be
  the one piece of harness knowledge left outside the file.
- **Baseline-only declarations, overlays may only tighten.** The lead's
  first recommendation: lint can check a declaration's shape but not that
  the harness honours `deny` or `ask`, and a file outside the repository
  would bypass the test-phase doctrine. Rejected by Jonathan for blocking
  exactly the user who wants to test an unknown harness; kept as the
  guard rails of § 4 and § 5 instead (`ask_probe`, no loosening of a
  baseline harness, announcement everywhere an override is).
- **A bouncer-native envelope for shims** (one fixed JSON in, one fixed
  JSON out, the shim translates). The shim then carries per-harness
  translation, which is policy code outside the file and outside the
  fixtures. With the declaration describing the harness's own objects the
  shim is twenty lines identical across harnesses but for the API call.
- **A subcommand per harness** (`bouncer codex doctor`). Multiplies a
  surface that is the same everywhere; the ids already exist; `run
  --shadow` already set the flag convention for the hook command line.
- **Fully declarative, no codecs.** `apply_patch` is text with its own
  grammar and the Codex trust state is a hashed table; a field map
  cannot express either, and pretending otherwise would put a parser in
  TOML.
- **Keep `omp` as the id with a `pi-agent.toml` file.** Zero migration,
  two names for one thing; the file name is the id everywhere else.

## Consequences

- Claude Code wiring, output and `doctor` are byte-identical after 15a;
  the fixtures and a recorded protocol set are the proof, not a review.
- A new assistant whose hook is stdin JSON is a file under
  `policy/harness/` (baseline, with a cited probe) or `harness.d/`
  (overlay, with `ask_probe`); one whose hook is in process is that file
  plus a shim the binary prints.
- Under Codex, every `confirm` verdict becomes `deny` until a Codex
  release honours `ask` and a probe says so; `check --harness codex` shows
  it on every verdict line.
- `rm -rf ~/.omp/agent` and its siblings now confirm under
  `pi-agent-config-dir`; `audit` on entries older than 15a shows the old
  row ids.
- `src/adapter/protocol.ts`, `degradation.ts`, `envelopes.ts` and the
  Claude Code maps of `dispatch.ts` and `targets.ts` are deleted, not
  kept as aliases.
- Claude Code gains verdicts on selector-suffixed and `;`-joined paths
  (15c, review round 1 L-1's `expandPathCandidates` — harness-neutral
  for every `role="read"` row, not a pi-agent-only fix); every other
  vector stays byte-identical to the installed binary
  (`fixtures/protocol/claude-code.json`'s own two new cases are
  captured from source instead, review round 2 C-3).
- Known limits, to document in `docs/reference/policy.md` § harness: a
  declaration cannot express a parser (that is a codec); lint proves the
  shape of an output table, never the harness's behaviour behind it; a
  shim installed by copy is a file the user maintains, and `doctor` for an
  in-process harness can only report what the shim relays.

## History

| Date | Change |
|---|---|
| 2026-09-07 | Proposed after the design session (facts 1–5 measured the same day; decisions on file-declared adapters, overlay-declared harnesses with guard rails, dumb printed shims, flag CLI, codex then pi-agent). |
| 2026-09-07 | Accepted the same day; build starts with ticket 15a on `feat/15a-adapter-seam`. |
| 2026-09-07 | Built on `feat/15a-adapter-seam` (ticket 15a): § 1–6, § 8–9 for Claude Code only, `policy/harness.toml` split into `policy/harness/<id>.toml` × 6, `omp` renamed `pi-agent`, `--harness <id>` on `run`/`check`/`doctor`/`audit` plus `harness list`. Claude Code byte-identical, proven by replaying `fixtures/protocol/claude-code.json` (captured from installed binary `253b06d`) through the refactored pipeline. Four review rounds added: per-template placeholder lint (`${reason}`/`${rule}`/`${verdict}` on deny/ask, `${context}` elsewhere; a quoted or unknown placeholder is rejected), `on_malformed` honoured (`deny` renders the harness's own deny template with `envelope-malformed`), `prompt` and `session_start` optional with six coherence rules, `[warn]` doctor tag for an uncheckable wiring, `check` dry-running through the harness's first `role = "command"` row at its own selector. Merged as `f69d37a` (commits `7606b51` + `f69d37a`), installed the same day. |
| 2026-09-08 | Built on `feat/15b-codex-adapter` (ticket 15b): `policy/harness/codex.toml` gains `[harness.protocol]` (confirm=deny, ADR-0006 § 4 rule 6's first reachable baseline), the `apply-patch` input codec (`src/adapter/codecs/input/apply-patch.ts`, `NeutralCall.path` generalized to plural `paths[]` for a move's two written ends), the `codex-hooks` wiring codec (`src/adapter/codecs/wiring/codex-hooks.ts` + a runtime codec registry, `src/adapter/codecs/wiring/registry.ts` — hooks.json + config.toml's `[hooks]` table, additive, plus a hook-trust ledger check, presence-only: the exact `trusted_hash` algorithm was attempted live via `/hooks` in an authenticated session and not determined, see the 15b report). Ten probes against a real, authenticated Codex CLI 0.153.2 session confirmed: `ask` is fail-open (probe 3, the hook is marked Failed and the tool call proceeds — the fact `confirm = "deny"` exists to route around), `confirm`-class verdicts degrade to `deny` with no prompt (probe 2), `apply_patch` writes are judged by protected-write and write-secret exactly like native file tools (probes 4a/4b), an untrusted hook is silently skipped (probe 6), and the exit-2/canary fail-closed paths hold under Codex too (probes 9–10). `fixtures/protocol/codex.json` (21 cases after review, captured from the SOURCE binary — the installed one predates this ticket) replays alongside `claude-code.json` (untouched) in the generalized `tests/fixtures-protocol.test.ts`, under the comparison contract decided on 2026-09-08: byte-for-byte except `permissionDecisionReason`, compared on its `<ruleId>:` prefix, with required case ids per harness. Two review rounds added: doctor labels naming the source actually read, a lint↔runtime codec-registry equality test, the rule-6 loader test against the real baseline, probes 7/8 re-run with an echo-forcing prompt (delivery of `additionalContext` confirmed in substance), the `codex-hooks` persistent row (`~/.codex/hooks.json` is where the guard's own wiring lives — it was an allowed write), an optional `input.permission` selector logged as `permission`. Merged as `6730a89` over `8f37af3`, installed the same day (107 effective rules on both profiles). |
| 2026-09-08/09 | Built on `feat/15c-pi-agent-adapter` (ticket 15c): `policy/harness/pi-agent.toml` gains `[harness.protocol]` (transport=stdin-json, wiring=shim-file, confirm=ask — a live probe of `ctx.ui.confirm` under both `pi` 0.84.1 and `omp` 18.1.10 confirmed a real dialog, decline blocks, accept runs, on BOTH binaries, `ask_probe` cites both sessions), the `hashline` input codec (`src/adapter/codecs/input/hashline.ts` — omp's `edit` tool's own `[PATH#TAG]` + `+`-row patch grammar, confirmed live and firsthand against the dev session's own `edit` tool; review round 1 P-1: pi's OWN `edit` tool is a structurally DIFFERENT shape, `{path, edits: [{oldText, newText}]}`, verified against the installed package's real `edit.d.ts` — the codec accepts both), pi's own `find`/`ls` rows (review round 1 P-2: pi has NO `glob` tool at all, verified against the installed package's real `index.d.ts`/`find.d.ts`/`ls.d.ts`; `glob` stays declared for omp only), `expandPathCandidates` (`src/adapter/neutral-call.ts`, review round 1 L-1, a reviewer finding: a `:N-M` selector suffix or `;`-joined list riding unstripped inside a `path` selector's raw value defeated every `$`-anchored path rule — harness-neutral for every `role="read"` row, so Claude Code's own `Read`/`Grep` rows gain verdicts on selector-suffixed and `;`-joined paths too, ticket 15c review round 2 C-3 — every other Claude Code vector stays byte-identical to the installed binary), the printed shim (`policy/harness/pi-agent.shim.ts`, embedded via Bun's `with { type: 'text' }` import attribute and `src/adapter/shim.ts`, `bouncer harness shim <id>`, a `before_agent_start` handler delivering the session-start doctor notice into headless (`-p`) turns on both binaries after `ctx.ui.notify`'s own toast was found not to reach one), and the `shim-file` wiring codec (`src/adapter/codecs/wiring/shim-file.ts` — `wiring:shim` + `wiring:binary`, no settings shape, no canary; `WiringCodec.read`/`extraChecks` generalized to one `buildChecks` method so hook-file/codex-hooks could keep their own settings/per-event/canary assembly while shim-file has none). Eleven probes designed: eight measured live and identical on both binaries (1, 3, 5, 7, 8, 9, 10, 11 — probe 5 only after a review round 1 tool-forced re-run proved pi's own native `write`/`edit` calls reach bouncer); probes 4 and 6 stay genuinely UNMEASURED under `pi`, each for a stated, live-observed reason (4: a content-based safety refusal on private key material, immune to which tool is named; 6: this one probe account's own pi toolset exposes no `grep`/`find`/`ls` to the model at all — a tool-availability fact, not a refusal) — never assumed identical to `omp`, which IS measured on both including the round-1 re-run's genuine `;`-list `grep` call; probe 2 (interactive confirm) is genuine on both binaries after one retraction — a first `omp`-attributed run turned out to be a stale, reused `pi` session (caught by decoding its own UUIDv7 session-id timestamp against the session file's own header), retracted before the flip, then re-run genuinely in a fresh pane. Two review rounds closed: round 1 (Standards REQUEST_CHANGES, Spec BLOCK — P-1/P-2/L-1 above, plus S-1…S-9/P-4/P-5/P-6, `src/adapter/codecs/warn.ts` extracted, `expandPathCandidates` unit- and protocol-tested); round 2 (confirmation reviewer + lead re-verification, REQUEST_CHANGES, no BLOCK — declaration/doc lag behind the already-correct code: the Claude Code consequence above, `pi-agent.toml`'s own three comment blocks rewritten to match the tree, `docs/reference/policy.md`'s candidate-set rule and `db.sqlite:table` test, three new protocol cases for the round-1 surfaces). The recorded probe table preserves both retractions' forensics and both review rounds' evidence. Merged as `96065fc`, installed the same day (107 effective rules on both profiles; `bouncer harness shim pi-agent` prints the shim with the installed binary's path). |
| 2026-10-11 | Amended § 7's ask rule in place (ticket 55, `feat/55-omp-ask-visible-to-herdr`): the shim's ask dialog moves from the Yes/No `ctx.ui.confirm` to a numbered one-key `ctx.ui.select` (`1. Allow` / `2. Block`, only the exact `1. Allow` allows, Block highlighted by default through `initialIndex: 1` where the harness honours it) and, when a UI exists, the shim emits omp's `herdr:blocked` on the extension bus around the wait (`{ active: true, label: "bouncer: <reason>" }` before the dialog, `{ active: false }` in a `finally`; an observability signal, not policy and not one of the canary's fixed rules — no verdict changes, guarded, always emitted, no `HERDR_*` sniffing). Why: observed 2026-10-11 under omp 18.9.1 and Herdr 0.9.0, a Bouncer ask left the agent `working` for the whole wait (17 min observed, no `blocked` state, no mobile notification), because omp's `ctx.ui` dialogs emit no bus event; a neutral `bouncer:ask` event plus a bridge extension was rejected (an unchecked file outside `doctor`'s byte check, silent if missing). Live probe, both binaries, real TUIs, 2026-10-11 (re-run on the final shim bytes and extended with the abort rows 2026-10-12): accept runs, decline, Esc and Ctrl+C block, and headless `-p` blocks without a dialog or an emit, on both; `omp` 18.9.1 selects instantly on a digit and honours `initialIndex` (a stray Enter blocks); `pi` 0.84.1 honours neither (digits do nothing, `1. Allow` is highlighted by default, a stray Enter allows — unchanged from the former Yes/No dialog, the same selector with Yes first); a subscriber on `pi.events` received the signal on both; with the dialog open and the process itself signalled, `omp` released the signal on SIGINT, SIGTERM and SIGHUP (shutdown settles the pending dialog, so the `finally` runs) while `pi` exited with the dialog pending and never released it (the signal dies with the process). Fact 5 (`ctx.ui.confirm` available when a UI is attached) describes the harness API and stays true. Every installed shim reads `[fail] wiring:shim` until reprinted (the shim's bytes changed); ships alone as 1.6.0. Known limit: vibe-island listens to omp's `tool_approval_*` events, not to `herdr:blocked`. |
| 2026-10-13 | Amended § 7's `session_start` rule in place: the shim folds the doctor notice for display. The toast and the collapsed `bouncer-doctor` message show the headline lines and a count of the indented detail lines; a `pi.registerMessageRenderer` renderer hands the message back to the host's full rendering when expanded (ctrl+o, `app.tools.expand`). The message content the model receives is unchanged. Why: an overlay's active relaxations, re-announced at every session start, filled the screen twice (toast, then message). Measured live on `omp` 18.10.3 and `pi` 0.84.1 (folded toast, folded message, ctrl+o expands and folds back); the toast under `omp`, unconfirmed since 15c, renders as a `Warning:` line. Registration is optional, runs last and is swallowed, so it cannot keep the guard handlers from loading. Every installed shim reads `[fail] wiring:shim` until reprinted (the shim's bytes changed). |
| 2026-10-13 | Extended by ADR-0008 (ticket 59, `feat/env-secrets-59`): an optional post-tool event (`events.post_tool`, `input.response`, an `output.redact` template carrying the structured `${response}` placeholder, lint-kept in lockstep and fail-closed), the shim's `tool_result` rule added to § 7 as fixed rule (4) — § 7 now lists the shim's rules as its header does: (1)–(3) enforced by the canary, (4) post-tool, the `session_start` delivery apart — and `doctor`'s `wiring:PostToolUse` for `hook-file`. § 3 names `${response}` as the one placeholder that is the JSON encoding of a structured value; the four others stay JSON-encoded strings. |
| 2026-10-14 | Added event-driven `flag` action and event-specific context template for the Claude Code failed-tool alert (ADR-0008 § 9). |
