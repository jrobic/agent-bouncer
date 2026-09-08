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

Facts measured on this workstation on 2026-09-07, all feeding the decision:

1. **omp 18.1.10 does not run the Claude Code hook.** In an omp session, a
   `confirm`-class command (`git branch -D no-such-branch-zzz`) ran with no
   prompt and no audit-log entry in either profile; an `observe`-class one
   (`git reflog show -n 1`) left no entry either, while the same envelope
   through `bouncer run` logs it. omp's `claude` discovery provider loads
   `hooks/pre/*.ts` factories, not the `command` hooks of `settings.json`.
   The assistant the workstation uses most is unguarded.
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
  behaviour of the installed binary (`9ee2286`) must not change while the
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
   ask_probe = "2026-08-16, workstation THREAT_MODEL §1: under --dangerously-skip-permissions an unanswerable ask is enforced as deny"

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
   `${rule}` and `${verdict}` the raw fields. A template may set `exit`
   instead of, or with, `stdout`.

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
   the file stays the single place that knows both APIs. Three fixed rules
   in every shim, the same ones the canary enforces: bouncer missing, not
   executable or exiting non-zero → block; an `ask` action → `ctx.ui.confirm`
   when a UI exists, block otherwise; a `session_start` action →
   `ctx.ui.notify` of the doctor context. `bouncer harness shim <id>` prints
   the shim source embedded with the binary; the documentation says where
   to write it (`<dir>/extensions/bouncer.ts` for pi-agent and omp,
   `~/.config/opencode/plugins/` for opencode). One protocol, two
   binaries for pi-agent: the test phase of its ticket runs the same shim,
   unmodified, under `pi` and under `omp`.

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
      declaration, a new protocol fixture set recorded from the installed
      binary matches byte for byte on stdout and exit code, `doctor`
      output is unchanged on the workstation settings.
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
| 2026-09-07 | Built on `feat/15a-adapter-seam` (ticket 15a): § 1–6, § 8–9 for Claude Code only, `policy/harness.toml` split into `policy/harness/<id>.toml` × 6, `omp` renamed `pi-agent`, `--harness <id>` on `run`/`check`/`doctor`/`audit` plus `harness list`. Claude Code byte-identical, proven by replaying `fixtures/protocol/claude-code.json` (captured from installed binary `9ee2286`) through the refactored pipeline. Four review rounds added: per-template placeholder lint (`${reason}`/`${rule}`/`${verdict}` on deny/ask, `${context}` elsewhere; a quoted or unknown placeholder is rejected), `on_malformed` honoured (`deny` renders the harness's own deny template with `envelope-malformed`), `prompt` and `session_start` optional with six coherence rules, `[warn]` doctor tag for an uncheckable wiring, `check` dry-running through the harness's first `role = "command"` row at its own selector. Merged as `4121482` (commits `ce1b7ae` + `4121482`), installed the same day. |
