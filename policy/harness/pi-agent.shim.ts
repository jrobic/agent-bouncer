// The printed pi-agent/omp shim (ADR-0006 § 7, ticket 15c). Embedded
// verbatim by src/adapter/shim.ts (`import … with { type: 'text' }`,
// `bun build --compile` inlines it exactly like every baseline TOML
// file, src/policy/baseline.ts) and printed as is by `bouncer harness
// shim pi-agent`, with ONE substitution: the double-quoted placeholder
// on the `BOUNCER` line below is replaced by the printing process's own
// absolute path (`process.execPath`) — everything else ships byte for
// byte. `doctor --harness pi-agent`'s `wiring:shim` check re-renders
// this same source with whatever `BOUNCER` the INSTALLED copy already
// carries and compares byte for byte (never `process.execPath` at
// doctor-run time — a doctor invoked from a different checkout must
// never claim drift solely because ITS OWN binary lives somewhere else).
//
// Carries NO policy (ADR-0006 § 7's own contract, doctrine 2026-09-04
// "bouncer judges alone"): it forwards pi-agent's own event object to
// `bouncer run --harness pi-agent` unmodified and returns bouncer's
// stdout to the harness as is. The three fixed, harness-neutral rules
// below are the same ones the canary enforces for every OTHER harness's
// wiring — never a per-harness decision this file gets to make:
//   1. bouncer missing, not executable, exiting non-zero, or timing out
//      (2s) → `{ block: true, reason: "bouncer: … — failing closed" }`.
//   2. empty stdout → `undefined` (allow — nothing matched).
//   3. `{ ask, reason }` → with no UI attached (`ctx.hasUI` false, e.g.
//      `-p`): `{ block: true, reason }`, nothing opened, nothing emitted.
//      With a UI: a numbered one-key dialog, `ctx.ui.select("bouncer\n"
//      + reason, ["1. Allow", "2. Block"], { initialIndex: 1 })` (Block
//      highlighted by default where the host honours it: omp yes, pi
//      0.84.1 no — see below), and ONLY the exact answer "1. Allow" lets
//      the call run — "2. Block", Esc (`undefined`), an abort, any other
//      string, or a select that rejects or throws → `{ block: true,
//      reason }`. No timeout: an unanswered dialog waits (a timeout would
//      silently turn asks into denials).
//
// The dialog's shape is measured per binary, never assumed iso (ticket
// 55, live 2026-10-11, re-run 2026-10-12): `omp` 18.9.1 selects instantly
// on a digit key when an option label starts with `N. ` and honours
// `initialIndex`, so Block is the default highlight and a stray Enter
// blocks; `pi` 0.84.1 honours neither — digits do nothing, the FIRST
// option ("1. Allow") is always highlighted and Enter confirms it
// (unchanged from the former Yes/No confirm), arrows move, Esc blocks.
// See pi-agent.toml's `ask_probe`.
//
// Around that wait — UI only — the shim also emits omp's `herdr:blocked`
// on the extension bus: `pi.events.emit("herdr:blocked", { active:
// true, label: "bouncer: " + reason })` BEFORE the dialog opens and
// `{ active: false }` in a `finally` that runs whenever the dialog
// settles (accept, decline, Esc, Ctrl+C, a failing select — and, under
// omp, a SIGINT/SIGTERM/SIGHUP to the process, which settles the pending
// dialog while it shuts down; pi 0.84.1 exits with the dialog still
// pending, so nothing releases the signal there and it dies with the
// process: live 2026-10-12, see `ask_probe`), so Herdr's own omp
// integration flips the agent to `blocked` for the duration of the
// dialog and back after. This is an OBSERVABILITY SIGNAL, NOT POLICY, and
// not one of the fixed rules above — nothing the canary enforces: it
// gates nothing and changes no verdict. One guarded helper
// (`emitHerdrBlocked`) swallows a missing `pi.events` and a throwing
// `emit`, so it can never keep the dialog from opening nor mask the
// verdict. Always emitted, no `HERDR_*` environment sniffing: a bus with
// no subscriber makes it a no-op, and there is nothing to drift against
// Herdr's own detection. The label is the same reason text the dialog
// already shows, never anything else.
// Why here: Herdr's integration file is herdr-managed and overwritten on
// reinstall, so the fix cannot live there; a neutral `bouncer:ask` event
// plus a local bridge extension was rejected (one more unchecked file on
// disk, outside `doctor`'s byte check, and a silent failure if missing).
// Known limit: vibe-island listens to omp's `tool_approval_*` events,
// not to `herdr:blocked`, so it stays blind to a Bouncer ask.
//
// `session_start`'s own doctor context is delivered TWO ways, both fixed
// rules (never a per-harness choice): `ctx.ui.notify` (an immediate,
// best-effort toast — measured live, ticket 15c: rendered as a startup
// banner under `pi` 0.84.1's TUI; not independently isolated under
// `omp` 18.1.10's TUI — the one live `omp` run that showed a startup
// banner used a shim build where the SECOND path below was already
// live too, and only that second path left hard proof in the session's
// own transcript, so this toast's presence on `omp` specifically is
// unconfirmed, not disproven) AND a message queued for the FIRST
// `before_agent_start` turn (`pi.sendMessage`'s own sibling mechanism —
// the RETURN-based `{ message: {...} }` shape, `customType:
// "bouncer-doctor"`, `display: true` — the same shape Claude Code's
// `UserPromptSubmit` `additionalContext` fills). This second path is
// confirmed live on BOTH binaries two ways: headless (`-p`), directly,
// on both `pi` and `omp`; and, on `omp`, from a real interactive
// session's own persisted transcript (a `custom_message` entry,
// `customType: "bouncer-doctor"`, matching this handler's own return
// shape exactly) — the strongest evidence of the two, since it is the
// harness's own recorded proof of delivery, not an operator's visual
// recollection. `before_agent_start` fires once real agent processing
// begins, well after either binary's own startup sequence, headless
// (`-p`) included — a message injected there participates in LLM
// context regardless of whether any UI is even attached, unlike a pure
// UI toast. Delivered exactly ONCE per session (cleared after the first
// `before_agent_start` turn consumes it), never repeated on later turns
// of the same session.
// Imports nothing from the harness itself but the type aliases below
// (structural, not a real import) — `pi` and `omp` share one extension
// API (ADR-0006 fact 5) and load this same file unmodified as an
// extension module (`export default function (pi) { … }`).

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { appendFileSync } from 'node:fs';

// `BOUNCER_BIN` overrides at the shim's own RUNTIME; the baked literal
// below is only the fallback, substituted at PRINT time (see this file's
// own header comment and src/adapter/shim.ts's `renderShim`) — never
// edited by hand.
const BOUNCER = process.env.BOUNCER_BIN ?? '__BOUNCER_BIN__';
const TIMEOUT_MS = 2000;

// Ticket 55: the ask dialog's one ALLOWING answer — the label offered as the
// first option AND the only answer the shim compares against, so the two can
// never drift apart (anything else, `undefined` included, blocks).
const ALLOW_OPTION = '1. Allow';

interface PiUi {
  select(title: string, options: string[], opts?: { initialIndex?: number; }): Promise<string | undefined>;
  notify(text: string, level?: string): void;
}

interface PiSessionManager {
  getSessionId?(): string | undefined;
}

interface PiContext {
  hasUI: boolean;
  cwd?: string;
  sessionManager?: PiSessionManager;
  ui: PiUi;
}

interface ToolCallEvent {
  toolName: string;
  input: unknown;
  toolCallId?: string;
}

interface ToolCallResult {
  block?: boolean;
  reason?: string;
}

interface BeforeAgentStartMessage {
  customType: string;
  content: string;
  display: boolean;
}

interface BeforeAgentStartResult {
  message?: BeforeAgentStartMessage;
}

// The payload of omp's `herdr:blocked` event (Herdr's own omp integration
// reads `active` and `label`) — see this file's own header comment.
interface HerdrBlockedSignal {
  active: boolean;
  label?: string;
}

interface PiExtensionHost {
  // Optional on purpose: the shim only ever emits on it (`emitHerdrBlocked`),
  // and a `pi` without a bus is a legal host, not an error.
  events?: { emit(channel: string, data?: unknown): void; };
  on(event: 'tool_call', handler: (event: ToolCallEvent, ctx: PiContext) => Promise<ToolCallResult | undefined>): void;
  on(event: 'session_start', handler: (event: unknown, ctx: PiContext) => Promise<void>): void;
  on(event: 'before_agent_start', handler: (event: unknown, ctx: PiContext) => BeforeAgentStartResult | undefined): void;
}

type SpawnOutcome =
  | { readonly kind: 'fail-closed'; readonly reason: string; }
  | { readonly kind: 'silent'; }
  | { readonly kind: 'parsed'; readonly value: Record<string, unknown>; };

function failClosed(what: string): SpawnOutcome {
  return { kind: 'fail-closed', reason: `bouncer: ${what} — failing closed` };
}

// Ticket 15c § probe phase: when `BOUNCER_PROBE_LOG` is set, the exact
// JSON payload this shim is about to send is appended there (one line)
// BEFORE the spawn — the probe script's own captured "stdin" evidence,
// since there is no external wrapper command (unlike a hook-file
// harness's `hooks.json` entry) to `tee` in front of here. A logging
// failure (an unwritable path, a full disk) never breaks the real
// fail-closed contract below — it is swallowed, never surfaced as a
// reason a tool call was blocked.
function logProbeStdin(payload: Record<string, unknown>): void {
  const path = process.env.BOUNCER_PROBE_LOG;
  if (path === undefined) return;
  try {
    appendFileSync(path, `${JSON.stringify(payload)}\n`);
  } catch {
    // Swallowed — see this function's own header comment.
  }
}

function spawnBouncer(payload: Record<string, unknown>): SpawnOutcome {
  logProbeStdin(payload);
  let result: SpawnSyncReturns<string>;
  try {
    result = spawnSync(BOUNCER, ['run', '--harness', 'pi-agent'], {
      input: JSON.stringify(payload),
      timeout: TIMEOUT_MS,
      encoding: 'utf8',
    });
  } catch (err) {
    return failClosed(`spawn threw (${err instanceof Error ? err.message : String(err)})`);
  }
  // Review round 1 S-3: `spawnSync`'s own `timeout` option, once
  // exceeded, sets BOTH `result.error` (`code: "ETIMEDOUT"`) AND
  // `result.signal` — checking `result.error !== undefined` first,
  // unconditionally, made the `result.signal !== null` branch below
  // permanently unreachable for a real timeout: every timeout matched
  // the generic "spawn failed" branch first, with Node's own opaque
  // ETIMEDOUT error text instead of this shim's own clearer message.
  if (result.error !== undefined) {
    if ((result.error as NodeJS.ErrnoException).code === 'ETIMEDOUT') return failClosed(`timed out after ${TIMEOUT_MS}ms`);
    return failClosed(`spawn failed (${result.error.message})`);
  }
  if (result.signal !== null) return failClosed(`timed out after ${TIMEOUT_MS}ms`);
  if (result.status !== 0) return failClosed(`exited ${String(result.status)}`);
  const stdout = typeof result.stdout === 'string' ? result.stdout.trim() : '';
  if (stdout === '') return { kind: 'silent' };
  try {
    const parsed: unknown = JSON.parse(stdout);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return failClosed('unreadable stdout');
    }
    return { kind: 'parsed', value: parsed as Record<string, unknown> };
  } catch {
    return failClosed('unreadable stdout');
  }
}

// Ticket 55: the ONE place `herdr:blocked` is emitted (see this file's own
// header comment — an observability signal, never policy). A `pi` with no
// `events` bus, or an `emit` that throws, is swallowed here: the signal can
// never keep the dialog from opening nor change the verdict, and the call
// in the ask branch's `finally` can never mask it.
function emitHerdrBlocked(pi: PiExtensionHost, signal: HerdrBlockedSignal): void {
  try {
    pi.events?.emit('herdr:blocked', signal);
  } catch {
    // Swallowed — see this function's own header comment.
  }
}

export default function(pi: PiExtensionHost): void {
  // Set by `session_start`, consumed once by the FIRST `before_agent_start`
  // turn, then cleared — see this file's own header comment for why two
  // delivery mechanisms exist and what each one is measured to cover.
  let pendingSessionNotice: string | undefined;

  pi.on('tool_call', async (event, ctx): Promise<ToolCallResult | undefined> => {
    const outcome = spawnBouncer({
      event: 'tool_call',
      toolName: event.toolName,
      input: event.input,
      session: ctx.sessionManager?.getSessionId?.() ?? null,
      cwd: ctx.cwd ?? null,
    });
    if (outcome.kind === 'fail-closed') return { block: true, reason: outcome.reason };
    if (outcome.kind === 'silent') return undefined;
    const { value } = outcome;
    if (typeof value['block'] === 'boolean') {
      const reason = typeof value['reason'] === 'string' ? value['reason'] : undefined;
      return reason === undefined ? { block: value['block'] } : { block: value['block'], reason };
    }
    if (value['ask'] === true) {
      const reason = typeof value['reason'] === 'string' ? value['reason'] : 'bouncer';
      // Rule 3 (header comment): no UI → block, opening and emitting
      // nothing. With a UI, ONLY the exact answer ALLOW_OPTION runs the
      // call. Block is the default highlight under omp only (it honours
      // `initialIndex`); pi 0.84.1 ignores it and opens on "1. Allow". The
      // `finally` releases the `herdr:blocked` signal whenever the dialog
      // settles (accept, decline, Esc, Ctrl+C, a select that rejects or
      // throws); a process signalled with the dialog pending never gets
      // there under pi (header comment).
      if (!ctx.hasUI) return { block: true, reason };
      emitHerdrBlocked(pi, { active: true, label: `bouncer: ${reason}` });
      try {
        const answer = await ctx.ui.select(`bouncer\n${reason}`, [ALLOW_OPTION, '2. Block'], { initialIndex: 1 });
        return answer === ALLOW_OPTION ? undefined : { block: true, reason };
      } catch {
        return { block: true, reason };
      } finally {
        emitHerdrBlocked(pi, { active: false });
      }
    }
    return undefined;
  });

  pi.on('session_start', async (_event, ctx): Promise<void> => {
    const outcome = spawnBouncer({ event: 'session_start', session: ctx.sessionManager?.getSessionId?.() ?? null, cwd: ctx.cwd ?? null });
    if (outcome.kind === 'fail-closed') {
      pendingSessionNotice = outcome.reason;
      ctx.ui.notify(outcome.reason, 'warning');
      return;
    }
    if (outcome.kind === 'silent') return;
    const { notify } = outcome.value;
    if (typeof notify === 'string') {
      pendingSessionNotice = notify;
      ctx.ui.notify(notify, 'warning');
    }
  });

  pi.on('before_agent_start', (): BeforeAgentStartResult | undefined => {
    if (pendingSessionNotice === undefined) return undefined;
    const content = pendingSessionNotice;
    pendingSessionNotice = undefined;
    return { message: { customType: 'bouncer-doctor', content, display: true } };
  });
}
