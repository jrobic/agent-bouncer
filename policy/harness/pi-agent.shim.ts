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
//   3. `{ ask, reason }` → `ctx.hasUI ? await ctx.ui.confirm(...) : false`;
//      `false` (declined, or no UI at all) → `{ block: true, reason }`.
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

interface PiUi {
  confirm(title: string, text: string): Promise<boolean>;
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

interface PiExtensionHost {
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
      const confirmed = ctx.hasUI ? await ctx.ui.confirm('bouncer', reason) : false;
      return confirmed ? undefined : { block: true, reason };
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
