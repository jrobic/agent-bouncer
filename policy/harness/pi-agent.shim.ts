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
// stdout to the harness as is. Its rules are fixed and harness-neutral —
// never a per-harness decision this file gets to make: the four numbered
// below (1–3 the same ones the canary enforces for every OTHER harness's
// wiring, 4 ADR-0008's post-tool rule), plus `session_start`'s two-way
// delivery of the doctor notice, described apart further down (its fold
// is display only, not a rule):
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
//   4. `tool_result` (ADR-0008): every tool's result is relayed before the
//      model sees it — `{ event: "tool_result", toolName, input, content,
//      isError, session, cwd }`, never `details` — and bouncer's `{
//      content }` answer is returned as is; empty stdout → `undefined`
//      (nothing to redact, the common case); rule 1's failures, or stdout
//      that is not a JSON object carrying a `content` array → `{ content:
//      [{ type: "text", text: "bouncer: post-tool check failed — output
//      withheld" }] }`. The handler never throws: a throwing `tool_result`
//      handler leaves the ORIGINAL output in place, on both binaries
//      (measured 2026-10-13, omp 18.10.3 / pi 0.84.1). With
//      `BOUNCER_PROBE_LOG` set, a `tool_result` line records the output's
//      shape and size only (block types, byte count) — never its text.
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
// best-effort toast — measured live: a startup banner under `pi` 0.84.1's
// TUI, ticket 15c; a `Warning:` line in the chat under `omp` 18.10.3's
// TUI, and under `pi` 0.84.1's again, 2026-10-13) AND a message queued
// for the FIRST `before_agent_start` turn (`pi.sendMessage`'s own sibling
// mechanism — the RETURN-based `{ message: {...} }` shape, `customType:
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
//
// Both are FOLDED for display only (2026-10-13): a doctor notice is
// headline lines, each followed by indented detail lines, and an active
// overlay's relaxations alone fill a screen at every session start. The
// toast shows the headlines and a count of the detail lines; the
// `bouncer-doctor` message renders the same fold through
// `pi.registerMessageRenderer` while collapsed, and hands back to the
// host's own full rendering when expanded — ctrl+o (`app.tools.expand`),
// measured live on `omp` 18.10.3 and `pi` 0.84.1. The message's content,
// what the model receives, is never folded. A host without
// `registerMessageRenderer`, or one whose registration throws, keeps its
// own full rendering: registration runs last and is swallowed, so it can
// never keep the guard handlers from loading.
//
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
// Rule 4's answer carries the whole rewritten output back on stdout; the
// harnesses truncate a tool's content (~50 KB measured) but an image block
// rides along unchanged, so Node's 1 MiB `spawnSync` default would turn a
// large answer into a spawn failure (a withheld output). A transport limit,
// not policy.
const MAX_STDOUT_BYTES = 64 * 1024 * 1024;
// Rule 4's answer when the post-tool check cannot be trusted (ADR-0008 § 6).
const POST_TOOL_WITHHELD = 'bouncer: post-tool check failed — output withheld';

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

// The slice of pi/omp's `tool_result` event the shim relays (rule 4) —
// `details` deliberately absent: it never reaches the model.
interface ToolResultEvent {
  toolName: string;
  input: unknown;
  content: unknown;
  isError?: boolean;
}

// A partial patch: omitted fields keep their current values (pi's own
// `ToolResultEventResult`, honoured identically by omp).
interface ToolResultPatch {
  content: unknown[];
}

interface BeforeAgentStartMessage {
  customType: string;
  content: string;
  display: boolean;
}

interface BeforeAgentStartResult {
  message?: BeforeAgentStartMessage;
}

// What a `registerMessageRenderer` renderer reads from the message and the
// component it returns: pi-tui's `Component` contract (`render(width)` →
// lines, `invalidate()`), shared by both hosts' TUIs.
interface CustomMessage {
  content: string | readonly { type: string; text?: string; }[];
}

interface RenderedComponent {
  render(width: number): string[];
  invalidate(): void;
}

interface PiTheme {
  fg(color: string, text: string): string;
}

type MessageRenderer = (message: CustomMessage, options: { expanded: boolean; }, theme: PiTheme) => RenderedComponent | undefined;

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
  on(event: 'tool_result', handler: (event: ToolResultEvent, ctx: PiContext) => Promise<ToolResultPatch | undefined>): void;
  // Optional on purpose, like `events`: without it the `bouncer-doctor`
  // message keeps the host's own full rendering.
  registerMessageRenderer?(customType: string, renderer: MessageRenderer): void;
}

type SpawnOutcome =
  | { readonly kind: 'fail-closed'; readonly reason: string; }
  | { readonly kind: 'silent'; }
  | { readonly kind: 'parsed'; readonly value: Record<string, unknown>; };

function failClosed(what: string): SpawnOutcome {
  return { kind: 'fail-closed', reason: `bouncer: ${what} — failing closed` };
}

// Ticket 15c § probe phase: when `BOUNCER_PROBE_LOG` is set, the JSON
// payload this shim is about to send is appended there (one line) BEFORE
// the spawn — the probe script's own captured "stdin" evidence, since there
// is no external wrapper command (unlike a hook-file harness's `hooks.json`
// entry) to `tee` in front of here. A `tool_result` payload is the one
// exception (rule 4, header comment): it carries the tool's raw output — the
// very text that may hold a protected value — so its line keeps the
// envelope fields and only the SHAPE and SIZE of the output (block types,
// byte count), never the output text. The tool input is left out of that
// line only because the same call's `tool_call` line already records it as
// is — that is no protection of the input. A logging failure (an unwritable
// path, a full disk) never breaks the real fail-closed contract below — it
// is swallowed, never surfaced as a reason a tool call was blocked.
function logProbeStdin(payload: Record<string, unknown>): void {
  const path = process.env.BOUNCER_PROBE_LOG;
  if (path === undefined) return;
  try {
    let record = payload;
    if (payload['event'] === 'tool_result') {
      const { content, input: _input, ...fields } = payload;
      const blocks: unknown[] = Array.isArray(content) ? content : [];
      record = {
        ...fields,
        contentTypes: blocks.map((block) => (block !== null && typeof block === 'object' && 'type' in block ? block.type : typeof block)),
        contentBytes: Buffer.byteLength(JSON.stringify(content ?? null)),
      };
    }
    appendFileSync(path, `${JSON.stringify(record)}\n`);
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
      maxBuffer: MAX_STDOUT_BYTES,
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

const NOTICE_TYPE = 'bouncer-doctor';

// A doctor notice is headline lines, each followed by its indented detail
// lines (`  - …`, src/adapter/doctor.ts's buildSessionStartContext). The
// fold keeps the headlines and counts the details. Display only: the model
// always receives the full text (`before_agent_start` below).
interface FoldedNotice {
  readonly headlines: readonly string[];
  readonly hidden: number;
}

function foldNotice(text: string): FoldedNotice | undefined {
  const lines = text.split('\n').filter((line) => line.trim() !== '');
  const headlines = lines.filter((line) => !/^\s/.test(line));
  const hidden = lines.length - headlines.length;
  return hidden === 0 || headlines.length === 0 ? undefined : { headlines, hidden };
}

// The toast cannot expand, so its last line names where the details are.
function noticeToast(text: string): string {
  const folded = foldNotice(text);
  if (folded === undefined) return text;
  return [...folded.headlines, `… ${folded.hidden} more line(s) — ctrl+o expands them on the bouncer doctor message`].join('\n');
}

// pi's TUI throws when a rendered line is wider than the terminal
// ("Rendered line N exceeds terminal width"), so cells are counted never
// below what either host measures: one for ASCII, Latin-1 and General
// Punctuation (`—`, `…`), two for anything else. Control characters (a tab
// is three cells to pi-tui) are turned into spaces before measuring.
function cellWidth(ch: string): number {
  const cp = ch.codePointAt(0) ?? 0;
  return cp < 0x300 || (cp >= 0x2000 && cp <= 0x206f) ? 1 : 2;
}

function wrapToCells(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  let used = 0;
  for (const word of text.replace(/\p{Cc}/gu, ' ').split(' ')) {
    const chars = [...word];
    const wordCells = chars.reduce((sum, ch) => sum + cellWidth(ch), 0);
    if (used > 0 && used + 1 + wordCells <= width) {
      line += ` ${word}`;
      used += 1 + wordCells;
      continue;
    }
    if (used > 0) {
      lines.push(line);
      line = '';
      used = 0;
    }
    for (const raw of chars) {
      const fits = cellWidth(raw) <= width;
      const cells = fits ? cellWidth(raw) : 1;
      if (used + cells > width) {
        lines.push(line);
        line = '';
        used = 0;
      }
      line += fits ? raw : '?';
      used += cells;
    }
  }
  lines.push(line);
  return lines;
}

function paint(theme: PiTheme, color: string, text: string): string {
  try {
    return theme.fg(color, text);
  } catch {
    return text;
  }
}

function messageText(message: CustomMessage): string {
  const { content } = message;
  if (typeof content === 'string') return content;
  return content.flatMap((part) => (part.type === 'text' && typeof part.text === 'string' ? [part.text] : [])).join('\n');
}

// The `bouncer-doctor` message, collapsed: the folded notice. Expanded
// (ctrl+o, `app.tools.expand` on both hosts), or nothing to fold:
// `undefined` hands the message back to the host's own full rendering.
const renderNotice: MessageRenderer = (message, { expanded }, theme) => {
  if (expanded) return undefined;
  const folded = foldNotice(messageText(message));
  if (folded === undefined) return undefined;
  const rows: (readonly [string, string])[] = [
    ...folded.headlines.map((headline) => ['warning', headline] as const),
    ['muted', `… ${folded.hidden} more line(s) — ctrl+o to expand`],
  ];
  let cache: { readonly width: number; readonly lines: string[]; } | undefined;
  return {
    render(width) {
      if (cache?.width !== width) {
        const pad = width >= 3 ? 1 : 0;
        const inner = Math.max(1, width - 2 * pad);
        const lines = rows.flatMap(([color, text]) =>
          wrapToCells(text, inner).map((part) => `${' '.repeat(pad)}${paint(theme, color, part)}`)
        );
        cache = { width, lines };
      }
      return cache.lines;
    },
    invalidate() {
      cache = undefined;
    },
  };
};

// The session/cwd pair every relayed event carries (pi-agent.toml's
// `input.session` / `input.cwd` selectors).
function sessionFields(ctx: PiContext): { session: string | null; cwd: string | null; } {
  return { session: ctx.sessionManager?.getSessionId?.() ?? null, cwd: ctx.cwd ?? null };
}

export default function(pi: PiExtensionHost): void {
  // Set by `session_start`, consumed once by the FIRST `before_agent_start`
  // turn, then cleared — see this file's own header comment for why two
  // delivery mechanisms exist and what each one is measured to cover.
  let pendingSessionNotice: string | undefined;

  pi.on('tool_call', async (event, ctx): Promise<ToolCallResult | undefined> => {
    const outcome = spawnBouncer({ event: 'tool_call', toolName: event.toolName, input: event.input, ...sessionFields(ctx) });
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
    const outcome = spawnBouncer({ event: 'session_start', ...sessionFields(ctx) });
    if (outcome.kind === 'fail-closed') {
      pendingSessionNotice = outcome.reason;
      ctx.ui.notify(outcome.reason, 'warning');
      return;
    }
    if (outcome.kind === 'silent') return;
    const { notify } = outcome.value;
    if (typeof notify === 'string') {
      pendingSessionNotice = notify;
      ctx.ui.notify(noticeToast(notify), 'warning');
    }
  });

  pi.on('before_agent_start', (): BeforeAgentStartResult | undefined => {
    if (pendingSessionNotice === undefined) return undefined;
    const content = pendingSessionNotice;
    pendingSessionNotice = undefined;
    return { message: { customType: NOTICE_TYPE, content, display: true } };
  });

  // Rule 4 (header comment): relay every tool's result, return bouncer's
  // `{ content }` as is, `undefined` on silence, the withheld content on
  // any failure. Everything inside the `try` — a throw would reach the
  // harness, which keeps the ORIGINAL output when a handler throws.
  pi.on('tool_result', async (event, ctx): Promise<ToolResultPatch | undefined> => {
    try {
      const outcome = spawnBouncer({
        event: 'tool_result',
        toolName: event.toolName,
        input: event.input,
        content: event.content,
        isError: event.isError ?? false,
        ...sessionFields(ctx),
      });
      if (outcome.kind === 'silent') return undefined;
      if (outcome.kind === 'parsed') {
        const { content } = outcome.value;
        if (Array.isArray(content)) return { content };
      }
    } catch {
      // Falls through to the withheld answer below.
    }
    return { content: [{ type: 'text', text: POST_TOOL_WITHHELD }] };
  });

  // Last, and never allowed to throw: a renderer that fails to register
  // must not keep the guard handlers above from loading.
  try {
    pi.registerMessageRenderer?.(NOTICE_TYPE, renderNotice);
  } catch {
    // Swallowed: the message keeps the host's own full rendering.
  }
}
