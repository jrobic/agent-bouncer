// The printed pi-agent/omp shim (policy/harness/pi-agent.shim.ts,
// ADR-0006 § 7, ticket 15c) — proved by spawning the REAL BUILT binary
// (`bun run build`, same discipline as tests/adapter-canary.test.ts's own
// "a freshly built binary leaves the canary silent") to print the shim,
// writing it to a fresh temp file per case (a distinct absolute path so
// Bun's module cache never serves a stale `BOUNCER` from an earlier
// case), and dynamically importing it with a fake `pi` host that records
// the handlers it registers (plus an `events` bus where a case needs one).
// Every assertion drives the REAL shim module, never a hand-reimplemented
// copy of its logic.

import { describe, expect, test } from 'bun:test';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { POST_TOOL_WITHHELD } from '../src/adapter/post-tool.ts';
import { tmpDir } from './tmp.ts';

const PROJECT_ROOT = join(import.meta.dir, '..');

interface FakeCtx {
  hasUI: boolean;
  cwd?: string;
  sessionManager?: { getSessionId?: () => string | undefined; };
  ui: {
    select: (title: string, options: string[], opts?: { initialIndex?: number; }) => Promise<string | undefined>;
    notify: (text: string, level?: string) => void;
  };
}

// The slice of omp/pi's `pi.events` bus the shim may touch (`emit` only).
interface FakeEvents {
  emit: (channel: string, data?: unknown) => void;
}

// What a `tool_call` handler hands back to the harness: `undefined` allows.
interface ToolCallVerdict {
  block?: boolean;
  reason?: string;
}

type ToolCallHandler = (event: { toolName: string; input: unknown; }, ctx: FakeCtx) => Promise<ToolCallVerdict | undefined>;
type SessionStartHandler = (event: unknown, ctx: FakeCtx) => Promise<void>;
type BeforeAgentStartHandler = (
  event: unknown,
  ctx: FakeCtx,
) => { message?: { customType: string; content: string; display: boolean; }; } | undefined;
// Rule 4 (ADR-0008): a `{ content }` patch, or `undefined` to keep the output.
type ToolResultHandler = (
  event: { toolName: string; input: unknown; content: unknown; isError?: boolean; details?: unknown; },
  ctx: FakeCtx,
) => Promise<{ content: unknown[]; } | undefined>;

// The slice of pi-tui's `Component` the shim's `bouncer-doctor` renderer returns.
interface RenderedNotice {
  render: (width: number) => string[];
}
type NoticeRenderer = (
  message: { content: string; },
  options: { expanded: boolean; },
  theme: { fg: (color: string, text: string) => string; },
) => RenderedNotice | undefined;

interface LoadedShim {
  readonly toolCall: ToolCallHandler;
  readonly sessionStart: SessionStartHandler;
  readonly beforeAgentStart: BeforeAgentStartHandler;
  readonly renderers: Readonly<Record<string, NoticeRenderer>>;
  readonly toolResult: ToolResultHandler;
}

function fakeCtx(overrides: Partial<FakeCtx> = {}): FakeCtx {
  return {
    hasUI: true,
    cwd: '/tmp/probe-cwd',
    sessionManager: { getSessionId: () => 'fake-session' },
    ui: { select: async () => undefined, notify: () => {} },
    ...overrides,
  };
}

// Builds the binary ONCE per file (mirrors tests/adapter-canary.test.ts):
// every case below reuses this same `dist/bouncer` to print the shim,
// only the `BOUNCER_BIN` a given case's temp copy resolves at import
// time differs.
let builtOnce: Promise<void> | undefined;
async function ensureBuilt(): Promise<void> {
  builtOnce ??= (async () => {
    const build = Bun.spawn(['bun', 'run', 'build'], { cwd: PROJECT_ROOT, stdout: 'ignore', stderr: 'ignore' });
    expect(await build.exited).toBe(0);
  })();
  return builtOnce;
}

// Prints the real shim from the real built binary, writes it to a fresh
// temp file, and imports it with `BOUNCER_BIN` set to `bouncerBin` for
// the duration of that one import — never touching the file's own baked
// `BOUNCER` (`process.execPath` of `dist/bouncer` at print time), which
// `BOUNCER_BIN` always overrides at the shim's own runtime, per its own
// contract. `events` is the fake `pi.events` bus handed to the shim; left
// undefined, the fake `pi` has NO `events` property at all. `registerMessageRenderer`
// replaces the fake host's recording one (a host that throws on registration).
async function loadShim(
  bouncerBin: string,
  events?: FakeEvents,
  registerMessageRenderer?: (customType: string, renderer: NoticeRenderer) => void,
): Promise<LoadedShim> {
  await ensureBuilt();
  const printed = Bun.spawn([join(PROJECT_ROOT, 'dist', 'bouncer'), 'harness', 'shim', 'pi-agent'], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const source = await new Response(printed.stdout).text();
  expect(await printed.exited).toBe(0);
  expect(source).toContain('const BOUNCER = process.env.BOUNCER_BIN');

  const dir = tmpDir('bouncer-shim-test-');
  const file = join(dir, 'bouncer.ts');
  await writeFile(file, source, 'utf8');

  const originalBouncerBin = process.env.BOUNCER_BIN;
  process.env.BOUNCER_BIN = bouncerBin;
  let mod: {
    default: (pi: {
      on: (event: string, handler: unknown) => void;
      events?: FakeEvents;
      registerMessageRenderer: (customType: string, renderer: NoticeRenderer) => void;
    }) => void;
  };
  try {
    // Exception to ts-no-dynamic-import: `file` is a fresh temp path
    // computed at test time (a distinct copy of the printed shim per
    // case, so BOUNCER_BIN above never leaks into an already-cached
    // module instance) — there is no static specifier to write here.
    mod = await import(file);
  } finally {
    if (originalBouncerBin === undefined) delete process.env.BOUNCER_BIN;
    else process.env.BOUNCER_BIN = originalBouncerBin;
  }

  // Four fixed, statically-known registration keys (the shim only ever
  // calls `pi.on("tool_call", …)`/`pi.on("session_start", …)`/
  // `pi.on("before_agent_start", …)`/`pi.on("tool_result", …)`) — a plain
  // record, not a Map, per this codebase's own lookup-table convention.
  const handlers: { tool_call?: unknown; session_start?: unknown; before_agent_start?: unknown; tool_result?: unknown; } = {};
  const renderers: Record<string, NoticeRenderer> = {};
  mod.default({
    on: (event, handler) => {
      handlers[event as 'tool_call' | 'session_start' | 'before_agent_start' | 'tool_result'] = handler;
    },
    ...(events === undefined ? {} : { events }),
    registerMessageRenderer: registerMessageRenderer ?? ((customType, renderer) => {
      renderers[customType] = renderer;
    }),
  });
  return {
    toolCall: handlers.tool_call as ToolCallHandler,
    sessionStart: handlers.session_start as SessionStartHandler,
    beforeAgentStart: handlers.before_agent_start as BeforeAgentStartHandler,
    renderers,
    toolResult: handlers.tool_result as ToolResultHandler,
  };
}

// A throwaway "bouncer" stand-in: a POSIX shell script the shim spawns
// exactly as it would the real binary (`spawnSync(BOUNCER, ["run", ...],
// {input, timeout})`) — `body` decides what it prints/exits/sleeps.
async function fakeBouncerScript(body: string): Promise<string> {
  const dir = tmpDir('bouncer-shim-fake-bin-');
  const path = join(dir, 'fake-bouncer.sh');
  await writeFile(path, `#!/bin/sh\n${body}\n`, 'utf8');
  await chmod(path, 0o755);
  return path;
}

describe('pi-agent shim: tool_call — the four fail-closed paths (§ 4)', () => {
  test('spawn impossible (BOUNCER_BIN names a path that does not exist) blocks with a failing-closed reason', async () => {
    const shim = await loadShim('/nonexistent/path/to/bouncer');
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('failing closed');
  });

  test('non-zero exit blocks with a failing-closed reason', async () => {
    const fakePath = await fakeBouncerScript('exit 1');
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('failing closed');
  });

  test('a spawn exceeding the 2s timeout blocks with a failing-closed reason', async () => {
    const fakePath = await fakeBouncerScript('sleep 5');
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('failing closed');
  }, 10_000);

  test('unparseable stdout (not valid JSON) blocks with a failing-closed reason', async () => {
    const fakePath = await fakeBouncerScript('printf "not json {{{"');
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('failing closed');
  });
});

describe('pi-agent shim: tool_call — allow on silence', () => {
  test('empty stdout (exit 0) resolves to undefined — allow, nothing returned', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result).toBeUndefined();
  });
});

describe('pi-agent shim: tool_call — {block} returned as is', () => {
  test('a real deny answer is returned unmodified', async () => {
    const fakePath = await fakeBouncerScript(String.raw`printf '{"block":true,"reason":"rm-rf-dangerous: dangerous target"}'`);
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'rm -rf /' } }, fakeCtx());
    expect(result).toEqual({ block: true, reason: 'rm-rf-dangerous: dangerous target' });
  });
});

// ADR-0006 § 7 (ticket 55): an `ask` is a numbered one-key `ctx.ui.select`
// with Block as the default highlight; only the exact answer "1. Allow"
// lets the call run. Around that dialog (UI only) the shim emits omp's
// `herdr:blocked` on `pi.events` — an observability signal, never policy.
// One reason, one fake bouncer that always answers `{ask, reason}`, one
// tool call to judge.
const ASK_REASON = 'git-protected: confirm before running';
const askingBouncer = (): Promise<string> => fakeBouncerScript(String.raw`printf '{"ask":true,"reason":"${ASK_REASON}"}'`);
const ASK_CALL = { toolName: 'bash', input: { command: 'git push --force' } };
const BLOCKED: ToolCallVerdict = { block: true, reason: ASK_REASON };

// ONE ordered log is fed by both the fake bus's `emit` and the fake
// `ctx.ui.select`, so "before the dialog opens" and "after it settles" are
// observed orderings, never inferred ones. `select` is the dialog's own
// outcome; `opened` settles the moment the dialog is up.
interface Step {
  readonly step: 'emit' | 'select opened';
  readonly channel?: string;
  readonly data?: unknown;
}
const SELECT_OPENED: Step = { step: 'select opened' };
const BLOCKED_ON: Step = {
  step: 'emit',
  channel: 'herdr:blocked',
  data: { active: true, label: 'bouncer: git-protected: confirm before running' },
};
const BLOCKED_OFF: Step = { step: 'emit', channel: 'herdr:blocked', data: { active: false } };

function askRig(select: () => Promise<string | undefined>) {
  const timeline: Step[] = [];
  const { promise: opened, resolve: markOpened } = Promise.withResolvers<void>();
  const events: FakeEvents = {
    emit: (channel, data) => {
      timeline.push({ step: 'emit', channel, data });
    },
  };
  const ctx = fakeCtx({
    ui: {
      select: () => {
        timeline.push(SELECT_OPENED);
        markOpened();
        return select();
      },
      notify: () => {},
    },
  });
  return { timeline, opened, events, ctx };
}

// Every way the dialog can end, with the verdict it must produce.
type AskOutcome = [name: string, select: () => Promise<string | undefined>, verdict: ToolCallVerdict | undefined];
const ACCEPT: AskOutcome = ['accept ("1. Allow")', async () => '1. Allow', undefined];
const DECLINE: AskOutcome = ['decline ("2. Block")', async () => '2. Block', BLOCKED];
const ASK_OUTCOMES: AskOutcome[] = [
  ACCEPT,
  DECLINE,
  ['Esc (undefined)', async () => undefined, BLOCKED],
  ['a select that rejects', () => Promise.reject(new Error('dialog failed')), BLOCKED],
  [
    'a select that throws synchronously',
    () => {
      throw new Error('dialog failed');
    },
    BLOCKED,
  ],
];

describe('pi-agent shim: tool_call — {ask, reason} is a numbered select, Block highlighted', () => {
  test('hasUI true: select("bouncer\\n<reason>", ["1. Allow", "2. Block"], { initialIndex: 1 }); "1. Allow" lets the call run', async () => {
    const shim = await loadShim(await askingBouncer());
    let selectCalledWith: readonly [string, readonly string[], unknown] | undefined;
    const ctx = fakeCtx({
      ui: {
        select: async (title, options, opts) => {
          selectCalledWith = [title, options, opts];
          return '1. Allow';
        },
        notify: () => {},
      },
    });
    const result = await shim.toolCall(ASK_CALL, ctx);
    expect(result).toBeUndefined();
    expect(selectCalledWith).toStrictEqual([
      'bouncer\ngit-protected: confirm before running',
      ['1. Allow', '2. Block'],
      { initialIndex: 1 },
    ]);
  });

  test.each<string | undefined>(['2. Block', undefined, 'Allow', '1. allow', '', '1. Allow ', 'Yes'])(
    'the answer %j is not exactly "1. Allow": blocked with the same reason',
    async (answer) => {
      const shim = await loadShim(await askingBouncer());
      const ctx = fakeCtx({ ui: { select: async () => answer, notify: () => {} } });
      expect(await shim.toolCall(ASK_CALL, ctx)).toStrictEqual(BLOCKED);
    },
  );
});

describe('pi-agent shim: tool_call — {ask, reason} signals herdr:blocked around the dialog', () => {
  test('the signal goes up before the dialog opens and comes down only once the answer arrives', async () => {
    const answer = Promise.withResolvers<string | undefined>();
    const rig = askRig(() => answer.promise);
    const shim = await loadShim(await askingBouncer(), rig.events);
    const pending = shim.toolCall(ASK_CALL, rig.ctx);
    await rig.opened;
    expect(rig.timeline).toStrictEqual([BLOCKED_ON, SELECT_OPENED]);
    answer.resolve('1. Allow');
    expect(await pending).toBeUndefined();
    expect(rig.timeline).toStrictEqual([BLOCKED_ON, SELECT_OPENED, BLOCKED_OFF]);
  });

  test.each(ASK_OUTCOMES)('%s: the signal still comes down, after the dialog, and the verdict is untouched',
    async (_outcome, select, verdict) => {
      const rig = askRig(select);
      const shim = await loadShim(await askingBouncer(), rig.events);
      expect(await shim.toolCall(ASK_CALL, rig.ctx)).toStrictEqual(verdict);
      expect(rig.timeline).toStrictEqual([BLOCKED_ON, SELECT_OPENED, BLOCKED_OFF]);
    });

  test('no UI attached (headless -p): blocked without opening a select AND without emitting anything', async () => {
    const rig = askRig(async () => '1. Allow');
    const shim = await loadShim(await askingBouncer(), rig.events);
    expect(await shim.toolCall(ASK_CALL, { ...rig.ctx, hasUI: false })).toStrictEqual(BLOCKED);
    expect(rig.timeline).toStrictEqual([]);
  });
});

// The signal can never get in the way: a `pi` with no bus at all, or a bus
// whose `emit` throws (on the raise AND on the release), changes neither
// whether the dialog opens nor the verdict.
describe('pi-agent shim: tool_call — {ask, reason} survives a missing or broken pi.events', () => {
  const BROKEN_BUSES: [string, FakeEvents | undefined][] = [
    ['pi has no events bus', undefined],
    [
      'pi.events.emit throws',
      {
        emit: () => {
          throw new Error('bus is down');
        },
      },
    ],
  ];
  for (const [bus, events] of BROKEN_BUSES) {
    test.each([ACCEPT, DECLINE])(`${bus}: %s — the dialog still opens once and the verdict is untouched`,
      async (_outcome, select, verdict) => {
        const rig = askRig(select);
        const shim = await loadShim(await askingBouncer(), events);
        expect(await shim.toolCall(ASK_CALL, rig.ctx)).toStrictEqual(verdict);
        expect(rig.timeline).toStrictEqual([SELECT_OPENED]);
      });
  }
});

describe('pi-agent shim: session_start', () => {
  test('a {notify} answer calls ctx.ui.notify with the doctor text, level "warning"', async () => {
    const fakePath = await fakeBouncerScript(String.raw`printf '{"notify":"bouncer doctor: 1 check(s) unprovable"}'`);
    const shim = await loadShim(fakePath);
    let notified: readonly [string, string | undefined] | undefined;
    const ctx = fakeCtx({
      ui: {
        select: async () => undefined,
        notify: (text, level) => {
          notified = [text, level];
        },
      },
    });
    await shim.sessionStart({}, ctx);
    expect(notified).toEqual(['bouncer doctor: 1 check(s) unprovable', 'warning']);
  });

  test('silence (healthy doctor state): ctx.ui.notify is never called', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const shim = await loadShim(fakePath);
    let notifyCalled = false;
    const ctx = fakeCtx({
      ui: {
        select: async () => undefined,
        notify: () => {
          notifyCalled = true;
        },
      },
    });
    await shim.sessionStart({}, ctx);
    expect(notifyCalled).toBe(false);
  });

  test('a fail-closed spawn failure notifies with the same failing-closed reason', async () => {
    const shim = await loadShim('/nonexistent/path/to/bouncer');
    let notified: string | undefined;
    const ctx = fakeCtx({
      ui: {
        select: async () => undefined,
        notify: (text) => {
          notified = text;
        },
      },
    });
    await shim.sessionStart({}, ctx);
    expect(notified).toContain('failing closed');
  });
});

describe('pi-agent shim: before_agent_start (cross-binary notice delivery)', () => {
  test('a pending session_start notice is delivered once, then cleared', async () => {
    const fakePath = await fakeBouncerScript(String.raw`printf '{"notify":"bouncer doctor: 1 check(s) unprovable"}'`);
    const shim = await loadShim(fakePath);
    await shim.sessionStart({}, fakeCtx());
    const first = shim.beforeAgentStart({}, fakeCtx());
    expect(first).toEqual({
      message: { customType: 'bouncer-doctor', content: 'bouncer doctor: 1 check(s) unprovable', display: true },
    });
    const second = shim.beforeAgentStart({}, fakeCtx());
    expect(second).toBeUndefined();
  });

  test('a fail-closed session_start spawn failure is ALSO delivered through before_agent_start', async () => {
    const shim = await loadShim('/nonexistent/path/to/bouncer');
    await shim.sessionStart({}, fakeCtx());
    const result = shim.beforeAgentStart({}, fakeCtx());
    expect(result?.message?.customType).toBe('bouncer-doctor');
    expect(result?.message?.content).toContain('failing closed');
    expect(result?.message?.display).toBe(true);
  });

  test('a healthy (silent) session_start leaves before_agent_start with nothing to deliver', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const shim = await loadShim(fakePath);
    await shim.sessionStart({}, fakeCtx());
    expect(shim.beforeAgentStart({}, fakeCtx())).toBeUndefined();
  });

  test('before_agent_start called before any session_start (e.g. a resumed session) delivers nothing, never throws', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const shim = await loadShim(fakePath);
    expect(shim.beforeAgentStart({}, fakeCtx())).toBeUndefined();
  });
});

describe('pi-agent shim: folded doctor notice (display only)', () => {
  // Test data, not doctor's wording: the second headline carries wide
  // characters, a tab and an unbreakable token to stress the wrap.
  const HEADLINES = [
    'bouncer doctor: 2 active override(s)/relaxation(s) — the effective policy is relaxed from the vetted baseline:',
    'bouncer doctor: 中文 🙂\tsecond headline a_very_long_unbroken_token_longer_than_any_narrow_terminal_width_xxxxxxxxxxxxxxxxxx',
  ];
  const NOTICE = [
    HEADLINES[0],
    '  - command.git.ask_flags:worktree (relax) — worktree autonome pour les leads multi-agents',
    '  - command.git.ask_flags:branch (relax) — cleanup des branches sous-agents après merge',
    HEADLINES[1],
    '  - wiring:shim: unprovable',
  ].join('\n');
  // Wraps in escape codes like the hosts' own themes: they take no cells.
  const THEME = { fg: (_color: string, text: string) => `\u001B[33m${text}\u001B[39m` };

  async function noticeShim(): Promise<LoadedShim> {
    return loadShim(await fakeBouncerScript(`cat <<'EOF'\n${JSON.stringify({ notify: NOTICE })}\nEOF`));
  }

  test('the toast keeps every headline and counts the detail lines; the model still receives the full notice', async () => {
    const shim = await noticeShim();
    const toasts: string[] = [];
    await shim.sessionStart({}, fakeCtx({ ui: { select: async () => undefined, notify: (text) => toasts.push(text) } }));
    const lines = (toasts[0] ?? '').split('\n');
    expect(lines.slice(0, -1)).toEqual(HEADLINES);
    expect(lines.at(-1)).toMatch(/\b3\b/);
    expect(shim.beforeAgentStart({}, fakeCtx())?.message?.content).toBe(NOTICE);
  });

  test('collapsed, the bouncer-doctor message renders the same fold, every line within the terminal width', async () => {
    const shim = await noticeShim();
    const component = shim.renderers['bouncer-doctor']?.({ content: NOTICE }, { expanded: false }, THEME);
    if (component === undefined) throw new Error('no collapsed component');
    for (let width = 1; width <= 160; width++) {
      for (const line of component.render(width)) expect(Bun.stringWidth(line)).toBeLessThanOrEqual(width);
    }
    const unwrapped = component.render(1000).map((line) => Bun.stripANSI(line).trim());
    expect(unwrapped.slice(0, -1)).toEqual(HEADLINES.map((headline) => headline.replace('\t', ' ')));
    expect(unwrapped.at(-1)).toMatch(/\b3\b/);
  });

  test('expanded, or with nothing to fold, the message goes back to the host\'s own full rendering', async () => {
    const shim = await noticeShim();
    const render = shim.renderers['bouncer-doctor'];
    expect(render?.({ content: NOTICE }, { expanded: true }, THEME)).toBeUndefined();
    expect(render?.({ content: 'bouncer: spawn failed — failing closed' }, { expanded: false }, THEME)).toBeUndefined();
  });

  test('a host whose registerMessageRenderer throws still loads every guard handler', async () => {
    const fakePath = await fakeBouncerScript(String.raw`printf '{"block":true,"reason":"rule: why"}'`);
    const shim = await loadShim(fakePath, undefined, () => {
      throw new Error('renderer registry unavailable');
    });
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result).toEqual({ block: true, reason: 'rule: why' });
  });
});

describe('pi-agent shim: BOUNCER_PROBE_LOG (probe-phase stdin capture)', () => {
  test('appends the exact JSON payload sent to bouncer, one line, before the spawn', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const logDir = tmpDir('bouncer-shim-probe-log-');
    const logPath = join(logDir, 'stdin.log');
    const shim = await loadShim(fakePath);
    const originalProbeLog = process.env.BOUNCER_PROBE_LOG;
    process.env.BOUNCER_PROBE_LOG = logPath;
    try {
      await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      const logged = await readFile(logPath, 'utf8');
      expect(JSON.parse(logged.trim())).toEqual({
        event: 'tool_call',
        toolName: 'bash',
        input: { command: 'echo hi' },
        session: 'fake-session',
        cwd: '/tmp/probe-cwd',
      });
    } finally {
      if (originalProbeLog === undefined) delete process.env.BOUNCER_PROBE_LOG;
      else process.env.BOUNCER_PROBE_LOG = originalProbeLog;
    }
  });

  test('unset BOUNCER_PROBE_LOG: no file is written, no error', async () => {
    const fakePath = await fakeBouncerScript('exit 0');
    const shim = await loadShim(fakePath);
    const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
    expect(result).toBeUndefined();
  });
});

// Rule 4 (ADR-0008): every tool's result goes to bouncer; its `{ content }`
// answer comes back as is, silence keeps the output, and every failure
// withholds it — the handler never throws (a throwing handler keeps the
// ORIGINAL output on both binaries, measured 2026-10-13).
// The shim carries its own copy of the text (it imports nothing from
// bouncer); the source's constant is the reference it must match.
const WITHHELD = { content: [{ type: 'text', text: POST_TOOL_WITHHELD }] };
const RESULT_EVENT = {
  toolName: 'bash',
  input: { command: 'printenv' },
  content: [{ type: 'text', text: 'some output' }],
  isError: false,
  details: { truncation: { content: 'some output' } },
};

describe('pi-agent shim: tool_result — every failure withholds the output', () => {
  test.each([
    ['spawn impossible (BOUNCER_BIN names a path that does not exist)', null],
    ['non-zero exit', 'exit 1'],
    ['unparseable stdout (not valid JSON)', 'printf "not json {{{"'],
    ['a JSON answer with no content array', String.raw`printf '{"block":true,"reason":"x"}'`],
  ])('%s → the withheld content', async (_label, body) => {
    const shim = await loadShim(body === null ? '/nonexistent/path/to/bouncer' : await fakeBouncerScript(body));
    expect(await shim.toolResult(RESULT_EVENT, fakeCtx())).toEqual(WITHHELD);
  });

  test('a spawn exceeding the 2s timeout → the withheld content', async () => {
    const shim = await loadShim(await fakeBouncerScript('sleep 5'));
    expect(await shim.toolResult(RESULT_EVENT, fakeCtx())).toEqual(WITHHELD);
  }, 10_000);

  test('a context that throws while the payload is built → the withheld content, never a throw', async () => {
    const shim = await loadShim(await fakeBouncerScript('exit 0'));
    const ctx = fakeCtx({
      sessionManager: {
        getSessionId: () => {
          throw new Error('session manager gone');
        },
      },
    });
    expect(await shim.toolResult(RESULT_EVENT, ctx)).toEqual(WITHHELD);
  });
});

describe('pi-agent shim: tool_result — silence and answers', () => {
  test('empty stdout (exit 0) → undefined: the output is kept as the harness has it', async () => {
    const shim = await loadShim(await fakeBouncerScript('exit 0'));
    expect(await shim.toolResult(RESULT_EVENT, fakeCtx())).toBeUndefined();
  });

  test('a { content } answer is returned as is — the shim judges nothing of what it carries', async () => {
    // Whatever bouncer answers is what the model gets: the shim neither
    // redacts nor inspects (no policy, ADR-0006 § 7), so text the shim
    // could have judged comes back untouched.
    const content = [{ type: 'text', text: 'token=[redacted: FAKE_API_TOKEN] and a raw-looking value Zq7-made-up-0042' }];
    const shim = await loadShim(await fakeBouncerScript(`printf '%s' '${JSON.stringify({ content })}'`));
    expect(await shim.toolResult(RESULT_EVENT, fakeCtx())).toEqual({ content });
  });

  test('relays { event, toolName, input, content, isError, session, cwd } — never details', async () => {
    const stdinPath = join(tmpDir('bouncer-shim-relay-'), 'stdin.json');
    const shim = await loadShim(await fakeBouncerScript(`cat > '${stdinPath}'`));
    await shim.toolResult({ ...RESULT_EVENT, isError: true }, fakeCtx());
    expect(JSON.parse(await readFile(stdinPath, 'utf8'))).toEqual({
      event: 'tool_result',
      toolName: 'bash',
      input: { command: 'printenv' },
      content: [{ type: 'text', text: 'some output' }],
      isError: true,
      session: 'fake-session',
      cwd: '/tmp/probe-cwd',
    });
  });

  test('BOUNCER_PROBE_LOG records a result\'s shape and size only — never the output text', async () => {
    const logPath = join(tmpDir('bouncer-shim-probe-log-'), 'stdin.log');
    const shim = await loadShim(await fakeBouncerScript('exit 0'));
    const content = [{ type: 'text', text: 'token=Zq7-made-up-0042 — é' }, { type: 'image', data: 'iVBORw0KGgo=', mimeType: 'image/png' }];
    const originalProbeLog = process.env.BOUNCER_PROBE_LOG;
    process.env.BOUNCER_PROBE_LOG = logPath;
    try {
      await shim.toolResult({ ...RESULT_EVENT, content }, fakeCtx());
      const logged = await readFile(logPath, 'utf8');
      expect(JSON.parse(logged.trim())).toEqual({
        event: 'tool_result',
        toolName: 'bash',
        isError: false,
        session: 'fake-session',
        cwd: '/tmp/probe-cwd',
        contentTypes: ['text', 'image'],
        contentBytes: Buffer.byteLength(JSON.stringify(content)),
      });
      for (const leak of ['Zq7-made-up-0042', 'iVBORw0KGgo=']) expect(logged).not.toContain(leak);
    } finally {
      if (originalProbeLog === undefined) delete process.env.BOUNCER_PROBE_LOG;
      else process.env.BOUNCER_PROBE_LOG = originalProbeLog;
    }
  });

  test('an answer above Node\'s 1 MiB spawnSync default still comes back (a transport limit, not a withheld output)', async () => {
    const dir = tmpDir('bouncer-shim-big-answer-');
    const answerPath = join(dir, 'answer.json');
    const content = [{ type: 'text', text: 'x'.repeat(3 * 1024 * 1024) }];
    await writeFile(answerPath, JSON.stringify({ content }), 'utf8');
    const shim = await loadShim(await fakeBouncerScript(`cat '${answerPath}'`));
    expect(await shim.toolResult(RESULT_EVENT, fakeCtx())).toEqual({ content });
  });
});
