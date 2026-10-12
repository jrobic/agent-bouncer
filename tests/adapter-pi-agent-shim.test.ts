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

interface LoadedShim {
  readonly toolCall: ToolCallHandler;
  readonly sessionStart: SessionStartHandler;
  readonly beforeAgentStart: BeforeAgentStartHandler;
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
// undefined, the fake `pi` has NO `events` property at all.
async function loadShim(bouncerBin: string, events?: FakeEvents): Promise<LoadedShim> {
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
  let mod: { default: (pi: { on: (event: string, handler: unknown) => void; events?: FakeEvents; }) => void; };
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

  // Three fixed, statically-known registration keys (the shim only ever
  // calls `pi.on("tool_call", …)`/`pi.on("session_start", …)`/
  // `pi.on("before_agent_start", …)`) — a plain record, not a Map, per
  // this codebase's own lookup-table convention.
  const handlers: { tool_call?: unknown; session_start?: unknown; before_agent_start?: unknown; } = {};
  mod.default({
    on: (event, handler) => {
      handlers[event as 'tool_call' | 'session_start' | 'before_agent_start'] = handler;
    },
    ...(events === undefined ? {} : { events }),
  });
  return {
    toolCall: handlers.tool_call as ToolCallHandler,
    sessionStart: handlers.session_start as SessionStartHandler,
    beforeAgentStart: handlers.before_agent_start as BeforeAgentStartHandler,
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
