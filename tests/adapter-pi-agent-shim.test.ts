// The printed pi-agent/omp shim (policy/harness/pi-agent.shim.ts,
// ADR-0006 § 7, ticket 15c) — proved by spawning the REAL BUILT binary
// (`bun run build`, same discipline as tests/adapter-canary.test.ts's own
// "a freshly built binary leaves the canary silent") to print the shim,
// writing it to a fresh temp file per case (a distinct absolute path so
// Bun's module cache never serves a stale `BOUNCER` from an earlier
// case), and dynamically importing it with a fake `pi` host that just
// records the two handlers it registers. Every assertion drives the
// REAL shim module, never a hand-reimplemented copy of its logic.

import { describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PROJECT_ROOT = join(import.meta.dir, '..');

interface FakeCtx {
  hasUI: boolean;
  cwd?: string;
  sessionManager?: { getSessionId?: () => string | undefined; };
  ui: { confirm: (title: string, text: string) => Promise<boolean>; notify: (text: string, level?: string) => void; };
}

type ToolCallHandler = (event: { toolName: string; input: unknown; },
  ctx: FakeCtx) => Promise<{ block?: boolean; reason?: string; } | undefined>;
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
    ui: { confirm: async () => true, notify: () => {} },
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
// contract.
async function loadShim(bouncerBin: string): Promise<{ shim: LoadedShim; cleanup: () => Promise<void>; }> {
  await ensureBuilt();
  const printed = Bun.spawn([join(PROJECT_ROOT, 'dist', 'bouncer'), 'harness', 'shim', 'pi-agent'], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const source = await new Response(printed.stdout).text();
  expect(await printed.exited).toBe(0);
  expect(source).toContain('const BOUNCER = process.env.BOUNCER_BIN');

  const dir = await mkdtemp(join(tmpdir(), 'bouncer-shim-test-'));
  const file = join(dir, 'bouncer.ts');
  await writeFile(file, source, 'utf8');

  const originalBouncerBin = process.env.BOUNCER_BIN;
  process.env.BOUNCER_BIN = bouncerBin;
  let mod: { default: (pi: { on: (event: string, handler: unknown) => void; }) => void; };
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
  });
  const shim: LoadedShim = {
    toolCall: handlers.tool_call as ToolCallHandler,
    sessionStart: handlers.session_start as SessionStartHandler,
    beforeAgentStart: handlers.before_agent_start as BeforeAgentStartHandler,
  };
  return { shim, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// A throwaway "bouncer" stand-in: a POSIX shell script the shim spawns
// exactly as it would the real binary (`spawnSync(BOUNCER, ["run", ...],
// {input, timeout})`) — `body` decides what it prints/exits/sleeps.
async function fakeBouncerScript(body: string): Promise<{ path: string; cleanup: () => Promise<void>; }> {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-shim-fake-bin-'));
  const path = join(dir, 'fake-bouncer.sh');
  await writeFile(path, `#!/bin/sh\n${body}\n`, 'utf8');
  await chmod(path, 0o755);
  return { path, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

describe('pi-agent shim: tool_call — the four fail-closed paths (§ 4)', () => {
  test('spawn impossible (BOUNCER_BIN names a path that does not exist) blocks with a failing-closed reason', async () => {
    const { shim, cleanup } = await loadShim('/nonexistent/path/to/bouncer');
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('failing closed');
    } finally {
      await cleanup();
    }
  });

  test('non-zero exit blocks with a failing-closed reason', async () => {
    const fake = await fakeBouncerScript('exit 1');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('failing closed');
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('a spawn exceeding the 2s timeout blocks with a failing-closed reason', async () => {
    const fake = await fakeBouncerScript('sleep 5');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('failing closed');
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  }, 10_000);

  test('unparseable stdout (not valid JSON) blocks with a failing-closed reason', async () => {
    const fake = await fakeBouncerScript('printf "not json {{{"');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('failing closed');
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});

describe('pi-agent shim: tool_call — allow on silence', () => {
  test('empty stdout (exit 0) resolves to undefined — allow, nothing returned', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result).toBeUndefined();
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});

describe('pi-agent shim: tool_call — {block} returned as is', () => {
  test('a real deny answer is returned unmodified', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"block":true,"reason":"rm-rf-dangerous: dangerous target"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'rm -rf /' } }, fakeCtx());
      expect(result).toEqual({ block: true, reason: 'rm-rf-dangerous: dangerous target' });
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});

describe('pi-agent shim: tool_call — {ask, reason} degrades through ctx.ui.confirm', () => {
  test('hasUI true, confirm resolves true (accept): the call runs, nothing returned', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"ask":true,"reason":"git-protected: confirm before running"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      let confirmCalledWith: readonly [string, string] | undefined;
      const ctx = fakeCtx({
        ui: {
          confirm: async (title, text) => {
            confirmCalledWith = [title, text];
            return true;
          },
          notify: () => {},
        },
      });
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'git push --force' } }, ctx);
      expect(result).toBeUndefined();
      expect(confirmCalledWith).toEqual(['bouncer', 'git-protected: confirm before running']);
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('hasUI true, confirm resolves false (decline): blocked with the same reason', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"ask":true,"reason":"git-protected: confirm before running"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const ctx = fakeCtx({ ui: { confirm: async () => false, notify: () => {} } });
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'git push --force' } }, ctx);
      expect(result).toEqual({ block: true, reason: 'git-protected: confirm before running' });
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('no UI attached (headless -p): blocked WITHOUT ever awaiting ctx.ui.confirm', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"ask":true,"reason":"git-protected: confirm before running"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const ctx = fakeCtx({
        hasUI: false,
        ui: {
          confirm: () => {
            throw new Error('confirm must never be called when hasUI is false');
          },
          notify: () => {},
        },
      });
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'git push --force' } }, ctx);
      expect(result).toEqual({ block: true, reason: 'git-protected: confirm before running' });
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});

describe('pi-agent shim: session_start', () => {
  test('a {notify} answer calls ctx.ui.notify with the doctor text, level "warning"', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"notify":"bouncer doctor: 1 check(s) unprovable"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      let notified: readonly [string, string | undefined] | undefined;
      const ctx = fakeCtx({
        ui: {
          confirm: async () => true,
          notify: (text, level) => {
            notified = [text, level];
          },
        },
      });
      await shim.sessionStart({}, ctx);
      expect(notified).toEqual(['bouncer doctor: 1 check(s) unprovable', 'warning']);
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('silence (healthy doctor state): ctx.ui.notify is never called', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      let notifyCalled = false;
      const ctx = fakeCtx({
        ui: {
          confirm: async () => true,
          notify: () => {
            notifyCalled = true;
          },
        },
      });
      await shim.sessionStart({}, ctx);
      expect(notifyCalled).toBe(false);
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('a fail-closed spawn failure notifies with the same failing-closed reason', async () => {
    const { shim, cleanup } = await loadShim('/nonexistent/path/to/bouncer');
    try {
      let notified: string | undefined;
      const ctx = fakeCtx({
        ui: {
          confirm: async () => true,
          notify: (text) => {
            notified = text;
          },
        },
      });
      await shim.sessionStart({}, ctx);
      expect(notified).toContain('failing closed');
    } finally {
      await cleanup();
    }
  });
});

describe('pi-agent shim: before_agent_start (cross-binary notice delivery)', () => {
  test('a pending session_start notice is delivered once, then cleared', async () => {
    const fake = await fakeBouncerScript(String.raw`printf '{"notify":"bouncer doctor: 1 check(s) unprovable"}'`);
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      await shim.sessionStart({}, fakeCtx());
      const first = shim.beforeAgentStart({}, fakeCtx());
      expect(first).toEqual({
        message: { customType: 'bouncer-doctor', content: 'bouncer doctor: 1 check(s) unprovable', display: true },
      });
      const second = shim.beforeAgentStart({}, fakeCtx());
      expect(second).toBeUndefined();
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('a fail-closed session_start spawn failure is ALSO delivered through before_agent_start', async () => {
    const { shim, cleanup } = await loadShim('/nonexistent/path/to/bouncer');
    try {
      await shim.sessionStart({}, fakeCtx());
      const result = shim.beforeAgentStart({}, fakeCtx());
      expect(result?.message?.customType).toBe('bouncer-doctor');
      expect(result?.message?.content).toContain('failing closed');
      expect(result?.message?.display).toBe(true);
    } finally {
      await cleanup();
    }
  });

  test('a healthy (silent) session_start leaves before_agent_start with nothing to deliver', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      await shim.sessionStart({}, fakeCtx());
      expect(shim.beforeAgentStart({}, fakeCtx())).toBeUndefined();
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });

  test('before_agent_start called before any session_start (e.g. a resumed session) delivers nothing, never throws', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      expect(shim.beforeAgentStart({}, fakeCtx())).toBeUndefined();
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});

describe('pi-agent shim: BOUNCER_PROBE_LOG (probe-phase stdin capture)', () => {
  test('appends the exact JSON payload sent to bouncer, one line, before the spawn', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const logDir = await mkdtemp(join(tmpdir(), 'bouncer-shim-probe-log-'));
    const logPath = join(logDir, 'stdin.log');
    const { shim, cleanup } = await loadShim(fake.path);
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
      await cleanup();
      await fake.cleanup();
      await rm(logDir, { recursive: true, force: true });
    }
  });

  test('unset BOUNCER_PROBE_LOG: no file is written, no error', async () => {
    const fake = await fakeBouncerScript('exit 0');
    const { shim, cleanup } = await loadShim(fake.path);
    try {
      const result = await shim.toolCall({ toolName: 'bash', input: { command: 'echo hi' } }, fakeCtx());
      expect(result).toBeUndefined();
    } finally {
      await cleanup();
      await fake.cleanup();
    }
  });
});
