// The env-value guard through run(): the protocol seam, the audit
// log, stdout/stderr, the baseline retry and the overlay overrides. Every name
// and value is made up, and the environment the guard reads is handed to run()
// as `options.env` — never the machine's (tests/setup.ts also drops the
// protected names from this process).

import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as neutralCall from '../src/adapter/neutral-call.ts';
import { run } from '../src/adapter/run.ts';
import type { EnvRecord } from '../src/env-value-rules.ts';
import { tmpDir } from './tmp.ts';

const VALUE = 'Zq7-made-up-0042';
const ENV: EnvRecord = { FAKE_API_TOKEN: VALUE, HOME: VALUE };
const b64 = (value: string): string => Buffer.from(value).toString('base64');
const hex = (value: string): string => Buffer.from(value).toString('hex');
// Every spelling of the value the guard looks for, plus the unpadded base64.
const SPELLINGS = [VALUE, b64(VALUE), b64(VALUE).replaceAll('=', ''), hex(VALUE), hex(VALUE).toUpperCase()];

// The account directories the harnesses log under, pointed at a throwaway
// account for each test and restored after.
const ACCOUNT_VARS = ['HOME', 'CLAUDE_CONFIG_DIR', 'PI_CODING_AGENT_DIR', 'CODEX_HOME'] as const;
const SAVED = ACCOUNT_VARS.map((name) => [name, process.env[name]] as const);
let accountDir: string;

beforeEach(() => {
  // A fresh account per test: its own log, its own overlay directory.
  accountDir = tmpDir('bouncer-env-value-');
  process.env.HOME = accountDir;
  process.env.CLAUDE_CONFIG_DIR = join(accountDir, '.claude');
  process.env.PI_CODING_AGENT_DIR = join(accountDir, '.pi');
  process.env.CODEX_HOME = join(accountDir, '.codex');
});

afterEach(() => {
  for (const [name, saved] of SAVED) {
    if (saved === undefined) delete process.env[name];
    else process.env[name] = saved;
  }
});

const logPath = (dir = '.claude'): string => join(accountDir, dir, 'logs', 'hooks', 'bouncer.log');

async function readLog(dir = '.claude'): Promise<string> {
  return readFile(logPath(dir), 'utf-8').catch(() => '');
}

function claudeCode(toolName: string, toolInput: Record<string, unknown>): string {
  return JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: toolInput });
}

function piAgent(toolName: string, input: Record<string, unknown>): string {
  return JSON.stringify({ event: 'tool_call', toolName, input, session: 'session-1', cwd: null });
}

function decisionOf(stdout: string | null): { decision: string; reason: string; } | null {
  if (stdout === null) return null;
  const { hookSpecificOutput } = JSON.parse(stdout);
  return { decision: hookSpecificOutput.permissionDecision, reason: hookSpecificOutput.permissionDecisionReason };
}

describe('env-value guard: claude-code surfaces', () => {
  test.each(SPELLINGS)('Write.content carrying %s is denied, naming the variable', async (spelling) => {
    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/out.ts', content: `const x = "${spelling}";` }), {
      env: ENV,
    });
    const verdict = decisionOf(stdout);
    expect(verdict?.decision).toBe('deny');
    expect(verdict?.reason).toContain('env-value');
    expect(verdict?.reason).toContain('FAKE_API_TOKEN');
    for (const secret of SPELLINGS) expect(stdout).not.toContain(secret);
  });

  test('Edit.new_string is judged; Edit.old_string is not', async () => {
    const denied = await run(claudeCode('Edit', { file_path: '/tmp/a.ts', old_string: 'a', new_string: VALUE }), { env: ENV });
    expect(decisionOf(denied.stdout)?.decision).toBe('deny');
    const silent = await run(claudeCode('Edit', { file_path: '/tmp/a.ts', old_string: VALUE, new_string: 'clean' }), {
      env: ENV,
    });
    expect(silent.stdout).toBeNull();
  });

  test('a MultiEdit entry is judged', async () => {
    const { stdout } = await run(
      claudeCode('MultiEdit', {
        file_path: '/tmp/a.ts',
        edits: [{ old_string: 'a', new_string: 'b' }, { old_string: 'c', new_string: `x ${hex(VALUE)} y` }],
      }),
      { env: ENV },
    );
    expect(decisionOf(stdout)?.decision).toBe('deny');
  });

  test('NotebookEdit has no text selector: not judged', async () => {
    const { stdout } = await run(
      claudeCode('NotebookEdit', { notebook_path: '/tmp/n.ipynb', new_source: VALUE, edit_mode: 'replace' }),
      { env: ENV },
    );
    expect(stdout).toBeNull();
  });

  test('a write without the value, or the value under an unprotected name only, is silent', async () => {
    expect((await run(claudeCode('Write', { file_path: '/tmp/a.ts', content: 'clean' }), { env: ENV })).stdout).toBeNull();
    expect((await run(claudeCode('Write', { file_path: '/tmp/a.ts', content: VALUE }), { env: { HOME: VALUE } })).stdout)
      .toBeNull();
  });

  test('a regex-matching token also in the environment is still named: the env-value hit leads the tie', async () => {
    const token = `ghp_${'a1B2'.repeat(9)}`;
    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/a.ts', content: token }), {
      env: { GITHUB_TOKEN: token },
    });
    expect(decisionOf(stdout)?.reason).toContain('env-value');
    expect(decisionOf(stdout)?.reason).toContain('GITHUB_TOKEN');
  });
});

describe('env-value guard: pi-agent surfaces', () => {
  const options = { harness: 'pi-agent', env: ENV } as const;

  test('write.content is judged', async () => {
    const { stdout } = await run(piAgent('write', { path: '/tmp/a.ts', content: `k=${VALUE}` }), options);
    expect(JSON.stringify(stdout)).toContain('FAKE_API_TOKEN');
  });

  test('edit through the hashline codec: a `+` row is judged, a context row is not', async () => {
    const denied = await run(piAgent('edit', { input: `[/tmp/a.ts#A1B2]\nPUT 1.=1:\n+key = ${b64(VALUE)}` }), options);
    expect(JSON.stringify(denied.stdout)).toContain('FAKE_API_TOKEN');
    const silent = await run(piAgent('edit', { input: `[/tmp/a.ts#A1B2]\nPUT 1.=1:\n+clean\n- ${VALUE}` }), options);
    expect(silent.stdout).toBeNull();
  });

  test('pi\'s own edit shape: newText is judged, oldText is not', async () => {
    const denied = await run(piAgent('edit', { path: '/tmp/a.ts', edits: [{ oldText: 'a', newText: VALUE }] }), options);
    expect(JSON.stringify(denied.stdout)).toContain('FAKE_API_TOKEN');
    const silent = await run(piAgent('edit', { path: '/tmp/a.ts', edits: [{ oldText: VALUE, newText: 'clean' }] }), options);
    expect(silent.stdout).toBeNull();
  });
});

describe('env-value guard: codex surface', () => {
  const patch = (body: string): string =>
    JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'apply_patch',
      tool_input: { command: `*** Begin Patch\n*** Update File: src/a.ts\n@@\n${body}\n*** End Patch` },
      session_id: 'session-1',
      cwd: '/tmp/project',
    });

  test('an added hunk line is judged; a removed one is not', async () => {
    const denied = await run(patch(`-old\n+key = ${VALUE}`), { harness: 'codex', env: ENV });
    expect(denied.stdout).toContain('FAKE_API_TOKEN');
    const silent = await run(patch(`-key = ${VALUE}\n+key = clean`), { harness: 'codex', env: ENV });
    expect(silent.stdout).toBeNull();
  });
});

describe('env-value guard: the value never leaves the process', () => {
  let stderrLines: string[];
  const spies: { mockRestore: () => void; }[] = [];

  beforeEach(() => {
    stderrLines = [];
    spies.push(
      spyOn(console, 'error').mockImplementation((...args: unknown[]) => void stderrLines.push(args.join(' '))),
      spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
        stderrLines.push(String(chunk));
        return true;
      }) as typeof process.stderr.write),
    );
  });

  afterEach(() => {
    for (const spy of spies.splice(0)) spy.mockRestore();
  });

  function expectNoValueAnywhere(...surfaces: readonly (string | null)[]): void {
    for (const surface of [...surfaces, ...stderrLines]) {
      for (const secret of SPELLINGS) expect(surface ?? '').not.toContain(secret);
    }
  }

  test.each(SPELLINGS)('a blocked write of %s: the log names the variable and holds no spelling of the value', async (spelling) => {
    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/out.ts', content: `k = ${spelling}` }), { env: ENV });
    expect(decisionOf(stdout)?.decision).toBe('deny');

    const log = await readLog();
    const entry = JSON.parse(log.trim().split('\n').at(-1)!);
    expect(entry).toMatchObject({
      family: 'write-secret',
      verdict: 'block',
      rule_id: 'env-value',
      target: '/tmp/out.ts',
      env_vars: ['FAKE_API_TOKEN'],
    });
    expectNoValueAnywhere(log, stdout);
  });

  test('a path that carries the value is withheld from the log target', async () => {
    const { stdout } = await run(claudeCode('Write', { file_path: `/tmp/${VALUE}.txt`, content: VALUE }), { env: ENV });
    expect(decisionOf(stdout)?.decision).toBe('deny');
    const log = await readLog();
    expect(JSON.parse(log.trim().split('\n').at(-1)!).target).toStartWith('(path withheld');
    expectNoValueAnywhere(log, stdout);
  });

  test('the same holds in shadow mode (logged, nothing on stdout)', async () => {
    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/out.ts', content: VALUE }), { env: ENV, shadow: true });
    expect(stdout).toBeNull();
    const log = await readLog();
    expect(JSON.parse(log.trim().split('\n').at(-1)!)).toMatchObject({
      rule_id: 'env-value',
      mode: 'shadow',
      env_vars: ['FAKE_API_TOKEN'],
    });
    expectNoValueAnywhere(log);
  });

  test('the dispatcher throws while the environment is read: the baseline retry still blocks, and nothing carries the value', async () => {
    // The first dispatcher (the overlay-aware one) throws while it reads the
    // environment; the retry builds the embedded-baseline dispatcher over the
    // SAME record and must keep the guard.
    let reads = 0;
    const flaky: Record<string, string> = {};
    Object.defineProperty(flaky, 'FAKE_API_TOKEN', {
      enumerable: true,
      get() {
        reads += 1;
        if (reads === 1) throw new Error('simulated failure while reading the environment');
        return VALUE;
      },
    });

    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/out.ts', content: `k = ${VALUE}` }), { env: flaky });
    const verdict = decisionOf(stdout);
    expect(verdict?.decision).toBe('deny');
    expect(verdict?.reason).toContain('FAKE_API_TOKEN');

    const log = await readLog();
    const entries = log.trim().split('\n').map((line) => JSON.parse(line));
    const warning = entries.find((entry) => entry.kind === 'policy-warning');
    expect(warning?.message).toBe(
      'dispatch failed, retrying with the embedded baseline: simulated failure while reading the environment',
    );
    expect(entries.at(-1)).toMatchObject({ rule_id: 'env-value', env_vars: ['FAKE_API_TOKEN'] });
    expectNoValueAnywhere(log, stdout);
  });

  test('the dispatcher throws mid-judgement with a message that embeds the written text: the warning withholds it and the guard still blocks', async () => {
    // An error whose message carries the input being judged — here the written
    // text, the value in all three spellings — must not reach the log through
    // the retry's policy-warning. The spy throws once, then passes through.
    const content = `k = ${VALUE} ${b64(VALUE)} ${hex(VALUE)}`;
    spies.push(
      spyOn(neutralCall, 'buildNeutralCall').mockImplementationOnce((_protocol, _toolName, toolInput) => {
        throw new Error(`could not judge ${JSON.stringify(toolInput)}`);
      }),
    );

    const { stdout } = await run(claudeCode('Write', { file_path: '/tmp/out.ts', content }), { env: ENV });

    const verdict = decisionOf(stdout);
    expect(verdict?.decision).toBe('deny');
    expect(verdict?.reason).toContain('FAKE_API_TOKEN');
    const log = await readLog();
    const warning = log.trim().split('\n').map((line) => JSON.parse(line)).find((entry) => entry.kind === 'policy-warning');
    expect(warning?.message).toBe(
      'dispatch failed, retrying with the embedded baseline (error message withheld: it contains the value of a protected environment variable: FAKE_API_TOKEN)',
    );
    expectNoValueAnywhere(log, stdout);
  });

  test('the environment cannot be read at all and the error embeds the value: the warning is withheld, nothing carries the value', async () => {
    const broken: Record<string, string> = {};
    Object.defineProperty(broken, 'FAKE_API_TOKEN', {
      enumerable: true,
      get() {
        throw new Error(`cannot read the environment, last value ${VALUE}`);
      },
    });

    await run(claudeCode('Write', { file_path: '/tmp/out.ts', content: `k = ${VALUE}` }), { env: broken });

    const log = await readLog();
    expect(log).toContain('(error message withheld: the environment could not be scanned)');
    expectNoValueAnywhere(log);
  });
});

describe('env-value guard: a consumer opts out through the env-value row', () => {
  async function overlay(toml: string): Promise<void> {
    const dir = join(accountDir, '.claude', 'bouncer');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'policy.toml'), toml, 'utf-8');
  }
  const write = claudeCode('Write', { file_path: '/tmp/out.ts', content: `k = ${VALUE}` });

  test('baseline: blocks', async () => {
    expect(decisionOf((await run(write, { env: ENV })).stdout)?.decision).toBe('deny');
  });

  test('[[override]] disable: the guard is off', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "disable"\nreason = "fixtures share the dev password"\n');
    expect((await run(write, { env: ENV })).stdout).toBeNull();
  });

  test('[[override]] relax to confirm: asks instead of blocking, still names the variable, still logs the name', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "relax"\nverdict = "confirm"\nreason = "review each write"\n');
    const verdict = decisionOf((await run(write, { env: ENV })).stdout);
    expect(verdict?.decision).toBe('ask');
    expect(verdict?.reason).toContain('FAKE_API_TOKEN');
    expect(JSON.parse((await readLog()).trim().split('\n').at(-1)!)).toMatchObject({ verdict: 'confirm', env_vars: ['FAKE_API_TOKEN'] });
  });

  test('[[override]] replace narrows which texts the guard looks at', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "replace"\nregex = "^only-this$"\nreason = "only one text"\n');
    expect((await run(write, { env: ENV })).stdout).toBeNull();
  });
});
