// Verdict logging: per-account JSONL, rotation, restrictive modes, and the
// specific property AC4 asks for — a conditional-rule allow is logged with
// its rule id, exactly like a deny/ask verdict, even though the tool call
// itself proceeds silently (nothing on stdout).

import { afterEach, describe, expect, test } from 'bun:test';
import { appendFile, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { logVerdict, MAX_LOG_SIZE } from '../src/adapter/log.ts';
import { run } from '../src/adapter/run.ts';
import type { BuildInfo } from '../src/build-info.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { Verdict } from '../src/types.ts';
import { tmpDir } from './tmp.ts';

const CLAUDE_CODE_HARNESS = BASELINE.rules.harness.find((h) => h.id === 'claude-code')!;
const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;

afterEach(() => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
});

function logPathFor(accountDir: string): string {
  return join(accountDir, 'logs', 'hooks', 'bouncer.log');
}

const BLOCK: Verdict = {
  verdict: 'block',
  ruleId: 'rm-rf-dangerous',
  reason: 'rm -rf targeting a dangerous path: /',
  target: 'rm -rf /',
};
const DIRTY_BUILD: BuildInfo = { sha: 'fixture', dirty: true, date: '2026-01-01T00:00Z' };

describe('logVerdict: JSONL entry shape', () => {
  test('writes family, verdict, rule, target, build, and policy provenance', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    await logVerdict('command', { toolName: 'Bash', sessionId: 'sess-1' }, BLOCK, CLAUDE_CODE_HARNESS);

    const content = await readFile(logPathFor(accountDir), 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.family).toBe('command');
    expect(entry.verdict).toBe('block');
    expect(entry.rule_id).toBe('rm-rf-dangerous');
    expect(entry.session_id).toBe('sess-1');
    expect(entry.tool_name).toBe('Bash');
    expect(entry.harness).toBe('claude-code');
    expect(typeof entry.timestamp).toBe('string');
    expect(entry.build).toBe('source');
    expect(entry.policy).toMatch(/^[0-9a-f]{12}$/);
  });

  test('writes the dirty build identity rather than the ambiguous bare SHA', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    await logVerdict('command', { toolName: 'Bash', sessionId: 'sess-1' }, BLOCK, CLAUDE_CODE_HARNESS, undefined, undefined, DIRTY_BUILD);

    const entry = JSON.parse((await readFile(logPathFor(accountDir), 'utf-8')).trim());
    expect(entry.build).toBe('fixture-dirty');
  });

  test('the log file is created with restrictive mode (0600)', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    await logVerdict('command', { toolName: 'Bash', sessionId: null }, BLOCK, CLAUDE_CODE_HARNESS);

    const mode = (await stat(logPathFor(accountDir))).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});

describe('logVerdict: ticket 08 — the shadow "mode" field', () => {
  test('mode: "shadow" is passed through, tagged on the entry', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    await logVerdict('command', { toolName: 'Bash', sessionId: null }, BLOCK, CLAUDE_CODE_HARNESS, undefined, 'shadow');

    const entry = JSON.parse((await readFile(logPathFor(accountDir), 'utf-8')).trim());
    expect(entry.mode).toBe('shadow');
  });

  test('a normal (non-shadow) call carries no "mode" key at all', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    await logVerdict('command', { toolName: 'Bash', sessionId: null }, BLOCK, CLAUDE_CODE_HARNESS);

    const entry = JSON.parse((await readFile(logPathFor(accountDir), 'utf-8')).trim());
    expect('mode' in entry).toBe(false);
  });
});

describe('logVerdict: per-account routing (two accounts, two logs)', () => {
  test('two different CLAUDE_CONFIG_DIR values never share a log file', async () => {
    const accountA = tmpDir('bouncer-log-test-');
    const accountB = tmpDir('bouncer-log-test-');

    process.env.CLAUDE_CONFIG_DIR = accountA;
    await logVerdict('command', { toolName: 'Bash', sessionId: null }, BLOCK, CLAUDE_CODE_HARNESS);

    process.env.CLAUDE_CONFIG_DIR = accountB;
    await logVerdict('command', { toolName: 'Bash', sessionId: null }, { ...BLOCK, ruleId: 'sudo' }, CLAUDE_CODE_HARNESS);

    const entryA = JSON.parse((await readFile(logPathFor(accountA), 'utf-8')).trim());
    const entryB = JSON.parse((await readFile(logPathFor(accountB), 'utf-8')).trim());
    expect(entryA.rule_id).toBe('rm-rf-dangerous');
    expect(entryB.rule_id).toBe('sudo');
  });
});

describe('logVerdict: rotation', () => {
  test('rotates the log file once it exceeds MAX_LOG_SIZE', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;
    const logFile = logPathFor(accountDir);

    // Force the file past the rotation threshold, then log once more.
    await logVerdict('command', { toolName: 'Bash', sessionId: null }, BLOCK, CLAUDE_CODE_HARNESS);
    await appendFile(logFile, 'x'.repeat(MAX_LOG_SIZE));

    await logVerdict('command', { toolName: 'Bash', sessionId: null }, { ...BLOCK, ruleId: 'after-rotation' }, CLAUDE_CODE_HARNESS);

    const rotated = await stat(`${logFile}.1`).catch(() => null);
    expect(rotated).not.toBeNull();

    const freshContent = await readFile(logFile, 'utf-8');
    const lastEntry = JSON.parse(freshContent.trim().split('\n').at(-1)!);
    expect(lastEntry.rule_id).toBe('after-rotation');
  });
});

describe('run(): conditional-rule allows are logged with their rule id (AC4)', () => {
  test('a ratified git grammar (apply --check) is silent on stdout but logged as observe', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'git apply --check p.diff' },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull(); // the tool call proceeds silently — nothing to the model

    const content = await readFile(logPathFor(accountDir), 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.verdict).toBe('observe');
    expect(entry.rule_id).toBe('git-conditional-apply');
  });

  test('an unconditionally safe command (git status) is not logged at all', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'git status' },
    });
    await run(envelope);

    const logged = await stat(logPathFor(accountDir)).catch(() => null);
    expect(logged).toBeNull();
  });

  test('a deny verdict carries its dirty build identity through run()', async () => {
    const accountDir = tmpDir('bouncer-log-test-');
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    await run(envelope, { build: DIRTY_BUILD });

    const entry = JSON.parse((await readFile(logPathFor(accountDir), 'utf-8')).trim());
    expect(entry.verdict).toBe('block');
    expect(entry.rule_id).toBe('rm-rf-dangerous');
    expect(entry.build).toBe('fixture-dirty');
  });
});
