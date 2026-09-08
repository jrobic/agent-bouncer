// `bouncer audit --diff` at the command-function level (ticket 08,
// code-only scope): real bouncer.log + real TS guard-*.log files on disk
// under a throwaway CLAUDE_CONFIG_DIR, no subprocess spawned. Complements
// tests/adapter-audit-diff.test.ts (the pure diffLogs/render logic).

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseAuditArgs, runAudit } from '../src/cli-commands.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function freshAccountDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-audit-diff-cli-test-'));
  cleanupDirs.push(dir);
  process.env.CLAUDE_CONFIG_DIR = dir;
  return dir;
}

async function writeBouncerLog(accountDir: string, lines: readonly Record<string, unknown>[]): Promise<void> {
  await mkdir(join(accountDir, 'logs', 'hooks'), { recursive: true });
  const text = `${lines.map((l) => JSON.stringify(l)).join('\n')}\n`;
  await writeFile(join(accountDir, 'logs', 'hooks', 'bouncer.log'), text, 'utf8');
}

async function writeTsLog(dir: string, filename: string, lines: readonly Record<string, unknown>[]): Promise<void> {
  await mkdir(join(dir, 'logs', 'hooks'), { recursive: true });
  const text = `${lines.map((l) => JSON.stringify(l)).join('\n')}\n`;
  await writeFile(join(dir, 'logs', 'hooks', filename), text, 'utf8');
}

function shadowVerdict(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    timestamp: '2026-08-10T12:00:00.000Z',
    session_id: 'sess-1',
    tool_name: 'Bash',
    family: 'command',
    verdict: 'block',
    rule_id: 'rm-rf-dangerous',
    target: 'rm -rf /',
    mode: 'shadow',
    ...overrides,
  };
}

function tsDeny(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    timestamp: '2026-08-10T12:00:00.000Z',
    session_id: 'sess-1',
    tool_name: 'Bash',
    decision: 'deny',
    rule_id: 'rm-rf-dangerous',
    target: 'rm -rf /',
    ...overrides,
  };
}

function sectionOf(report: string, heading: string): string {
  const lines = report.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`## ${heading}`));
  if (start === -1) return '';
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('## '));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

describe('parseAuditArgs: --diff / --ts-logs (ticket 08)', () => {
  test('--diff sets the diff flag', () => {
    expect(parseAuditArgs(['--diff'])).toEqual({ options: { days: 30, suggest: false, diff: true, harness: 'claude-code' } });
  });

  test('--diff --ts-logs <dir> carries the override through', () => {
    expect(parseAuditArgs(['--diff', '--ts-logs', '/scratch/other-config'])).toEqual({
      options: { days: 30, suggest: false, diff: true, tsLogsDir: '/scratch/other-config', harness: 'claude-code' },
    });
  });

  test('--diff and --suggest together is an explicit error', () => {
    const result = parseAuditArgs(['--diff', '--suggest']);
    expect(result.options).toBeUndefined();
    expect(result.error).toContain('mutually exclusive');
  });

  test('--ts-logs without --diff is an explicit error', () => {
    const result = parseAuditArgs(['--ts-logs', '/scratch/x']);
    expect(result.options).toBeUndefined();
    expect(result.error).toContain('--ts-logs');
  });

  test('--ts-logs with a missing value is an explicit error', () => {
    const result = parseAuditArgs(['--diff', '--ts-logs']);
    expect(result.options).toBeUndefined();
    expect(result.error).toContain('directory argument');
  });
});

describe('runAudit({ diff: true }): end to end against real files on disk', () => {
  test('a matched pair (same target/tool/decision-bucket) produces NO divergence', async () => {
    const dir = await freshAccountDir();
    await writeBouncerLog(dir, [shadowVerdict()]);
    await writeTsLog(dir, 'command-guard.log', [tsDeny()]);

    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: true });
    expect(ok).toBe(true);
    expect(sectionOf(text, 'TS denied/asked, bouncer would allow')).toContain('none');
    expect(sectionOf(text, 'bouncer would deny/ask, TS allowed')).toContain('none');
    expect(sectionOf(text, 'matched, but verdicts differ')).toContain('none');
  });

  test('a TS deny with no bouncer counterpart reports "bouncer would allow", naming the TS rule id', async () => {
    const dir = await freshAccountDir();
    await writeTsLog(dir, 'command-guard.log', [tsDeny({ target: 'mkfs /dev/sda1', rule_id: 'mkfs' })]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: true });
    const section = sectionOf(text, 'TS denied/asked, bouncer would allow');
    expect(section).toContain('mkfs');
  });

  test('a bouncer shadow block with no TS counterpart reports "TS allowed", naming the bouncer rule id', async () => {
    const dir = await freshAccountDir();
    await writeBouncerLog(dir, [shadowVerdict({ target: 'sudo apt update', rule_id: 'sudo' })]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: true });
    const section = sectionOf(text, 'bouncer would deny/ask, TS allowed');
    expect(section).toContain('sudo');
  });

  test('a matched pair with different verdicts reports a verdict divergence, naming both sides', async () => {
    const dir = await freshAccountDir();
    await writeBouncerLog(dir, [
      shadowVerdict({ verdict: 'confirm', rule_id: 'transcript-backup', target: '/home/user/.claude/transcripts/foo.json' }),
    ]);
    await writeTsLog(dir, 'secret-guard.log', [
      tsDeny({ rule_id: 'transcript-backup', target: '/home/user/.claude/transcripts/foo.json' }),
    ]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: true });
    const section = sectionOf(text, 'matched, but verdicts differ');
    expect(section).toContain('transcript-backup');
    expect(section).toContain('[expected');
    expect(section).toContain('ticket 13');
  });

  test('a plain (non-shadow) bouncer entry is ignored — the diff only compares the shadow window', async () => {
    const dir = await freshAccountDir();
    await writeBouncerLog(dir, [
      { ...shadowVerdict({ target: 'sudo apt update', rule_id: 'sudo' }), mode: undefined },
    ]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: true });
    expect(sectionOf(text, 'bouncer would deny/ask, TS allowed')).toContain('none');
  });

  test('--sessions-only removes CLI-only divergences on both sides and labels each filtered stream', async () => {
    const dir = await freshAccountDir();
    const timestamp = new Date().toISOString();
    await writeBouncerLog(dir, [
      shadowVerdict({ timestamp, session_id: 'session-1', rule_id: 'session-bouncer-rule', target: 'session-bouncer-target' }),
      shadowVerdict({ timestamp, session_id: null, rule_id: 'cli-shadow-rule', target: 'cli-shadow-target' }),
      shadowVerdict({ timestamp, session_id: null, rule_id: 'cli-enforce-rule', target: 'cli-enforce-target', mode: undefined }),
    ]);
    await writeTsLog(dir, 'command-guard.log', [
      tsDeny({ timestamp, session_id: 'session-1', rule_id: 'session-ts-rule', target: 'session-ts-target' }),
      tsDeny({ timestamp, session_id: null, rule_id: 'cli-ts-rule', target: 'cli-ts-target' }),
    ]);

    const filtered = await runAudit({ days: 1, suggest: false, diff: true, sessionsOnly: true });
    expect(filtered.text).toStartWith(
      'bouncer shadow: 1 entries, 1 CLI entries excluded · TS: 1 entries, 1 CLI entries excluded',
    );
    expect(filtered.text).toContain('session-bouncer-rule');
    expect(filtered.text).toContain('session-ts-rule');
    expect(filtered.text).not.toContain('cli-shadow-rule');
    expect(filtered.text).not.toContain('cli-ts-rule');

    const unfiltered = await runAudit({ days: 1, suggest: false, diff: true });
    expect(unfiltered.text).toContain('cli-shadow-rule');
    expect(unfiltered.text).toContain('cli-ts-rule');
    expect(unfiltered.text.split('\n').slice(0, 3).join('\n')).not.toMatch(/exclud/i);
  });

  test('--ts-logs overrides the TS log directory (a DIFFERENT account entirely)', async () => {
    await freshAccountDir(); // sets CLAUDE_CONFIG_DIR — the bouncer-log side of the diff
    const tsDir = await mkdtemp(join(tmpdir(), 'bouncer-audit-diff-ts-'));
    cleanupDirs.push(tsDir);

    await writeTsLog(tsDir, 'command-guard.log', [tsDeny({ target: 'mkfs /dev/sda1', rule_id: 'mkfs' })]);
    // Nothing written under bouncerDir's own logs/hooks/ for the TS side —
    // proves the override, not the default, is what got read.

    const { text } = await runAudit({ days: 30, suggest: false, diff: true, tsLogsDir: tsDir });
    expect(sectionOf(text, 'TS denied/asked, bouncer would allow')).toContain('mkfs');
  });

  test('a missing TS log file (ENOENT — that guard never fired) is silent, not a warning', async () => {
    await freshAccountDir(); // no TS logs at all
    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: true });
    expect(ok).toBe(true);
    expect(text).not.toContain('warning:');
  });

  test('the report states the correlation heuristic and never writes anywhere', async () => {
    const dir = await freshAccountDir();
    await writeBouncerLog(dir, [shadowVerdict()]);
    await writeTsLog(dir, 'command-guard.log', [tsDeny()]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: true });
    expect(text.toLowerCase()).toContain('heuristic');

    // No overlay, no log mutation beyond what this test itself wrote.
    const overlayExists = await Bun.file(join(dir, 'bouncer', 'policy.toml')).exists();
    expect(overlayExists).toBe(false);
  });
});
