// Ticket 14: bouncer's own audit log (logs/hooks/bouncer.log, the
// binary's own denial/confirm history — reconnaissance for a compromised
// agent) is now a baseline secret.path rule, verdict "confirm". This file
// proves it end to end, through the REAL adapter dispatch (src/adapter/
// run.ts) against a REAL on-disk log file under a throwaway, EXPLICITLY
// VERIFIED CLAUDE_CONFIG_DIR — the ticket-13 incident (an unverified,
// accidentally-empty CLAUDE_CONFIG_DIR fell through to the real live
// ~/.claude) is why every smoke/adapter invocation here asserts the env
// var is set and non-empty before calling run().

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/adapter/run.ts';
import { runAudit } from '../src/cli-commands.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function freshAccountWithRealLog(): Promise<{ accountDir: string; logPath: string; }> {
  const accountDir = await mkdtemp(join(tmpdir(), 'bouncer-log-protection-'));
  cleanupDirs.push(accountDir);
  const logDir = join(accountDir, 'logs', 'hooks');
  await mkdir(logDir, { recursive: true });
  const logPath = join(logDir, 'bouncer.log');
  await writeFile(logPath, '{"timestamp":"2026-08-17T00:00:00.000Z","rule_id":"mkfs","verdict":"block"}\n', 'utf8');

  // The ticket-13 lesson: assert before use, never trust an unverified var.
  process.env.CLAUDE_CONFIG_DIR = accountDir;
  if (!process.env.CLAUDE_CONFIG_DIR || process.env.CLAUDE_CONFIG_DIR.trim() === '') {
    throw new Error('CLAUDE_CONFIG_DIR failed to set — refusing to proceed (would fall through to live ~/.claude)');
  }

  return { accountDir, logPath };
}

describe('run(): Read on bouncer\'s own audit log confirms, under a real custom CLAUDE_CONFIG_DIR', () => {
  test('Read on the real, absolute, resolved log path asks (confirm), naming bouncer-audit-log', async () => {
    const { logPath } = await freshAccountWithRealLog();
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: logPath },
    });
    const { stdout } = await run(envelope);
    expect(stdout).not.toBeNull();
    const parsed = JSON.parse(stdout!);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain('bouncer-audit-log');
  });

  test('Grep targeting the log file path also confirms', async () => {
    const { accountDir } = await freshAccountWithRealLog();
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Grep',
      tool_input: { pattern: 'rule_id', path: join(accountDir, 'logs', 'hooks', 'bouncer.log') },
    });
    const { stdout } = await run(envelope);
    expect(stdout).not.toBeNull();
    const parsed = JSON.parse(stdout!);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain('bouncer-audit-log');
  });

  test('a Bash "cat" of the log path also confirms (not a hardcoded block)', async () => {
    const { logPath } = await freshAccountWithRealLog();
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: `cat ${logPath}` },
    });
    const { stdout } = await run(envelope);
    expect(stdout).not.toBeNull();
    const parsed = JSON.parse(stdout!);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain('bash-bouncer-audit-log');
  });

  test('negative: a DIFFERENT file also named bouncer.log, outside logs/hooks/, is not touched', async () => {
    const { accountDir } = await freshAccountWithRealLog();
    const decoyPath = join(accountDir, 'bouncer.log');
    await writeFile(decoyPath, 'not the audit log\n', 'utf8');
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: decoyPath },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();
  });

  test('bouncer audit itself is unaffected — it reads its own log straight through, no PreToolUse envelope at all', async () => {
    // No dispatch/run() call in this test at all — runAudit
    // (src/cli-commands.ts) calls node:fs's readFile directly on
    // hookLogPath(HOOK_NAME); there is no tool call for the guard to
    // intercept. Proven concretely: the SAME account dir and SAME
    // pre-written log line the Read/Grep/Bash cases above got a
    // "confirm" for reads back cleanly through the sanctioned path.
    await freshAccountWithRealLog();
    const { ok, text } = await runAudit({ days: 30, suggest: false, diff: false });
    // A single block entry doesn't clear the friction-clustering threshold
    // (see tests/adapter-audit.test.ts), so the report legitimately shows
    // no findings — what this test actually proves is `ok: true` and a
    // well-formed report: the file was read and parsed successfully,
    // never rejected or blocked by anything this ticket added.
    expect(ok).toBe(true);
    expect(text).toContain('bouncer audit');
  });
});
