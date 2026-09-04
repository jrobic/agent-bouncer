// SessionStart end to end through run() — the hook mode of doctor (ticket
// 07): a real stdin envelope, a real scratch settings.json under
// CLAUDE_CONFIG_DIR, and the real policy load. Complements
// tests/adapter-doctor.test.ts (the pure check logic) by proving the
// wiring actually reaches the protocol: silent stdout when healthy,
// additionalContext when not — the same discipline
// tests/adapter-run.test.ts and tests/adapter-policy.test.ts already use
// for PreToolUse/UserPromptSubmit and the overlay.

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, runSessionStart } from '../src/adapter/run.ts';
import type { LoadResult } from '../src/policy/load.ts';
import { BOUNCER_COMMAND, CANARY_COMMAND, HEALTHY_HOOKS } from './doctor-fixtures.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function accountWithSettings(hooks: unknown): Promise<string> {
  const accountDir = await mkdtemp(join(tmpdir(), 'bouncer-sessionstart-e2e-'));
  cleanupDirs.push(accountDir);
  await writeFile(join(accountDir, 'settings.json'), JSON.stringify({ hooks }), 'utf8');
  process.env.CLAUDE_CONFIG_DIR = accountDir;
  return accountDir;
}

const SESSION_START_ENVELOPE = JSON.stringify({ hook_event_name: 'SessionStart', session_id: 'sess-1' });

describe('run(): SessionStart, the doctor hook (ticket 07)', () => {
  test('a fully wired, healthy settings.json produces total silence', async () => {
    await accountWithSettings(HEALTHY_HOOKS);
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).toBeNull();
  });

  test('a PreToolUse matcher of "*" (CC\'s "all tools" wildcard) is silent too — never a cry-wolf scream', async () => {
    await accountWithSettings({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        { matcher: '*', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
        { matcher: '*', hooks: [{ type: 'command', command: CANARY_COMMAND }] },
      ],
    });
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).toBeNull();
  });

  test('a missing canary reaches the SessionStart scream', async () => {
    await accountWithSettings({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    expect(JSON.parse(stdout!).hookSpecificOutput.additionalContext).toContain('wiring:canary');
  });
  test('removing a hook entry from settings.json makes the next SessionStart scream', async () => {
    const { PreToolUse: _omit, ...withoutPreToolUse } = HEALTHY_HOOKS;
    await accountWithSettings(withoutPreToolUse);
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    const parsed = JSON.parse(stdout!);
    expect(parsed.hookSpecificOutput.hookEventName).toBe('SessionStart');
    expect(parsed.hookSpecificOutput.additionalContext).toContain('PreToolUse');
    expect(parsed.hookSpecificOutput.additionalContext.toLowerCase()).toContain('unguarded');
  });

  test('a missing settings.json entirely (naked account) screams', async () => {
    const accountDir = await mkdtemp(join(tmpdir(), 'bouncer-sessionstart-e2e-'));
    cleanupDirs.push(accountDir);
    process.env.CLAUDE_CONFIG_DIR = accountDir; // no settings.json written at all
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    expect(JSON.parse(stdout!).hookSpecificOutput.additionalContext).toContain('wiring');
  });

  test('a corrupt settings.json screams with the honest "settings" failure, not a false "hook missing"', async () => {
    const accountDir = await mkdtemp(join(tmpdir(), 'bouncer-sessionstart-e2e-'));
    cleanupDirs.push(accountDir);
    process.env.CLAUDE_CONFIG_DIR = accountDir;
    await writeFile(join(accountDir, 'settings.json'), 'not valid json {{{', 'utf8');
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    const context = JSON.parse(stdout!).hookSpecificOutput.additionalContext;
    expect(context.toLowerCase()).toContain('malformed');
    expect(context).toContain('cannot verify');
  });

  test('a broken policy overlay is reported at SessionStart even with healthy wiring', async () => {
    const accountDir = await accountWithSettings(HEALTHY_HOOKS);
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    await writeFile(join(accountDir, 'bouncer', 'policy.toml'), 'this is [not valid toml {{{', 'utf8');
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    expect(JSON.parse(stdout!).hookSpecificOutput.additionalContext).toContain('baseline');
  });

  test('an active override is announced at SessionStart even though nothing is broken', async () => {
    const accountDir = await accountWithSettings(HEALTHY_HOOKS);
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    await writeFile(
      join(accountDir, 'bouncer', 'policy.toml'),
      '[[override]]\nrule = "curl-file-upload"\naction = "disable"\nreason = "test: SessionStart announces this"\n',
      'utf8',
    );
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
    const context = JSON.parse(stdout!).hookSpecificOutput.additionalContext;
    expect(context).toContain('curl-file-upload');
    expect(context).not.toContain('WIRING/POLICY PROBLEM'); // nothing is actually broken
  });

  test('a PostToolUse envelope stays silent — SessionStart handling does not widen the whitelist', async () => {
    await accountWithSettings(HEALTHY_HOOKS);
    const envelope = JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'ls' } });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();
  });
});

// Ticket 08: shadow mode never screams on stdout, even for a genuinely
// broken wiring — but the would-be scream is not lost, it goes to the log
// (mode: "shadow") so shadow wiring health is verifiable without stdout.
describe('run: SessionStart in shadow mode (ticket 08) — never screams, logs what it would have said', () => {
  test('a broken wiring would normally scream; in shadow it stays silent AND logs the would-be message', async () => {
    const accountDir = await accountWithSettings({});
    const { stdout } = await run(SESSION_START_ENVELOPE, { shadow: true });
    expect(stdout).toBeNull();

    const logContent = await readFile(join(accountDir, 'logs', 'hooks', 'bouncer.log'), 'utf8');
    const lines = logContent.trim().split('\n').map((l) => JSON.parse(l));
    const shadowEntry = lines.find((l) => l.mode === 'shadow');
    expect(shadowEntry).toBeDefined();
    expect(shadowEntry.message).toContain('unguarded');
  });

  test('a fully healthy wiring stays silent in shadow too, and logs nothing (context is null — nothing to log)', async () => {
    const accountDir = await accountWithSettings(HEALTHY_HOOKS);
    const { stdout } = await run(SESSION_START_ENVELOPE, { shadow: true });
    expect(stdout).toBeNull();

    const logExists = await readFile(join(accountDir, 'logs', 'hooks', 'bouncer.log'), 'utf8').catch(() => null);
    expect(logExists).toBeNull(); // nothing was ever worth logging, so the file was never created
  });

  test('WITHOUT shadow, the same broken wiring DOES scream on stdout — confirms shadow, not something else, is what changed', async () => {
    await accountWithSettings({});
    const { stdout } = await run(SESSION_START_ENVELOPE);
    expect(stdout).not.toBeNull();
  });
});

describe('runSessionStart: a throwing doctor check is caught, logged, and never crashes the hook', () => {
  const FAKE_LOADED: LoadResult = {
    policy: {} as LoadResult['policy'],
    effectiveRules: [],
    warnings: [],
    overlayApplied: false,
    overlayFiles: [],
    activeOverrides: [],
    activeRelaxations: [],
    layers: [], // irrelevant here — this test is about the throwing-check catch path, not layer provenance
  };

  test('the catch path logs a policy-warning entry instead of failing silently (round-3 review)', async () => {
    const accountDir = await mkdtemp(join(tmpdir(), 'bouncer-sessionstart-crash-'));
    cleanupDirs.push(accountDir);
    process.env.CLAUDE_CONFIG_DIR = accountDir;

    const throwingCheck = async (): Promise<never> => {
      throw new Error('doctor check exploded');
    };
    const result = await runSessionStart(FAKE_LOADED, false, throwingCheck);
    expect(result.stdout).toBeNull(); // still never crashes the hook

    const logContent = await readFile(join(accountDir, 'logs', 'hooks', 'bouncer.log'), 'utf8');
    const lines = logContent.trim().split('\n').map((l) => JSON.parse(l));
    const warning = lines.find((l) => l.kind === 'policy-warning');
    expect(warning).toBeDefined();
    expect(warning.message).toContain('doctor checks failed');
    expect(warning.message).toContain('doctor check exploded');
  });
});
