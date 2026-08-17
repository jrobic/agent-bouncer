// `bouncer doctor` — the manual, always-verbose CLI form (ticket 07).
// Tested at the command-function level (src/cli-commands.ts's runDoctor),
// same discipline as tests/cli-commands.test.ts for check/rules. Kept in
// its own file (not appended to cli-commands.test.ts) to stay out of the
// way of parallel work on the same source files (ticket 10 / `audit`).

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseDoctorArgs, runDoctor } from '../src/cli-commands.ts';
import { HEALTHY_HOOKS } from './doctor-fixtures.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function freshAccountDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-cli-'));
  cleanupDirs.push(dir);
  process.env.CLAUDE_CONFIG_DIR = dir;
  return dir;
}

describe('parseDoctorArgs: the pure argv-tail parsing cli.ts delegates to', () => {
  test('no --settings flag at all: no path, no error', () => {
    expect(parseDoctorArgs([])).toEqual({});
  });

  test('--settings <path>: the path is captured', () => {
    expect(parseDoctorArgs(['--settings', '/tmp/scratch/settings.json'])).toEqual({
      settingsPath: '/tmp/scratch/settings.json',
    });
  });

  test('--settings as the LAST token (no value at all) is an explicit error', () => {
    const result = parseDoctorArgs(['--settings']);
    expect(result.settingsPath).toBeUndefined();
    expect(result.error).toContain('--settings');
  });

  test('--settings immediately followed by another flag is an error, not a silently swallowed value '
    + '(round-3 review: --other-flag must never become the "path")', () => {
    const result = parseDoctorArgs(['--settings', '--other-flag']);
    expect(result.settingsPath).toBeUndefined();
    expect(result.error).toBeDefined();
  });
});

describe('runDoctor: the manual checklist, always printed', () => {
  test('a healthy scratch settings.json passed via --settings prints an all-pass checklist', async () => {
    await freshAccountDir();
    const scratchDir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-settings-'));
    cleanupDirs.push(scratchDir);
    const settingsPath = join(scratchDir, 'settings.json');
    await writeFile(settingsPath, JSON.stringify({ hooks: HEALTHY_HOOKS }), 'utf8');

    const { text, ok } = await runDoctor(settingsPath);
    expect(ok).toBe(true);
    expect(text).toContain('[pass] wiring:PreToolUse');
    expect(text).toContain('[pass] wiring:UserPromptSubmit');
    expect(text).toContain('[pass] wiring:SessionStart');
    expect(text).toContain('[pass] policy');
    expect(text).toContain('[pass] log');
    expect(text).toContain('overrides: none active');
  });

  test('a scratch settings.json missing SessionStart prints a failing checklist and exits non-zero', async () => {
    await freshAccountDir();
    const scratchDir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-settings-'));
    cleanupDirs.push(scratchDir);
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = join(scratchDir, 'settings.json');
    await writeFile(settingsPath, JSON.stringify({ hooks: rest }), 'utf8');

    const { text, ok } = await runDoctor(settingsPath);
    expect(ok).toBe(false);
    expect(text).toContain('[fail] wiring:SessionStart');
  });

  test('with no --settings argument, defaults to <configDir>/settings.json', async () => {
    const accountDir = await freshAccountDir();
    await writeFile(join(accountDir, 'settings.json'), JSON.stringify({ hooks: HEALTHY_HOOKS }), 'utf8');

    const { ok } = await runDoctor();
    expect(ok).toBe(true);
  });

  test('active overrides are shown in the manual checklist with their reason', async () => {
    const accountDir = await freshAccountDir();
    await writeFile(join(accountDir, 'settings.json'), JSON.stringify({ hooks: HEALTHY_HOOKS }), 'utf8');
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    await writeFile(
      join(accountDir, 'bouncer', 'policy.toml'),
      '[[override]]\nrule = "curl-file-upload"\naction = "disable"\nreason = "manual doctor visibility test"\n',
      'utf8',
    );

    const { text, ok } = await runDoctor();
    expect(ok).toBe(true); // an active, reasoned override is not itself a failure
    expect(text).toContain('overrides: 1 active');
    expect(text).toContain('curl-file-upload');
    expect(text).toContain('manual doctor visibility test');
  });
});

describe('runDoctor: `ok` is exactly the exit-code contract cli.ts relies on '
  + '(`process.exit(ok ? 0 : 1)`, round-3 review item 10)', () => {
  test('a healthy checklist maps to ok=true (cli.ts would exit 0)', async () => {
    await freshAccountDir();
    const scratchDir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-settings-'));
    cleanupDirs.push(scratchDir);
    const settingsPath = join(scratchDir, 'settings.json');
    await writeFile(settingsPath, JSON.stringify({ hooks: HEALTHY_HOOKS }), 'utf8');

    const { ok } = await runDoctor(settingsPath);
    expect(ok).toBe(true);
  });

  test('a failing checklist maps to ok=false (cli.ts would exit 1)', async () => {
    await freshAccountDir();
    const scratchDir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-settings-'));
    cleanupDirs.push(scratchDir);
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = join(scratchDir, 'settings.json');
    await writeFile(settingsPath, JSON.stringify({ hooks: rest }), 'utf8');

    const { ok } = await runDoctor(settingsPath);
    expect(ok).toBe(false);
  });
});
