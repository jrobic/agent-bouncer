// The doctor check logic, at its own seam: given a settings.json path and
// an already-loaded policy (LoadResult), what does each check decide, and
// how does that decide the two report shapes (SessionStart's silence-or-
// scream context, and the manual full checklist)? Written before
// src/adapter/doctor.ts exists (TDD) — every case names an observed
// property at this boundary, not internal structure.

import { describe, expect, test } from 'bun:test';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LoadResult } from '../src/policy/load.ts';
import {
  buildSessionStartContext,
  formatDoctorChecklist,
  runDoctorChecks,
} from '../src/adapter/doctor.ts';
import { BOUNCER_COMMAND, FULL_MATCHER, HEALTHY_HOOKS } from './doctor-fixtures.ts';

async function scratchSettingsPath(hooks: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
  const path = join(dir, 'settings.json');
  await writeFile(path, JSON.stringify({ hooks }), 'utf8');
  return path;
}

function cleanLoadResult(overlayApplied = false): LoadResult {
  return {
    policy: {} as LoadResult['policy'],
    effectiveRules: [
      { family: 'command.bash', rule: { id: 'mkfs', regex: 'mkfs', reason: 'x' }, provenance: 'baseline' },
    ],
    warnings: [],
    overlayApplied,
    overlayFiles: overlayApplied ? ['policy.toml'] : [],
    activeOverrides: [],
    activeRelaxations: [],
  };
}

function brokenOverlayLoadResult(): LoadResult {
  return {
    ...cleanLoadResult(false),
    warnings: ['overlay policy rejected — falling back to the embedded baseline: invalid TOML'],
  };
}

function loadResultWithOverrides(): LoadResult {
  return {
    ...cleanLoadResult(true),
    activeOverrides: [
      {
        rule: 'curl-file-upload',
        action: 'relax',
        verdict: 'confirm',
        reason: 'we want a prompt, not a hard stop',
        sourceFile: 'policy.toml',
      },
    ],
    activeRelaxations: [
      {
        list: 'command.git.safe_subcommands',
        value: 'push',
        reason: 'our CI force-pushes to a throwaway branch',
        sourceFile: 'policy.toml',
      },
    ],
  };
}

describe('runDoctorChecks: wiring', () => {
  test('a fully wired settings.json passes every wiring check', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring).toHaveLength(3);
    expect(wiring.every((c) => c.ok)).toBe(true);
  });

  test('removing PreToolUse fails only that wiring check, with an explicit message', async () => {
    const { PreToolUse, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
    expect(preToolUse?.message).toContain('PreToolUse');
    expect(preToolUse?.message.toLowerCase()).toContain('unguarded');
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.ok).toBe(true);
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.ok).toBe(true);
  });

  test('removing UserPromptSubmit fails only that wiring check', async () => {
    const { UserPromptSubmit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('removing SessionStart fails only that wiring check (the doctor hook itself)', async () => {
    const { SessionStart, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.ok).toBe(false);
  });

  test('a PreToolUse matcher missing a guarded tool fails wiring even though the hook exists', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
  });

  test('a PreToolUse hook pointing at a DIFFERENT command (not bouncer) fails wiring', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: 'some-other-tool run' }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(false);
  });

  test('a matcher covering only ONE real mcp-tool shape still fails (round-3 review: MCP false negative)', async () => {
    // A matcher tuned to context-mode's naming convention alone must not
    // silently pass a filesystem-server-shaped (or any other) MCP tool —
    // EXPECTED_PRETOOLUSE_TOOLS carries two differently-shaped real names
    // specifically so a narrow matcher gets caught here.
    const narrowMatcher = 'Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep|Glob|'
      + 'mcp__plugin_context-mode_context-mode__ctx_execute';
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: narrowMatcher, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(false);
  });

  test('matcher "*" (CC\'s documented "all tools" wildcard) passes without throwing', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('an ABSENT matcher field (CC semantics: applies to every tool) passes', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('an unparseable matcher regex fails with a dedicated message, never throws', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: '(unclosed', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
    expect(preToolUse?.message.toLowerCase()).toContain('unparseable');
  });

  test('a missing settings.json file fails every wiring check without throwing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
    const report = await runDoctorChecks(join(dir, 'does-not-exist.json'), cleanLoadResult());
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring.every((c) => !c.ok)).toBe(true);
  });
});

describe('runDoctorChecks: settings.json readability (round-3 review: corrupt vs. absent)', () => {
  test('a missing settings.json is a healthy "settings" check — normal, unconfigured, not corrupt', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
    const report = await runDoctorChecks(join(dir, 'does-not-exist.json'), cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'settings')?.ok).toBe(true);
  });

  test('a malformed settings.json fails its OWN "settings" check, named honestly', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
    const path = join(dir, 'settings.json');
    await writeFile(path, 'not valid json {{{', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult());
    const settings = report.checks.find((c) => c.id === 'settings');
    expect(settings?.ok).toBe(false);
    expect(settings?.message.toLowerCase()).toContain('malformed');
  });

  test('a malformed settings.json makes wiring checks say "cannot verify", never "missing" (no false diagnosis)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
    const path = join(dir, 'settings.json');
    await writeFile(path, 'not valid json {{{', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult());
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring.every((c) => !c.ok)).toBe(true);
    for (const check of wiring) {
      expect(check.message.toLowerCase()).toContain('cannot verify');
      expect(check.message.toLowerCase()).not.toContain('is missing');
    }
  });

  test('a settings.json that is valid JSON but not an object is reported as corrupt too', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-test-'));
    const path = join(dir, 'settings.json');
    await writeFile(path, '[1,2,3]', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult());
    expect(report.checks.find((c) => c.id === 'settings')?.ok).toBe(false);
  });
});

describe('runDoctorChecks: policy', () => {
  test('a broken overlay (baseline-active) fails the policy check with the warning', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, brokenOverlayLoadResult());
    const policy = report.checks.find((c) => c.id === 'policy');
    expect(policy?.ok).toBe(false);
    expect(policy?.message).toContain('baseline');
  });

  test('no overlay configured at all is a healthy pass (baseline by design, not by failure)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(false));
    expect(report.checks.find((c) => c.id === 'policy')?.ok).toBe(true);
  });

  test('a valid overlay applied is a healthy pass', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(true));
    expect(report.checks.find((c) => c.id === 'policy')?.ok).toBe(true);
  });
});

describe('runDoctorChecks: log writability', () => {
  test('a writable config dir with no log file yet passes the log check', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-log-'));
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult());
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(true);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('an unwritable log directory fails the log check', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-log-'));
    await mkdir(join(dir, 'logs'), { recursive: true });
    await chmod(join(dir, 'logs'), 0o500); // read+execute, no write
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult());
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(false);
    } finally {
      await chmod(join(dir, 'logs'), 0o700);
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('an EXISTING but read-only log file fails the check even though its directory is writable '
    + '(round-3 review: the append-time failure log.ts silently swallows)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-log-'));
    const logsDir = join(dir, 'logs', 'hooks');
    await mkdir(logsDir, { recursive: true });
    const logFile = join(logsDir, 'bouncer.log');
    await writeFile(logFile, '{"already":"here"}\n', 'utf8');
    await chmod(logFile, 0o400); // read-only file, writable directory
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult());
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(false);
    } finally {
      await chmod(logFile, 0o600);
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('an EXISTING, writable log file (with content already in it) still passes', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-doctor-log-'));
    const logsDir = join(dir, 'logs', 'hooks');
    await mkdir(logsDir, { recursive: true });
    const logFile = join(logsDir, 'bouncer.log');
    const before = '{"already":"here"}\n';
    await writeFile(logFile, before, 'utf8');
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult());
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(true);
      // The check proves writability by opening for append and closing —
      // it must never actually write anything itself.
      const { readFile } = await import('node:fs/promises');
      expect(await readFile(logFile, 'utf8')).toBe(before);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('runDoctorChecks: overrides/relaxations announcement', () => {
  test('zero active overrides/relaxations: overrideCount is 0', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.overrideCount).toBe(0);
    expect(report.overrideLines).toEqual([]);
  });

  test('active overrides and relaxations are both counted and formatted', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides());
    expect(report.overrideCount).toBe(2); // 1 override + 1 relaxation
    expect(report.overrideLines).toContainEqual(expect.stringContaining('curl-file-upload'));
    expect(report.overrideLines).toContainEqual(expect.stringContaining('command.git.safe_subcommands'));
  });
});

describe('runDoctorChecks: report.ok', () => {
  test('ok is true when every check passes, regardless of active overrides', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides());
    expect(report.ok).toBe(true);
  });

  test('ok is false when any check fails', async () => {
    const { SessionStart, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(report.ok).toBe(false);
  });
});

describe('formatDoctorChecklist: the manual, always-verbose form', () => {
  test('prints pass/fail for every check and the override count, healthy or not', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const healthy = formatDoctorChecklist(await runDoctorChecks(settingsPath, cleanLoadResult()));
    expect(healthy).toContain('[pass] wiring:PreToolUse');
    expect(healthy).toContain('[pass] wiring:UserPromptSubmit');
    expect(healthy).toContain('[pass] wiring:SessionStart');
    expect(healthy).toContain('[pass] settings');
    expect(healthy).toContain('[pass] policy');
    expect(healthy).toContain('[pass] log');
    expect(healthy.toLowerCase()).toContain('overrides: none active');

    const withOverrides = formatDoctorChecklist(await runDoctorChecks(settingsPath, loadResultWithOverrides()));
    expect(withOverrides).toContain('overrides: 2 active');
    expect(withOverrides).toContain('curl-file-upload');
  });

  test('a failing check shows [fail], not silently omitted', async () => {
    const { SessionStart, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const text = formatDoctorChecklist(await runDoctorChecks(settingsPath, cleanLoadResult()));
    expect(text).toContain('[fail] wiring:SessionStart');
  });
});

describe('buildSessionStartContext: silent when healthy, screams on anomaly, announces on override', () => {
  test('healthy setup + zero overrides is fully silent (null)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    expect(buildSessionStartContext(report)).toBeNull();
  });

  test('a wiring anomaly produces non-null context naming the problem', async () => {
    const { SessionStart, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult());
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('SessionStart');
  });

  test('a broken overlay produces non-null context naming baseline fallback', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, brokenOverlayLoadResult());
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('baseline');
  });

  test('healthy wiring/policy but active overrides still produces non-null context (never silent)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides());
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('2');
    expect(context).toContain('curl-file-upload');
  });
});
