// The doctor check logic, at its own seam: given a settings.json path and
// an already-loaded policy (LoadResult), what does each check decide, and
// how does that decide the two report shapes (SessionStart's silence-or-
// scream context, and the manual full checklist)? Written before
// src/adapter/doctor.ts exists (TDD) — every case names an observed
// property at this boundary, not internal structure.

import { describe, expect, test } from 'bun:test';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { buildCanaryCommand } from '../src/adapter/canary.ts';
import { buildSessionStartContext, formatDoctorChecklist, runDoctorChecks } from '../src/adapter/doctor.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { LoadResult } from '../src/policy/load.ts';
import type { HarnessDeclaration } from '../src/policy/schema.ts';
import {
  BOUNCER_COMMAND,
  BOUNCER_SHADOW_COMMAND,
  BOUNCER_TYPO_COMMAND,
  FULL_MATCHER,
  HEALTHY_HOOKS,
  PING_WORD_COMMAND,
} from './doctor-fixtures.ts';
import { tmpDir } from './tmp.ts';

const CLAUDE_CODE_HARNESS = BASELINE.rules.harness.find((h) => h.id === 'claude-code')!;

// Review round 3 R3-1: a declared harness with no `wiring` codec — the
// `[warn]` case ("not checkable", never `[pass]`, never `[fail]`, `ok`
// stays true). `events.session_start` is declared so buildSessionStartContext
// has a real SessionStart form to check the calm-announce branch against.
const NO_WIRING_HARNESS: HarnessDeclaration = {
  id: 'mini',
  dir: ['(^|/)\\.mini'],
  env: ['MINI_HOME'],
  witness: '~/.mini',
  reason: 'test',
  persistent: [],
  protocol: {
    transport: 'stdin-json',
    input: { event: 'hook_event_name', tool: 'tool_name', input: 'tool_input', session: 'session_id', cwd: 'cwd' },
    events: { pre_tool: 'PreToolUse', session_start: 'SessionStart' },
    tools: { Bash: { role: 'command', command: 'command' } },
    output: { block: 'deny', confirm: 'deny', observe: 'silent', flag: 'silent', on_malformed: 'allow' },
    templates: {
      deny: { stdout: '{"decision":"deny"}' },
      session_start: { stdout: '{"sessionContext":${context}}' },
    },
  },
};

async function scratchSettingsPath(hooks: unknown): Promise<string> {
  const dir = tmpDir('bouncer-doctor-test-');
  const path = join(dir, 'settings.json');
  await writeFile(path, JSON.stringify({ hooks }), 'utf8');
  return path;
}

function cleanLoadResult(overlayApplied = false): LoadResult {
  return {
    policy: { harness: [] } as unknown as LoadResult['policy'],
    effectiveRules: [
      { family: 'command.bash', rule: { id: 'mkfs', regex: 'mkfs', reason: 'x' }, provenance: 'baseline' },
    ],
    warnings: [],
    overlayApplied,
    overlayFiles: overlayApplied ? ['policy.toml'] : [],
    activeOverrides: [],
    activeRelaxations: [],
    overlayHarnessIds: [],
    // Empty on purpose: these fixtures test runDoctorChecks' OWN checks in
    // isolation from loadPolicyFromLayers, not the layer-count suffix
    // (tests/adapter-policy-layers.test.ts covers that, against the real
    // loader) — doctor.ts's layerCountSuffix renders no suffix at all for
    // an empty `layers`, so `checkPolicy`'s message stays exactly what it
    // was before ticket 20 here.
    layers: [],
  };
}

function brokenOverlayLoadResult(): LoadResult {
  return {
    ...cleanLoadResult(false),
    warnings: ['profile layer rejected — policy.toml: invalid TOML'],
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
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring).toHaveLength(4);
    expect(wiring.every((c) => c.ok)).toBe(true);
  });

  test('removing PreToolUse fails only that wiring check, with an explicit message', async () => {
    const { PreToolUse: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
    expect(preToolUse?.message).toContain('PreToolUse');
    expect(preToolUse?.message.toLowerCase()).toContain('unguarded');
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.ok).toBe(true);
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.ok).toBe(true);
  });

  test('removing UserPromptSubmit fails only that wiring check', async () => {
    const { UserPromptSubmit: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('removing SessionStart fails only that wiring check (the doctor hook itself)', async () => {
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.ok).toBe(false);
  });

  test('a PreToolUse matcher missing a guarded tool fails wiring even though the hook exists', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
  });

  test('a PreToolUse hook pointing at a DIFFERENT command (not bouncer) fails wiring', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: 'some-other-tool run' }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
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
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(false);
  });

  test('matcher "*" (CC\'s documented "all tools" wildcard) passes without throwing', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('an ABSENT matcher field (CC semantics: applies to every tool) passes', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('an unparseable matcher regex fails with a dedicated message, never throws', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: '(unclosed', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
    expect(preToolUse?.message.toLowerCase()).toContain('unparseable');
  });

  test('a missing settings.json file fails every wiring check without throwing', async () => {
    const dir = tmpDir('bouncer-doctor-test-');
    const report = await runDoctorChecks(join(dir, 'does-not-exist.json'), cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring.every((c) => !c.ok)).toBe(true);
  });

  test('a canonical PreToolUse canary using the main binary path passes', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        ...HEALTHY_HOOKS.PreToolUse,
        {
          matcher: FULL_MATCHER,
          hooks: [{ type: 'command', command: buildCanaryCommand('/fake/checkout/dist/bouncer') }],
        },
      ],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:canary')).toMatchObject({ ok: true });
  });

  test('a missing canary fails without weakening the primary wiring check', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const canary = report.checks.find((check) => check.id === 'wiring:canary');
    expect(canary).toMatchObject({ ok: false });
    expect(canary?.message).toContain('missing');
    expect(report.checks.find((check) => check.id === 'wiring:PreToolUse')).toMatchObject({ ok: true });
  });

  test('a canonical canary pointed at another binary fails', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: buildCanaryCommand('/other/bouncer') }] },
      ],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const canary = report.checks.find((check) => check.id === 'wiring:canary');
    expect(canary).toMatchObject({ ok: false });
    expect(canary?.message).toContain('different binary path');
  });

  test('a ping probe without the deny branch fails', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
        {
          matcher: FULL_MATCHER,
          hooks: [{ type: 'command', command: 'sh -c \'"$0" ping\' /fake/checkout/dist/bouncer' }],
        },
      ],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const canary = report.checks.find((check) => check.id === 'wiring:canary');
    expect(canary).toMatchObject({ ok: false });
    expect(canary?.message).toContain('deny-on-failure');
  });

  test('a paired command merely containing the word ping is not a liveness probe', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: PING_WORD_COMMAND }] },
      ],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((check) => check.id === 'wiring:canary')).toMatchObject({
      ok: false,
      message: 'PreToolUse canary is missing for /fake/checkout/dist/bouncer',
    });
  });

  test('a shell command never counts as the primary bouncer entry', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: '/bin/sh ping' }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((check) => check.id === 'wiring:PreToolUse')).toMatchObject({ ok: false });
    expect(report.checks.find((check) => check.id === 'wiring:canary')).toMatchObject({ ok: false });
  });

  test('malformed hook entries become a failing checklist rather than a doctor crash', async () => {
    const settingsPath = await scratchSettingsPath({
      PreToolUse: [null, { matcher: FULL_MATCHER, hooks: [null, { command: 1 }] }],
      UserPromptSubmit: HEALTHY_HOOKS.UserPromptSubmit,
      SessionStart: HEALTHY_HOOKS.SessionStart,
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.ok).toBe(false);
    expect(report.checks.find((check) => check.id === 'wiring:PreToolUse')).toMatchObject({ ok: false });
  });
});

// Ticket 08: `run --shadow` must count as valid wiring (pointsAtBouncer
// only requires 'run' among the args, which --shadow doesn't remove), and
// the manual checklist should say so — info, never a failure. After
// cutover the flag drops and doctor goes back to saying nothing extra;
// there is no separate "shadow expected" state to configure.
describe('runDoctorChecks: shadow-mode wiring (ticket 08)', () => {
  test('a hook command carrying --shadow still passes wiring — pointsAtBouncer already accepts it (arg "run" is present)', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_SHADOW_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('the manual checklist message says "shadow mode" for a --shadow-wired event, info not fail', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_SHADOW_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(true);
    expect(preToolUse?.message.toLowerCase()).toContain('shadow mode');
  });

  test('a non-shadow wiring never mentions shadow mode', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.message.toLowerCase()).not.toContain('shadow');
  });

  test('shadow mode is reported per-event: only the events actually wired with --shadow say so', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_SHADOW_COMMAND }] }],
      // UserPromptSubmit and SessionStart stay on the plain (non-shadow) command.
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.message.toLowerCase()).toContain('shadow');
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.message.toLowerCase()).not.toContain('shadow');
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.message.toLowerCase()).not.toContain('shadow');
  });

  test('the passing canary check says that it remains enforcing in shadow mode', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [
        { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_SHADOW_COMMAND }] },
        {
          matcher: FULL_MATCHER,
          hooks: [{ type: 'command', command: buildCanaryCommand('/fake/checkout/dist/bouncer') }],
        },
      ],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const canary = report.checks.find((check) => check.id === 'wiring:canary');
    expect(canary).toMatchObject({ ok: true });
    expect(canary?.message).toContain('canary remains enforcing');
  });
});

// Ticket 08 review round: a typo'd token in the live wiring (--shadwo
// instead of --shadow) still "points at bouncer" (pointsAtBouncer only
// requires 'run'), so it would otherwise pass silently — the wiring check
// must fail loudly instead, naming the unrecognized token, since this is
// the one place (SessionStart) it's actually actionable.
describe('runDoctorChecks: unrecognized token in the wired command (ticket 08 review)', () => {
  test('a hook command with an unrecognized token FAILS wiring, naming the token', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_TYPO_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const preToolUse = report.checks.find((c) => c.id === 'wiring:PreToolUse');
    expect(preToolUse?.ok).toBe(false);
    expect(preToolUse?.message).toContain('--shadwo');
    expect(preToolUse?.message.toLowerCase()).toContain('unrecognized');
  });

  test('a healthy --shadow wiring (the exact, correct flag) never trips this check', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_SHADOW_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(true);
  });

  test('unrecognized-token failure is reported per-event, only for the events actually wired with the typo', async () => {
    const settingsPath = await scratchSettingsPath({
      ...HEALTHY_HOOKS,
      PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_TYPO_COMMAND }] }],
    });
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')?.ok).toBe(true);
    expect(report.checks.find((c) => c.id === 'wiring:SessionStart')?.ok).toBe(true);
  });
});

describe('runDoctorChecks: settings.json readability (round-3 review: corrupt vs. absent)', () => {
  test('a missing settings.json is a healthy "settings" check — normal, unconfigured, not corrupt', async () => {
    const dir = tmpDir('bouncer-doctor-test-');
    const report = await runDoctorChecks(join(dir, 'does-not-exist.json'), cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'settings')?.ok).toBe(true);
  });

  test('a malformed settings.json fails its OWN "settings" check, named honestly', async () => {
    const dir = tmpDir('bouncer-doctor-test-');
    const path = join(dir, 'settings.json');
    await writeFile(path, 'not valid json {{{', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const settings = report.checks.find((c) => c.id === 'settings');
    expect(settings?.ok).toBe(false);
    expect(settings?.message.toLowerCase()).toContain('malformed');
  });

  test('a malformed settings.json makes wiring checks say "cannot verify", never "missing" (no false diagnosis)', async () => {
    const dir = tmpDir('bouncer-doctor-test-');
    const path = join(dir, 'settings.json');
    await writeFile(path, 'not valid json {{{', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const wiring = report.checks.filter((c) => c.id.startsWith('wiring:'));
    expect(wiring.every((c) => !c.ok)).toBe(true);
    for (const check of wiring) {
      expect(check.message.toLowerCase()).toContain('cannot verify');
      expect(check.message.toLowerCase()).not.toContain('is missing');
    }
  });

  test('a settings.json that is valid JSON but not an object is reported as corrupt too', async () => {
    const dir = tmpDir('bouncer-doctor-test-');
    const path = join(dir, 'settings.json');
    await writeFile(path, '[1,2,3]', 'utf8');
    const report = await runDoctorChecks(path, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'settings')?.ok).toBe(false);
  });
});

describe('runDoctorChecks: policy', () => {
  test('a broken overlay (baseline-active) fails the policy check with the warning', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, brokenOverlayLoadResult(), CLAUDE_CODE_HARNESS);
    const policy = report.checks.find((c) => c.id === 'policy');
    expect(policy?.ok).toBe(false);
    expect(policy?.message).toContain('baseline');
  });

  test('no overlay configured at all is a healthy pass (baseline by design, not by failure)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(false), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'policy')?.ok).toBe(true);
  });

  test('a valid overlay applied is a healthy pass', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(true), CLAUDE_CODE_HARNESS);
    expect(report.checks.find((c) => c.id === 'policy')?.ok).toBe(true);
  });
});

describe('runDoctorChecks: log writability', () => {
  test('a writable config dir with no log file yet passes the log check', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = tmpDir('bouncer-doctor-log-');
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(true);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
    }
  });

  test('an unwritable log directory fails the log check', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = tmpDir('bouncer-doctor-log-');
    await mkdir(join(dir, 'logs'), { recursive: true });
    await chmod(join(dir, 'logs'), 0o500); // read+execute, no write
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(false);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
    }
  });

  test('an EXISTING but read-only log file fails the check even though its directory is writable '
    + '(round-3 review: the append-time failure log.ts silently swallows)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = tmpDir('bouncer-doctor-log-');
    const logsDir = join(dir, 'logs', 'hooks');
    await mkdir(logsDir, { recursive: true });
    const logFile = join(logsDir, 'bouncer.log');
    await writeFile(logFile, '{"already":"here"}\n', 'utf8');
    await chmod(logFile, 0o400); // read-only file, writable directory
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(false);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
    }
  });

  test('an EXISTING, writable log file (with content already in it) still passes', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const dir = tmpDir('bouncer-doctor-log-');
    const logsDir = join(dir, 'logs', 'hooks');
    await mkdir(logsDir, { recursive: true });
    const logFile = join(logsDir, 'bouncer.log');
    const before = '{"already":"here"}\n';
    await writeFile(logFile, before, 'utf8');
    const original = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = dir;
    try {
      const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
      expect(report.checks.find((c) => c.id === 'log')?.ok).toBe(true);
      // The check proves writability by opening for append and closing —
      // it must never actually write anything itself.
      const { readFile } = await import('node:fs/promises');
      expect(await readFile(logFile, 'utf8')).toBe(before);
    } finally {
      if (original === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = original;
    }
  });
});

describe('runDoctorChecks: overrides/relaxations announcement', () => {
  test('zero active overrides/relaxations: overrideCount is 0', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.overrideCount).toBe(0);
    expect(report.overrideLines).toEqual([]);
  });

  test('active overrides and relaxations are both counted and formatted', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides(), CLAUDE_CODE_HARNESS);
    expect(report.overrideCount).toBe(2); // 1 override + 1 relaxation
    expect(report.overrideLines).toContainEqual(expect.stringContaining('curl-file-upload'));
    expect(report.overrideLines).toContainEqual(expect.stringContaining('command.git.safe_subcommands'));
  });
});

describe('runDoctorChecks: report.ok', () => {
  test('ok is true when every check passes, regardless of active overrides', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides(), CLAUDE_CODE_HARNESS);
    expect(report.ok).toBe(true);
  });

  test('ok is false when any check fails', async () => {
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(report.ok).toBe(false);
  });
});

describe('formatDoctorChecklist: the manual, always-verbose form', () => {
  test('prints pass/fail for every check and the override count, healthy or not', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const healthy = formatDoctorChecklist(await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS));
    expect(healthy).toContain('[pass] wiring:PreToolUse');
    expect(healthy).toContain('[pass] wiring:UserPromptSubmit');
    expect(healthy).toContain('[pass] wiring:SessionStart');
    expect(healthy).toContain('[pass] settings');
    expect(healthy).toContain('[pass] policy');
    expect(healthy).toContain('[pass] log');
    expect(healthy.toLowerCase()).toContain('overrides: none active');

    const withOverrides = formatDoctorChecklist(await runDoctorChecks(settingsPath, loadResultWithOverrides(), CLAUDE_CODE_HARNESS));
    expect(withOverrides).toContain('overrides: 2 active');
    expect(withOverrides).toContain('curl-file-upload');
  });

  test('a failing check shows [fail], not silently omitted', async () => {
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const text = formatDoctorChecklist(await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS));
    expect(text).toContain('[fail] wiring:SessionStart');
  });

  test('review round 3 R3-1: a declared harness with no wiring codec shows [warn], not [pass], ok stays true', async () => {
    const report = await runDoctorChecks(undefined, cleanLoadResult(), NO_WIRING_HARNESS);
    const text = formatDoctorChecklist(report);
    expect(text).toContain('[warn] wiring — not checkable (declared harness)');
    expect(text).not.toContain('[pass] wiring');
    expect(report.ok).toBe(true);
  });
});

describe('buildSessionStartContext: silent when healthy, screams on anomaly, announces on override', () => {
  test('healthy setup + zero overrides is fully silent (null)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    expect(buildSessionStartContext(report)).toBeNull();
  });

  test('a wiring anomaly produces non-null context naming the problem', async () => {
    const { SessionStart: _omit, ...rest } = HEALTHY_HOOKS;
    const settingsPath = await scratchSettingsPath(rest);
    const report = await runDoctorChecks(settingsPath, cleanLoadResult(), CLAUDE_CODE_HARNESS);
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('SessionStart');
  });

  test('a broken overlay produces non-null context naming baseline fallback', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, brokenOverlayLoadResult(), CLAUDE_CODE_HARNESS);
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('baseline');
  });

  test('healthy wiring/policy but active overrides still produces non-null context (never silent)', async () => {
    const settingsPath = await scratchSettingsPath(HEALTHY_HOOKS);
    const report = await runDoctorChecks(settingsPath, loadResultWithOverrides(), CLAUDE_CODE_HARNESS);
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).toContain('2');
    expect(context).toContain('curl-file-upload');
  });

  test('review round 3 R3-1: a [warn] check with nothing else broken joins the calm announce, never the scream', async () => {
    const report = await runDoctorChecks(undefined, cleanLoadResult(), NO_WIRING_HARNESS);
    const context = buildSessionStartContext(report);
    expect(context).not.toBeNull();
    expect(context).not.toContain('WIRING/POLICY PROBLEM DETECTED');
    expect(context).toContain('unprovable, not broken');
    expect(context).toContain('wiring: not checkable (declared harness)');
  });
});
