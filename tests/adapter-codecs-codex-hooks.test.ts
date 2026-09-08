// The `codex-hooks` wiring codec (src/adapter/codecs/wiring/codex-hooks.ts,
// ADR-0006 § 6, ticket 15b) — exercised the same way tests/adapter-doctor.
// test.ts exercises hook-file: real scratch `$CODEX_HOME` trees on disk,
// through runDoctorChecks (never the codec's own internals directly), so
// this is a proof of what `bouncer doctor --harness codex` actually
// reports, not a unit test of implementation.

import { describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCanaryCommand } from '../src/adapter/canary.ts';
import { formatCodexCanonicalCanaryEntry } from '../src/adapter/codecs/wiring/codex-hooks.ts';
import { runDoctorChecks } from '../src/adapter/doctor.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { LoadResult } from '../src/policy/load.ts';
import type { HarnessDeclaration } from '../src/policy/schema.ts';

const CODEX_HARNESS: HarnessDeclaration = BASELINE.rules.harness.find((h) => h.id === 'codex')!;
const BOUNCER_COMMAND = '/fake/checkout/dist/bouncer run --harness codex';
const CANARY_COMMAND = buildCanaryCommand('/fake/checkout/dist/bouncer');
const FULL_MATCHER = 'Bash|apply_patch|mcp__example__probe';

function cleanLoadResult(): LoadResult {
  return {
    policy: BASELINE.rules,
    effectiveRules: [],
    overlayApplied: false,
    overlayFiles: [],
    activeOverrides: [],
    activeRelaxations: [],
    overlayHarnessIds: [],
    layers: [],
    warnings: [],
  };
}

async function scratchCodexHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'bouncer-codex-hooks-test-'));
}

function healthyHooksJson(includeCanary = true) {
  const preToolUse = [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }];
  if (includeCanary) preToolUse.push({ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: CANARY_COMMAND }] });
  return {
    hooks: {
      PreToolUse: preToolUse,
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
      SessionStart: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
    },
  };
}

async function writeHooksJson(codexHome: string, content: unknown): Promise<void> {
  await writeFile(join(codexHome, 'hooks.json'), JSON.stringify(content), 'utf8');
}

async function writeConfigToml(codexHome: string, text: string): Promise<void> {
  await writeFile(join(codexHome, 'config.toml'), text, 'utf8');
}

function trustStateBlock(entries: readonly { readonly source: string; readonly key: string; }[]): string {
  return entries.map((e) => `[hooks.state."${e.source}:${e.key}"]\ntrusted_hash = "sha256:${'a'.repeat(64)}"\n`).join('\n');
}

const CONFIG_TOML_HOOKS = (matcher: string) =>
  [
    '[[hooks.PreToolUse]]',
    `matcher = "${matcher}"`,
    '[[hooks.PreToolUse.hooks]]',
    'type = "command"',
    `command = "${BOUNCER_COMMAND}"`,
    '',
    '[[hooks.UserPromptSubmit]]',
    '[[hooks.UserPromptSubmit.hooks]]',
    'type = "command"',
    `command = "${BOUNCER_COMMAND}"`,
    '',
    '[[hooks.SessionStart]]',
    '[[hooks.SessionStart.hooks]]',
    'type = "command"',
    `command = "${BOUNCER_COMMAND}"`,
    '',
  ].join('\n');

describe('codex-hooks wiring: healthy hooks.json alone', () => {
  test('every wiring check passes; trust fails (no [hooks.state] records yet)', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson());
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'settings')).toMatchObject({
        ok: true,
        // Review round 1 S-1/S-2/P-5: only hooks.json exists in this
        // scratch tree — the label must name exactly that, never the
        // config.toml [hooks] it never read.
        message: `hooks.json parsed (${join(codexHome, 'hooks.json')})`,
      });
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:canary')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:SessionStart')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: false,
        message: expect.stringContaining('3 bouncer hook(s) need review in /hooks'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: [hooks] in config.toml only', () => {
  test('wiring checks read config.toml when hooks.json is absent; a fully trusted ledger passes', async () => {
    const codexHome = await scratchCodexHome();
    try {
      const configTomlPath = join(codexHome, 'config.toml');
      const trust = trustStateBlock([
        { source: configTomlPath, key: 'pre_tool_use:0:0' },
        { source: configTomlPath, key: 'user_prompt_submit:0:0' },
        { source: configTomlPath, key: 'session_start:0:0' },
      ]);
      await writeConfigToml(codexHome, `${CONFIG_TOML_HOOKS(FULL_MATCHER)}\n${trust}`);
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'settings')).toMatchObject({
        ok: true,
        // S-1/S-2/P-5: hooks.json is absent here — the label must name
        // only config.toml [hooks], never a file that was never read.
        message: `config.toml [hooks] parsed (${configTomlPath})`,
      });
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:UserPromptSubmit')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:SessionStart')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: true,
        message: expect.stringContaining('3 bouncer hook(s) trust recorded'),
      });
      // No canary in config.toml's own PreToolUse group here — proves the
      // canary check reaches config.toml-sourced entries too, not just
      // hooks.json ones.
      expect(report.checks.find((c) => c.id === 'wiring:canary')).toMatchObject({ ok: false });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: both sources present (merged, additive)', () => {
  test('a bouncer entry in EITHER source counts as wired; trust is tracked per source independently', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson(true));
      const configTomlPath = join(codexHome, 'config.toml');
      // config.toml adds a SECOND PreToolUse group (its own [0][0]) — the
      // merge is additive, never a replacement of hooks.json's own
      // entries, and this group's own index is independent of
      // hooks.json's (separate source, separate indexing).
      const trust = trustStateBlock([{ source: configTomlPath, key: 'pre_tool_use:0:0' }]);
      await writeConfigToml(
        codexHome,
        `[[hooks.PreToolUse]]\nmatcher = "${FULL_MATCHER}"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "${BOUNCER_COMMAND}"\n\n${trust}`,
      );
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      const hooksJsonPath = join(codexHome, 'hooks.json');
      expect(report.checks.find((c) => c.id === 'settings')).toMatchObject({
        ok: true,
        // S-1/S-2/P-5: BOTH sources are present here — the label names
        // both, in read order, not a hardcoded single-file default.
        message: `hooks.json + config.toml [hooks] parsed (${hooksJsonPath}, ${configTomlPath})`,
      });
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({ ok: true });
      // 4 bouncer PreToolUse/UserPromptSubmit/SessionStart handlers from
      // hooks.json + 1 extra PreToolUse handler from config.toml = 4
      // total bouncer entries (hooks.json's own 3 + config.toml's 1);
      // only config.toml's is trusted, so 3 remain untrusted.
      const trustCheck = report.checks.find((c) => c.id === 'wiring:trust');
      expect(trustCheck).toMatchObject({ ok: false, message: expect.stringContaining('3 bouncer hook(s) need review') });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: missing --harness codex fails', () => {
  test('a bare "bouncer run" (no --harness codex) is caught as a wiring failure', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, {
        hooks: {
          PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: '/fake/checkout/dist/bouncer run' }] }],
        },
      });
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({
        ok: false,
        message: expect.stringContaining('does not carry --harness codex'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: matcher missing apply_patch fails coverage', () => {
  test('a matcher covering only Bash (no apply_patch, no mcp__) is a coverage gap', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, {
        hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }] },
      });
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({
        ok: false,
        message: expect.stringContaining('does not cover every guarded tool'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: untrusted entries fail with the count', () => {
  test('bouncer entries with no [hooks.state] record at all are named "need review in /hooks"', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson(false));
      // No config.toml at all — every one of the 3 bouncer entries is untrusted.
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: false,
        message: '3 bouncer hook(s) need review in /hooks; they are skipped, this session runs unguarded',
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });

  test('a [hooks.state] record with no trusted_hash still counts as untrusted', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, {
        hooks: { PreToolUse: [{ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }] },
      });
      await writeConfigToml(
        codexHome,
        `[hooks.state."${join(codexHome, 'hooks.json')}:pre_tool_use:0:0"]\nenabled = true\n`,
      );
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: false,
        message: expect.stringContaining('1 bouncer hook(s)'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: canary present/absent', () => {
  test('canary present in hooks.json passes wiring:canary', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson(true));
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:canary')).toMatchObject({ ok: true });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });

  test('canary absent from hooks.json fails wiring:canary, naming the missing binary path', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson(false));
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:canary')).toMatchObject({
        ok: false,
        message: expect.stringContaining('canary is missing for'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: neither source present', () => {
  test('absent hooks.json and absent config.toml is "no hooks configured yet", not a failure', async () => {
    const codexHome = await scratchCodexHome();
    try {
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      expect(report.checks.find((c) => c.id === 'settings')).toMatchObject({
        ok: true,
        message: expect.stringContaining('no hooks configured yet'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: true,
        message: expect.stringContaining('no bouncer hook entries'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: corrupt hooks.json (S-8)', () => {
  test('malformed hooks.json fails "settings" naming ITSELF, not config.toml', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeFile(join(codexHome, 'hooks.json'), 'not valid json {{{', 'utf8');
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      const settings = report.checks.find((c) => c.id === 'settings');
      expect(settings?.ok).toBe(false);
      expect(settings?.message).toContain('hooks.json malformed JSON');
      expect(settings?.message).toContain(join(codexHome, 'hooks.json'));
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify — hooks.json is unreadable/malformed'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:trust')).toMatchObject({
        ok: false,
        message: 'cannot verify — a hooks source is unreadable/malformed (see the settings check)',
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks wiring: corrupt config.toml (S-8)', () => {
  test('malformed config.toml fails "settings" naming ITSELF, not hooks.json — even with a healthy hooks.json present', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson());
      await writeFile(join(codexHome, 'config.toml'), 'not = [valid toml {{{', 'utf8');
      process.env.CODEX_HOME = codexHome;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), CODEX_HARNESS);
      const settings = report.checks.find((c) => c.id === 'settings');
      expect(settings?.ok).toBe(false);
      expect(settings?.message).toContain('config.toml [hooks]');
      expect(settings?.message).toContain(join(codexHome, 'config.toml'));
      expect(settings?.message).not.toContain('hooks.json parsed');
      expect(report.checks.find((c) => c.id === 'wiring:PreToolUse')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify — config.toml [hooks] is unreadable/malformed'),
      });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});

describe('codex-hooks: formatCodexCanonicalCanaryEntry (S-8)', () => {
  test('a healthy hooks.json produces a real canary entry', async () => {
    const codexHome = await scratchCodexHome();
    try {
      await writeHooksJson(codexHome, healthyHooksJson(true));
      process.env.CODEX_HOME = codexHome;
      const entry = await formatCodexCanonicalCanaryEntry(undefined, CODEX_HARNESS, CODEX_HARNESS.protocol!);
      if (entry.error !== undefined) throw new Error(`expected a canary entry, got error: ${entry.error}`);
      expect(JSON.parse(entry.entry)).toEqual({ matcher: FULL_MATCHER, hooks: [{ type: 'command', command: CANARY_COMMAND }] });
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });

  test('neither source present names BOTH candidate paths in the error', async () => {
    const codexHome = await scratchCodexHome();
    try {
      process.env.CODEX_HOME = codexHome;
      const entry = await formatCodexCanonicalCanaryEntry(undefined, CODEX_HARNESS, CODEX_HARNESS.protocol!);
      if (entry.error === undefined) throw new Error('expected an error, got a real canary entry');
      expect(entry.error).toContain(join(codexHome, 'hooks.json'));
      expect(entry.error).toContain(join(codexHome, 'config.toml'));
    } finally {
      delete process.env.CODEX_HOME;
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});
