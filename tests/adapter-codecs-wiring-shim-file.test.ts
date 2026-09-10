// The `shim-file` wiring codec (src/adapter/codecs/wiring/shim-file.ts,
// ADR-0006 § 6/7, ticket 15c) — exercised the same way tests/adapter-
// doctor.test.ts exercises hook-file and tests/adapter-codecs-codex-hooks.
// test.ts exercises codex-hooks: real scratch trees on disk, through
// runDoctorChecks (never the codec's own internals directly), so this is
// a proof of what `bouncer doctor --harness pi-agent` actually reports.

import { describe, expect, test } from 'bun:test';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runDoctorChecks } from '../src/adapter/doctor.ts';
import { renderShim } from '../src/adapter/shim.ts';
import { runPrintCanary } from '../src/cli-commands.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { LoadResult } from '../src/policy/load.ts';
import type { HarnessDeclaration } from '../src/policy/schema.ts';
import { tmpDir } from './tmp.ts';

const PI_AGENT_HARNESS: HarnessDeclaration = BASELINE.rules.harness.find((h) => h.id === 'pi-agent')!;

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

function scratchAgentDir(): string {
  return tmpDir('bouncer-shim-file-test-');
}

async function writeExecutableBouncer(dir: string): Promise<string> {
  const path = join(dir, 'fake-bouncer');
  await writeFile(path, '#!/bin/sh\nexit 0\n', 'utf8');
  await chmod(path, 0o755);
  return path;
}

async function writeShimFile(agentDir: string, content: string): Promise<string> {
  const extensionsDir = join(agentDir, 'extensions');
  await mkdir(extensionsDir, { recursive: true });
  const path = join(extensionsDir, 'bouncer.ts');
  await writeFile(path, content, 'utf8');
  return path;
}

describe('shim-file wiring: identical to the printed shim', () => {
  test('wiring:shim and wiring:binary both pass', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({ ok: true, message: `${bouncerPath} is executable` });
      // shim-file carries no per-event settings shape — no top-level
      // "settings" check exists at all for this wiring codec.
      expect(report.checks.find((c) => c.id === 'settings')).toBeUndefined();
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: drifted (one byte edited)', () => {
  test('wiring:shim fails, names the reprint command; wiring:binary still passes (BOUNCER path untouched)', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      const source = renderShim('pi-agent', bouncerPath)!;
      await writeShimFile(agentDir, source.replace('failing closed', 'FAILING CLOSED'));
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('bouncer harness shim pi-agent'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({ ok: true });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: absent', () => {
  test('wiring:shim fails, names the print command; wiring:binary reports "cannot verify"', async () => {
    const agentDir = scratchAgentDir();
    try {
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('bouncer harness shim pi-agent'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify'),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: non-executable BOUNCER', () => {
  test('wiring:shim passes (the file matches byte for byte); wiring:binary fails', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = join(agentDir, 'not-executable-bouncer');
      await writeFile(bouncerPath, 'not a real binary', 'utf8');
      await chmod(bouncerPath, 0o644);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining(bouncerPath),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: a file that is not a printed shim at all', () => {
  test('no BOUNCER line found: wiring:shim fails naming the reprint, wiring:binary "cannot verify"', async () => {
    const agentDir = scratchAgentDir();
    try {
      await writeShimFile(agentDir, 'export default function (pi) { /* not a real shim */ }\n');
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('reprint it'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify'),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: policy and log checks are unaffected (ADR-0006 § 6: "leaves policy/log unchanged")', () => {
  test('policy and log checks still run and pass alongside the two shim checks', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'policy')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'log')).toMatchObject({ ok: true });
      expect(report.ok).toBe(true);
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: doctor --print-canary (review round 1 S-4)', () => {
  test('the "no canary entry" error names the ACTUAL harness id, not a literal "<id>" placeholder', async () => {
    const printed = await runPrintCanary(undefined, 'pi-agent');
    expect(printed.ok).toBe(false);
    if (printed.ok) throw new Error('expected an error result');
    expect(printed.error).toContain('bouncer harness shim pi-agent');
    expect(printed.error).not.toContain('<id>');
  });
});
