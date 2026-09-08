#!/usr/bin/env bun
// Shared per-harness capture/probe configuration (review round 1 S-7):
// scripts/capture-protocol.ts used to key a harness in five separate
// structures (its own exec command, account-dir env var, wiring-file
// name, `--harness` flag args, and the wiring-fixture bouncer command),
// and codex's own probe helpers (probe-codex-write-hooks.ts,
// probe-codex-write-special-hooks.ts, probe-codex-derive-canary.ts) each
// carried an INDEPENDENT hand-typed copy of the SAME PreToolUse matcher
// regex — three literals, silently free to drift from each other and
// from the harness's own real declared tools map. One record per
// harness, derived from the same BASELINE every doctor/lint check
// already reads, imported everywhere a harness needs describing.

import { join } from 'node:path';
import { representativeToolNames } from '../src/adapter/codecs/wiring/hook-file.ts';
import { BASELINE } from '../src/policy/baseline.ts';

export interface HarnessCaptureRecord {
  /** The executable Bun.spawnSync actually invokes. */
  readonly exec: readonly string[];
  /** The account-dir env var this harness reads its config from (ADR-0005). */
  readonly envVar: string;
  /** The wiring file's own basename under that account dir. */
  readonly settingsFile: string;
  /** Extra tokens `run`/`doctor`/etc. need beyond the bare subcommand. */
  readonly flagArgs: readonly string[];
  /** The wiring-fixture PreToolUse command a hooks/settings file should point at, given the (fake or real) bouncer binary path. */
  readonly wiringCommand: (bouncerPath: string) => string;
  /** The PreToolUse matcher regex covering every guarded tool this harness declares, derived from its own real protocol.tools — never hand-typed. */
  readonly matcher: string;
}

function matcherFor(harnessId: string): string {
  const harness = BASELINE.rules.harness.find((h) => h.id === harnessId);
  const tools = harness?.protocol?.tools;
  if (tools === undefined) {
    throw new Error(`harness-capture-config.ts: harness ${JSON.stringify(harnessId)} has no protocol.tools to derive a matcher from`);
  }
  return representativeToolNames(tools).map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
}

const PROJECT_ROOT = join(import.meta.dir, '..');

export const HARNESS_CAPTURE: Readonly<Record<string, HarnessCaptureRecord>> = {
  'claude-code': {
    exec: [`${process.env.HOME}/.local/bin/bouncer`],
    envVar: 'CLAUDE_CONFIG_DIR',
    settingsFile: 'settings.json',
    flagArgs: [],
    wiringCommand: (bouncerPath) => `${bouncerPath} run`,
    matcher: matcherFor('claude-code'),
  },
  codex: {
    exec: ['bun', 'run', join(PROJECT_ROOT, 'src', 'cli.ts')],
    envVar: 'CODEX_HOME',
    settingsFile: 'hooks.json',
    flagArgs: ['--harness', 'codex'],
    wiringCommand: (bouncerPath) => `${bouncerPath} run --harness codex`,
    matcher: matcherFor('codex'),
  },
};

export function harnessCaptureFor(harnessId: string): HarnessCaptureRecord {
  const record = HARNESS_CAPTURE[harnessId];
  if (record === undefined) throw new Error(`harness-capture-config.ts: no capture config for harness ${JSON.stringify(harnessId)}`);
  return record;
}
