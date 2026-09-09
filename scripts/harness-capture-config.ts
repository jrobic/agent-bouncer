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
  /** The wiring artifact's own relative path under that account dir (a `settings.json`/`hooks.json` basename, or — for a `shim-file` harness — `extensions/bouncer.ts`). */
  readonly settingsFile: string;
  /** Extra tokens `run`/`doctor`/etc. need beyond the bare subcommand. */
  readonly flagArgs: readonly string[];
  /** The wiring-fixture PreToolUse command a hooks/settings file should point at, given the (fake or real) bouncer binary path. Unused for `wiring: "shim"` (ticket 15c: the artifact IS the shim source, not a JSON entry pointing at one). */
  readonly wiringCommand: (bouncerPath: string) => string;
  /** The PreToolUse matcher regex covering every guarded tool this harness declares, derived from its own real protocol.tools — never hand-typed. Unused for `wiring: "shim"` (no per-event matcher concept). */
  readonly matcher: string;
  /** `"settings"` (default shape, hook-file/codex-hooks): capture-protocol.ts writes `{hooks: settings}` and splices a canary. `"shim"` (ticket 15c, pi-agent): capture-protocol.ts writes the rendered shim source itself instead, no canary concept. */
  readonly wiring: 'settings' | 'shim';
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
    wiring: 'settings',
  },
  codex: {
    exec: ['bun', 'run', join(PROJECT_ROOT, 'src', 'cli.ts')],
    envVar: 'CODEX_HOME',
    settingsFile: 'hooks.json',
    flagArgs: ['--harness', 'codex'],
    wiringCommand: (bouncerPath) => `${bouncerPath} run --harness codex`,
    matcher: matcherFor('codex'),
    wiring: 'settings',
  },
  'pi-agent': {
    // Source capture (ADR-0006 § 10, same reasoning as codex): the
    // installed binary predates pi-agent.toml's own [harness.protocol].
    exec: ['bun', 'run', join(PROJECT_ROOT, 'src', 'cli.ts')],
    envVar: 'PI_CODING_AGENT_DIR',
    settingsFile: 'extensions/bouncer.ts',
    flagArgs: ['--harness', 'pi-agent'],
    wiringCommand: (bouncerPath) => `${bouncerPath} run --harness pi-agent`,
    matcher: matcherFor('pi-agent'),
    wiring: 'shim',
  },
};

export function harnessCaptureFor(harnessId: string): HarnessCaptureRecord {
  const record = HARNESS_CAPTURE[harnessId];
  if (record === undefined) throw new Error(`harness-capture-config.ts: no capture config for harness ${JSON.stringify(harnessId)}`);
  return record;
}
