// The runtime wiring-codec registry (ADR-0006 § 6): `doctor` reads a
// harness's declared `protocol.wiring` name and dispatches to the codec
// it names — src/policy/harness.ts's KNOWN_WIRINGS is this registry's
// LINT-TIME counterpart (proving a declaration only ever names a real
// codec); the two are hand-kept in lockstep, reviewed together, same as
// KNOWN_INPUT_CODECS/src/adapter/codecs/input/registry.ts's own
// INPUT_CODECS pair.
//
// Every codec below answers the same two questions doctor.ts and
// src/cli-commands.ts's runDoctor/runPrintCanary need, regardless of how
// many files (or none, for an in-process shim) that codec's own wiring
// source actually is: what checks does its own wiring look like right
// now (`buildChecks` — S-4/ticket 15c: hook-file's and codex-hooks'
// settings-shaped settings/per-event/canary assembly moved HERE, into
// each codec's own closure, so shim-file's own two-check shape — no
// settings object, no per-event loop, no canary — is a real, equally
// legal WiringCodec rather than a special case doctor.ts has to branch
// on), and how is the canonical canary entry rendered for it (a concept
// shim-file has no equivalent of at all — an in-process harness's shim
// already fails closed on its own liveness, ADR-0006 § 7).

import type { HarnessDeclaration, HarnessProtocol } from '../../../policy/schema.ts';
import type { DoctorCheck } from '../../doctor.ts';
import { checkCodexTrust, formatCodexCanonicalCanaryEntry, readCodexHooksForDoctor } from './codex-hooks.ts';
import {
  type CanonicalCanaryEntry,
  checkCanary,
  checkSettings,
  checkWiring,
  formatCanonicalCanaryEntry,
  readSettingsFile,
  settingsPathFor,
  type SettingsReadResult,
} from './hook-file.ts';
import { checkShim, checkShimBinary, readShimFile, shimPathFor } from './shim-file.ts';

export interface WiringChecksResult {
  /** The top-level "can this codec's own file even be read" check — absent for a codec with no such single file (shim-file). */
  readonly settingsCheck?: DoctorCheck;
  readonly checks: readonly DoctorCheck[];
}

export interface WiringCodec {
  /**
   * Builds every check this codec's own wiring shape produces, given the
   * target harness's declared events and tools. Fully self-contained —
   * doctor.ts never inspects a codec's own file shape, settings object,
   * or event loop; it only ever assembles what this returns alongside
   * the shared policy/log checks.
   */
  readonly buildChecks: (
    pathOverride: string | undefined,
    harness: HarnessDeclaration,
    protocol: HarnessProtocol,
  ) => Promise<WiringChecksResult>;
  /** `doctor --print-canary`'s canonical entry for this codec's own file shape — an `error` result for a codec with no canary concept (shim-file). */
  readonly formatCanonicalCanaryEntry: (
    pathOverride: string | undefined,
    harness: HarnessDeclaration,
    protocol: HarnessProtocol,
  ) => Promise<CanonicalCanaryEntry>;
}

// Shared by hook-file and codex-hooks (S-5 discipline: one assembly, not
// two copies drifting apart) — both produce a real `SettingsReadResult`,
// the same `{hooks: {...}}` shape `checkWiring`/`checkCanary` have always
// read, merged or not. Skips an event this harness's own declaration
// doesn't carry (review round 2 R2-1: `prompt`/`session_start` are
// optional), and only checks the canary alongside `pre_tool` — there is
// exactly one PreToolUse-shaped canary per harness, never one per event.
function settingsShapedChecks(
  settingsResult: SettingsReadResult,
  protocol: HarnessProtocol,
  harnessId: string,
  label: string,
): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  for (const eventKind of ['pre_tool', 'prompt', 'session_start'] as const) {
    if (protocol.events[eventKind] === undefined) continue;
    checks.push(checkWiring(settingsResult, protocol, harnessId, eventKind, label));
    if (eventKind === 'pre_tool') checks.push(checkCanary(settingsResult, protocol, label));
  }
  return checks;
}

const HOOK_FILE_CODEC: WiringCodec = {
  buildChecks: async (pathOverride, harness, protocol) => {
    const path = pathOverride ?? settingsPathFor(harness);
    const settingsResult = await readSettingsFile(path);
    return {
      settingsCheck: checkSettings(settingsResult, path, 'settings.json'),
      checks: settingsShapedChecks(settingsResult, protocol, harness.id, 'settings.json'),
    };
  },
  formatCanonicalCanaryEntry: (pathOverride, harness, protocol) =>
    formatCanonicalCanaryEntry(pathOverride ?? settingsPathFor(harness), protocol),
};

const CODEX_HOOKS_CODEC: WiringCodec = {
  buildChecks: async (pathOverride, harness, protocol) => {
    const readResult = await readCodexHooksForDoctor(pathOverride, harness, protocol);
    const { settings: settingsResult, label, path } = readResult;
    return {
      settingsCheck: checkSettings(settingsResult, path, label),
      checks: [...settingsShapedChecks(settingsResult, protocol, harness.id, label), checkCodexTrust(readResult, protocol)],
    };
  },
  formatCanonicalCanaryEntry: formatCodexCanonicalCanaryEntry,
};

// ADR-0006 § 6/7, ticket 15c: pi-agent/omp are IN-PROCESS harnesses — the
// installed shim relays every event uniformly, so there is no per-event
// settings shape and no `settingsCheck` at all, only the two checks
// named below. No canary concept either: the printed shim already fails
// closed on its own liveness (bouncer missing/non-executable/non-zero
// exit/timeout, ADR-0006 § 7's own fixed rule 1) — `doctor --print-canary`
// for this wiring is a real, honest error, never a fabricated entry.
const SHIM_FILE_CODEC: WiringCodec = {
  buildChecks: async (pathOverride, harness, _protocol) => {
    const path = pathOverride ?? shimPathFor(harness);
    const result = await readShimFile(path);
    return { checks: [checkShim(result, path, harness.id), await checkShimBinary(result)] };
  },
  formatCanonicalCanaryEntry: async (_pathOverride, harness) => ({
    error: 'shim-file wiring has no canary entry — the printed shim already fails closed on its own '
      + `liveness (ADR-0006 § 7); print it with \`bouncer harness shim ${harness.id}\` instead`,
  }),
};

// Exported for the S-3 parity test (tests/adapter-codec-registries.test.ts):
// this runtime registry and src/policy/harness.ts's KNOWN_WIRINGS
// lint-time registry must name the same key set.
export const WIRING_CODECS: Readonly<Record<string, WiringCodec>> = {
  'hook-file': HOOK_FILE_CODEC,
  'codex-hooks': CODEX_HOOKS_CODEC,
  'shim-file': SHIM_FILE_CODEC,
};

/**
 * Resolves a declaration's `protocol.wiring` string to its runtime codec.
 * `undefined` means the lint-time and runtime registries drifted (`rules
 * lint` already proved the name is a member of KNOWN_WIRINGS before this
 * declaration ever reached here) — every caller treats that as a wiring
 * failure, never a crash.
 */
export function wiringCodecFor(name: string): WiringCodec | undefined {
  return WIRING_CODECS[name];
}
