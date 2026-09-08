// The runtime wiring-codec registry (ADR-0006 § 6): `doctor` reads a
// harness's declared `protocol.wiring` name and dispatches to the codec
// it names — src/policy/harness.ts's KNOWN_WIRINGS is this registry's
// LINT-TIME counterpart (proving a declaration only ever names a real
// codec); the two are hand-kept in lockstep, reviewed together, same as
// KNOWN_INPUT_CODECS/src/adapter/neutral-call.ts's own INPUT_CODECS pair.
//
// Every codec below answers the same four questions doctor.ts and
// src/cli-commands.ts's runDoctor/runPrintCanary need, regardless of how
// many files or what shape that codec's own wiring source actually is:
// where does it live by default, how is it read, what extra checks (if
// any) does it add beyond the settings/wiring/canary checks every codec
// shares, and how is the canonical canary entry rendered for it.

import type { HarnessDeclaration, HarnessProtocol } from '../../../policy/schema.ts';
import type { DoctorCheck } from '../../doctor.ts';
import { checkCodexTrust, formatCodexCanonicalCanaryEntry, readCodexHooksForDoctor } from './codex-hooks.ts';
import {
  type CanonicalCanaryEntry,
  formatCanonicalCanaryEntry,
  readSettingsFile,
  settingsPathFor,
  type WiringReadResult,
} from './hook-file.ts';

export interface WiringCodec {
  /**
   * Reads (and, for a multi-source codec, merges) the raw wiring config.
   * Review round 1 S-1/S-2/P-5: the result carries its OWN label and
   * effective path — `corrupt` names the file that broke, `absent`
   * names every candidate path, `ok` names exactly what was parsed —
   * instead of doctor.ts guessing a single hardcoded default path/label
   * regardless of which source actually produced the result.
   */
  readonly read: (pathOverride: string | undefined, harness: HarnessDeclaration, protocol: HarnessProtocol) => Promise<WiringReadResult>;
  /**
   * Checks beyond settings/wiring/canary this codec alone needs
   * (codex-hooks' hook-trust ledger; none for hook-file). Review round 2
   * C-2: takes the SAME `WiringReadResult` `read()` already produced
   * (specifically its `raw` field) instead of re-reading the source(s)
   * from disk a second time — one filesystem read per source per
   * `doctor` run, not two.
   */
  readonly extraChecks: (result: WiringReadResult, protocol: HarnessProtocol) => Promise<readonly DoctorCheck[]>;
  /** `doctor --print-canary`'s canonical entry for this codec's own file shape. */
  readonly formatCanonicalCanaryEntry: (
    pathOverride: string | undefined,
    harness: HarnessDeclaration,
    protocol: HarnessProtocol,
  ) => Promise<CanonicalCanaryEntry>;
}

const HOOK_FILE_CODEC: WiringCodec = {
  read: async (pathOverride, harness) => {
    const path = pathOverride ?? settingsPathFor(harness);
    return { settings: await readSettingsFile(path), label: 'settings.json', path };
  },
  extraChecks: async () => [],
  formatCanonicalCanaryEntry: (pathOverride, harness, protocol) =>
    formatCanonicalCanaryEntry(pathOverride ?? settingsPathFor(harness), protocol),
};

const CODEX_HOOKS_CODEC: WiringCodec = {
  read: readCodexHooksForDoctor,
  extraChecks: async (result, protocol) => [checkCodexTrust(result, protocol)],
  formatCanonicalCanaryEntry: formatCodexCanonicalCanaryEntry,
};

// Exported for the S-3 parity test (tests/adapter-codec-registries.test.ts):
// this runtime registry and src/policy/harness.ts's KNOWN_WIRINGS
// lint-time registry must name the same key set.
export const WIRING_CODECS: Readonly<Record<string, WiringCodec>> = {
  'hook-file': HOOK_FILE_CODEC,
  'codex-hooks': CODEX_HOOKS_CODEC,
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
