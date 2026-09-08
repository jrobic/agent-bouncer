// The runtime input-codec registry (ADR-0006 § 6): a `[harness.protocol.
// tools]` row's `codec` field names a codec here — src/policy/harness.ts's
// KNOWN_INPUT_CODECS is this registry's LINT-TIME counterpart (proving a
// declaration only ever names a real codec); the two are hand-kept in
// lockstep, reviewed together, same discipline as KNOWN_WIRINGS/
// src/adapter/codecs/wiring/registry.ts's own WIRING_CODECS pair (S-4:
// one registry shape for every codec kind, not a bespoke pattern per
// kind — 15c adds `hashline` and `shim-file` onto this same shape).

import { applyPatchCodec } from './apply-patch.ts';

export type InputCodecResult = Readonly<{ paths: readonly string[]; text: string | null; }>;

export type InputCodec = (ti: Record<string, unknown>, hookName: string) => InputCodecResult;

// Exported for the S-3 parity test (tests/adapter-codec-registries.test.ts):
// this runtime registry and src/policy/harness.ts's KNOWN_INPUT_CODECS
// lint-time registry must name the same key set.
export const INPUT_CODECS: Readonly<Record<string, InputCodec>> = {
  'apply-patch': applyPatchCodec,
};

/**
 * Resolves a tool row's `codec` string to its runtime codec. `undefined`
 * means the lint-time and runtime registries drifted (`rules lint`
 * already proved the name is a member of KNOWN_INPUT_CODECS before this
 * row ever reached src/adapter/neutral-call.ts's buildNeutralCall) —
 * every caller treats that as a codec failure, never a crash.
 */
export function inputCodecFor(name: string): InputCodec | undefined {
  return INPUT_CODECS[name];
}
