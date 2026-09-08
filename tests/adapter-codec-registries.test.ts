// Review round 1 S-3: a codec name lint accepts (src/policy/harness.ts's
// KNOWN_INPUT_CODECS / KNOWN_WIRINGS) but the runtime registries
// (src/adapter/codecs/input/registry.ts's INPUT_CODECS, src/adapter/
// codecs/wiring/registry.ts's WIRING_CODECS) do not implement is a
// declaration that lints clean and then fails to dispatch at runtime —
// silently, before this ticket's own S-3 fix added a stderr warn(). This
// test catches that drift directly, at the two registries themselves,
// rather than relying on every future codec addition remembering to keep
// both hand-kept pairs in lockstep.

import { describe, expect, test } from 'bun:test';
import { INPUT_CODECS } from '../src/adapter/codecs/input/registry.ts';
import { WIRING_CODECS } from '../src/adapter/codecs/wiring/registry.ts';
import { KNOWN_INPUT_CODECS, KNOWN_WIRINGS } from '../src/policy/harness.ts';

describe('codec registry parity (S-3)', () => {
  test('KNOWN_INPUT_CODECS (lint-time) and INPUT_CODECS (runtime) name the same set', () => {
    expect(Object.keys(INPUT_CODECS).toSorted()).toEqual(Object.keys(KNOWN_INPUT_CODECS).toSorted());
  });

  test('KNOWN_WIRINGS (lint-time) and WIRING_CODECS (runtime) name the same set', () => {
    expect(Object.keys(WIRING_CODECS).toSorted()).toEqual(Object.keys(KNOWN_WIRINGS).toSorted());
  });

  test('every registry is non-empty — an accidentally-emptied registry would pass the set-equality checks above vacuously', () => {
    expect(Object.keys(INPUT_CODECS).length).toBeGreaterThan(0);
    expect(Object.keys(WIRING_CODECS).length).toBeGreaterThan(0);
  });
});
