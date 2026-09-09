// Embedded printed shims (ADR-0006 § 7, ticket 15c): the dumb, policy-
// free extension `bouncer harness shim <id>` prints for an in-process
// harness (pi-agent — `omp` shares the same printed file, ADR-0006 fact
// 5). One harness id maps to its own raw shim source; `bun build
// --compile` inlines the imported text exactly like every baseline TOML
// file (src/policy/baseline.ts) — there is no on-disk shim source to find
// at runtime.
//
// `__BOUNCER_BIN__` is the ONE substitution point: a bare, single-quoted
// placeholder the shim's own `BOUNCER` constant falls back to, swapped
// for a real absolute path at PRINT time (`harness shim`'s own call
// site, `process.execPath`, or `doctor`'s `wiring:shim` re-rendering the
// installed copy's own already-baked path for its drift comparison).
// `BOUNCER_BIN` still overrides it at the shim's own RUNTIME — the baked
// literal is only ever the fallback.

import piAgentShimSourceModule from '../../policy/harness/pi-agent.shim.ts' with { type: 'text' };

// Bun's `type: "text"` import attribute makes the import above resolve
// to the FILE'S RAW TEXT at runtime (verified live: `bun build
// --compile` embeds it exactly this way, same as every baseline TOML
// file below it) — but tsc has no notion of an import attribute
// changing a module's shape, so it still infers the import's type from
// the REAL `.ts` file's own exports (a function). This cast documents
// that gap; it is not a runtime unsafety — the value at runtime is
// always a string.
const piAgentShimSource = piAgentShimSourceModule as unknown as string;

// The exact, single-quoted token substituted — never a bare
// `__BOUNCER_BIN__` match, so this file's own comments (or the shim
// source's own header comment) can mention the placeholder's name in
// plain English without colliding with the real substitution site. The
// replacement itself is JSON-encoded (always double-quoted, JSON has no
// other string syntax) — the printed shim's one `BOUNCER` line ends up
// double-quoted, every other line single-quoted; cosmetic only.
const PLACEHOLDER = '\'__BOUNCER_BIN__\'';

const SHIM_SOURCES: Readonly<Record<string, string>> = {
  'pi-agent': piAgentShimSource,
};

/** `harness list`'s own `shim=yes|no` column (ADR-0006 § 7/9) and `harness shim <id>`'s own usage-error gate. */
export function hasShim(harnessId: string): boolean {
  return Object.hasOwn(SHIM_SOURCES, harnessId);
}

/**
 * `bouncer harness shim <id>` — the embedded source with `BOUNCER` baked
 * to `bouncerPath`, byte for byte otherwise. `undefined`: this harness
 * has no printable shim (a stdin-json hook harness, or an undeclared
 * id) — the caller renders that as a usage error, never a crash.
 */
export function renderShim(harnessId: string, bouncerPath: string): string | undefined {
  const source = SHIM_SOURCES[harnessId];
  if (source === undefined) return undefined;
  // Review round 1 S-1: `String.replace`'s SECOND argument, when a
  // string, interprets `$&`/`` $` ``/`$'`/`$n` as replacement patterns —
  // a `bouncerPath` containing one of those sequences (a real, if
  // unusual, absolute path) would corrupt the printed shim. A function
  // replacer's return value is inserted literally, no pattern
  // interpretation at all.
  return source.replace(PLACEHOLDER, () => JSON.stringify(bouncerPath));
}
