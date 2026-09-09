// The `shim-file` wiring codec (ADR-0006 § 6/7, ticket 15c): doctor's
// "was the printed shim cut, drifted, or never installed" detection for
// an in-process harness (pi-agent, omp). Unlike hook-file/codex-hooks,
// there is no per-event settings shape to read here — pi-agent/omp never
// write stdin themselves, the ONE installed shim relays every event the
// declaration names uniformly, so there is no separate "PreToolUse
// wired"/"canary" concept to check per event; two checks instead:
//
// - `wiring:shim` — the installed `<dir>/extensions/bouncer.ts` exists
//   and is byte-identical to what `bouncer harness shim <id>` prints
//   TODAY, rendered with the SAME `BOUNCER` path the installed copy
//   ALREADY carries (never this doctor process's own `process.execPath`
//   — a doctor run from a different checkout must never claim drift
//   solely because its own binary happens to live somewhere else; compare
//   AFTER substitution, per the ticket's own contract).
// - `wiring:binary` — that baked `BOUNCER` path resolves to an
//   executable file (the one thing the shim itself cannot verify at
//   spawn time without literally trying, which is exactly what its own
//   fail-closed spawn-failure branch already covers live).

import { access, constants as fsConstants, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { HarnessDeclaration } from '../../../policy/schema.ts';
import type { DoctorCheck } from '../../doctor.ts';
import { configDirFor } from '../../log-path.ts';
import { renderShim } from '../../shim.ts';

/** `<configDir>/extensions/bouncer.ts` — this codec's own file, under the target harness's account directory. */
export function shimPathFor(harness: HarnessDeclaration): string {
  return join(configDirFor(harness), 'extensions', 'bouncer.ts');
}

export type ShimReadResult =
  | { readonly kind: 'absent'; }
  | { readonly kind: 'ok'; readonly content: string; }
  | { readonly kind: 'corrupt'; readonly detail: string; };

export async function readShimFile(shimPath: string): Promise<ShimReadResult> {
  try {
    const content = await readFile(shimPath, 'utf8');
    return { kind: 'ok', content };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') return { kind: 'absent' };
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `unreadable: ${detail}` };
  }
}

// The installed shim's own baked `BOUNCER` path, read back out — the
// printed source's ONE substitution point
// (`const BOUNCER = process.env.BOUNCER_BIN ?? "<path>";`), inverted.
// `undefined` when the line is missing entirely (a hand-edited or
// unrelated file) — `checkShim`'s own drift message already names that,
// this just has nothing further to extract for `wiring:binary`.
const BOUNCER_LINE = /const BOUNCER = process\.env\.BOUNCER_BIN \?\? ("(?:[^"\\]|\\.)*");/;

export function extractBouncerPath(shimContent: string): string | undefined {
  const match = BOUNCER_LINE.exec(shimContent);
  if (match === null) return undefined;
  try {
    const parsed: unknown = JSON.parse(match[1]!);
    return typeof parsed === 'string' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

// `shimPath` names the resolved location in the two messages that never
// reach a SessionStart scream (`corrupt` — a genuine read error, rare
// enough that no committed fixture exercises it; `ok` — never rendered
// at all, success is silent) — useful there for a human running
// `bouncer doctor` manually. The three FAILURE messages that CAN reach
// a SessionStart scream (`absent`, the two "not a real shim" cases, and
// `drift`) instead name the fixed, harness-neutral relative label
// (`extensions/bouncer.ts`, matching this ticket's own exact expected
// wording) — a resolved scratch-account path there would make
// `fixtures/protocol/pi-agent.json`'s own captured SessionStart-broken
// case unreproducible byte for byte (a fresh temp dir every capture).
const SHIM_LABEL = 'extensions/bouncer.ts';

export function checkShim(result: ShimReadResult, shimPath: string, harnessId: string): DoctorCheck {
  const id = 'wiring:shim';
  if (result.kind === 'corrupt') {
    return { id, ok: false, message: `${shimPath} ${result.detail}` };
  }
  if (result.kind === 'absent') {
    return {
      id,
      ok: false,
      message: `${SHIM_LABEL} is missing — print it with \`bouncer harness shim ${harnessId}\` and write it there`,
    };
  }
  const bouncerPath = extractBouncerPath(result.content);
  if (bouncerPath === undefined) {
    return {
      id,
      ok: false,
      message: `${SHIM_LABEL} does not look like a printed bouncer shim (no BOUNCER path found) — reprint it`,
    };
  }
  const canonical = renderShim(harnessId, bouncerPath);
  if (canonical === undefined) {
    return { id, ok: false, message: `harness ${JSON.stringify(harnessId)} has no embedded shim to compare against` };
  }
  if (result.content !== canonical) {
    return { id, ok: false, message: `${SHIM_LABEL} differs from \`bouncer harness shim ${harnessId}\`; reprint it` };
  }
  return { id, ok: true, message: `${shimPath} matches the printed shim` };
}

export async function checkShimBinary(result: ShimReadResult): Promise<DoctorCheck> {
  const id = 'wiring:binary';
  if (result.kind !== 'ok') {
    return { id, ok: false, message: 'cannot verify — the shim itself is unreadable/missing (see wiring:shim)' };
  }
  const bouncerPath = extractBouncerPath(result.content);
  if (bouncerPath === undefined) {
    return { id, ok: false, message: 'cannot verify — no BOUNCER path found in the installed shim (see wiring:shim)' };
  }
  try {
    await access(bouncerPath, fsConstants.X_OK);
    return { id, ok: true, message: `${bouncerPath} is executable` };
  } catch {
    return {
      id,
      ok: false,
      message: `${bouncerPath} is not executable (or does not exist) — every tool call would fail closed`,
    };
  }
}
