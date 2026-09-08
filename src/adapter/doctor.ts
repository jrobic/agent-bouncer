// The "the hook was cut by accident" detection layer. Declaration-driven
// (ADR-0006 § 6): the wiring/canary/settings checks themselves are the
// `hook-file` codec (src/adapter/codecs/wiring/hook-file.ts); this module owns
// only what every harness shares regardless of its wiring codec — the
// policy/log checks, the report assembly, and the two output forms.
//
// Two report shapes come out of the SAME checks (runDoctorChecks), never
// two separate check passes — a SessionStart-mode divergence from the
// manual checklist would be exactly the kind of silent drift this feature
// exists to prevent:
//   - formatDoctorChecklist: the manual `bouncer doctor` form — always
//     verbose, pass/fail per item, printed regardless of health.
//   - buildSessionStartContext: the hook form — null (fully silent) when
//     every check passes AND no override/relaxation is active; otherwise a
//     message that screams (a real anomaly: wiring gap, broken overlay, an
//     unwritable log) or calmly announces (only overrides/relaxations are
//     active, nothing is actually broken) — but never both silent AND
//     something worth knowing.

import { access, constants as fsConstants, mkdir, open, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { EffectiveRule, LoadResult } from '../policy/load.ts';
import type { HarnessDeclaration } from '../policy/schema.ts';
import { checkCanary, checkSettings, checkWiring } from './codecs/wiring/hook-file.ts';
import { wiringCodecFor } from './codecs/wiring/registry.ts';
import { HOOK_NAME } from './constants.ts';
import { hookLogPathFor } from './log-path.ts';

export interface DoctorCheck {
  readonly id: string;
  readonly ok: boolean;
  // Review round 3 R3-1: a THIRD tag, `[warn]` — always paired with
  // `ok: true` (exit 0: nothing is broken), reserved for a fact that is
  // unprovable rather than unhealthy (today: a declared harness with no
  // `wiring` codec, ADR-0006 § 6's "visible rather than silently green").
  // `[pass]` alone would say the fact was actually verified, which it
  // wasn't; `[fail]` would say something is broken, which it isn't
  // either.
  readonly warn?: true;
  readonly message: string;
}

export interface DoctorReport {
  readonly checks: readonly DoctorCheck[];
  readonly overrideCount: number;
  readonly overrideLines: readonly string[];
  // ADR-0006 § 5: every harness declared or extended by an overlay,
  // named so it is impossible to overlook — never the baseline-only six,
  // which need no announcement.
  readonly overlayHarnessLines: readonly string[];
  readonly ok: boolean;
}

// ADR-0006 § 5/9: `harness <id> <provenance> transport=<t|none>
// confirm=<ask|deny|none> [ask_probe]` — the one line format every
// harness-naming surface (`doctor`, `rules list`, `harness list`) shares.
// Provenance and its source-file bracket are read off the harness's own
// `<id>-config-dir` derived protected-write row, which already carries
// the real baseline/overlay/baseline+overlay provenance and contributing
// file(s) (src/policy/load.ts's derivedHarnessRows) — never re-derived
// here.
export function harnessAnnouncementLine(harness: HarnessDeclaration, effectiveRules: readonly EffectiveRule[]): string {
  const configDirRule = effectiveRules.find((r) => r.harnessId === harness.id && r.rule.id === `${harness.id}-config-dir`);
  const provenance = configDirRule?.provenance ?? 'baseline';
  const files = configDirRule?.sourceFiles ?? (configDirRule?.sourceFile === undefined ? [] : [configDirRule.sourceFile]);
  const fileSuffix = files.length > 0 ? ` [${files.join(', ')}]` : '';
  const protocol = harness.protocol;
  const transport = protocol === undefined ? 'none' : protocol.transport;
  const confirm = protocol === undefined ? 'none' : protocol.output.confirm;
  const probeSuffix = protocol?.output.ask_probe !== undefined ? ` ask_probe=${JSON.stringify(protocol.output.ask_probe)}` : '';
  return `harness ${harness.id} ${provenance}${fileSuffix} transport=${transport} confirm=${confirm}${probeSuffix}`;
}

// Only the harnesses an overlay actually touched — the plain six-
// baseline case announces nothing (ADR-0006 § 5: an overlay-touched
// harness "is announced everywhere an override is", not every harness on
// every invocation). Filtered against LoadResult.overlayHarnessIds
// (review round 1 S-6) — the merge-time-authoritative list, never
// re-derived here by matching a harness id against a derived
// protected-write row id.
function overlayHarnessLinesOf(loaded: LoadResult): string[] {
  return loaded.policy.harness
    .filter((h) => loaded.overlayHarnessIds.includes(h.id))
    .map((h) => harnessAnnouncementLine(h, loaded.effectiveRules));
}

// ADR-0001 § Provenance: "; common: 4 files, profile: 0 files". `absent`
// specifically means the layer's ROOT DIRECTORY does not exist on disk
// (LayerInfo.root undefined), never merely "zero files": a root that
// exists but happens to be empty is a real, distinct, reachable state
// ("profile: 0 files") and must not collapse into "absent" too. An empty
// `layers` array (no per-layer information at all in this LoadResult)
// renders no suffix — nothing to name.
function layerCountSuffix(loaded: LoadResult): string {
  const parts = loaded.layers.map((l) => (l.root === undefined ? `${l.name}: absent` : `${l.name}: ${l.files.length} files`));
  return parts.length > 0 ? `; ${parts.join(', ')}` : '';
}

// The leading "overlay active"/"baseline active (every layer rejected)"/
// "baseline only" clause every policy message opens with, healthy or
// not. Three states: an overlay that genuinely never existed ("no
// overlay configured") and one that existed but got entirely rejected
// ("every layer rejected") are DIFFERENT stories a human debugging this
// needs told apart; both happen to leave `overlayApplied` false, so that
// alone can't distinguish them — `warnings.length > 0` is what actually
// separates "nothing was ever there" from "something was there and
// fell" (a rejected layer always leaves at least one warning; see
// src/policy/load.ts's warningsFor and the migration guard,
// src/adapter/policy.ts, which also warns without necessarily marking a
// layer `rejected`).
function policyStateSuffix(loaded: LoadResult): string {
  if (loaded.overlayApplied) return 'overlay active';
  if (loaded.warnings.length > 0) return 'baseline active (every layer rejected)';
  return 'baseline only (no overlay configured)';
}

// Every layer's own state, one entry per `loaded.layers` — `absent`
// mirrors layerCountSuffix's own rule (LayerInfo.root undefined, not
// merely zero files): "common: absent" belongs on every output this
// module produces, not only the pass path's layerCountSuffix.
function layerStateParts(loaded: LoadResult): string[] {
  return loaded.layers.map((l) => {
    if (l.rejected !== undefined) return `${l.name} layer rejected (${l.rejected.file}: ${l.rejected.reason})`;
    if (l.root === undefined) return `${l.name}: absent`;
    return `${l.name} active (${l.files.length} files)`;
  });
}

function checkPolicy(loaded: LoadResult): DoctorCheck {
  const tail = `(${loaded.effectiveRules.length} effective rules${layerCountSuffix(loaded)})`;
  const rejectedLayers = loaded.layers.filter((l) => l.rejected !== undefined);
  if (rejectedLayers.length > 0) {
    // ADR-0001 § Rejection, per layer: name which layer(s) fell and which
    // survived — a surviving layer next to a rejected one still has its
    // own rules and relaxations in effect, so `policyStateSuffix` alone
    // is never enough; the counters + effective rule count stay present
    // on this path too, not just the pass path.
    return { id: 'policy', ok: false, message: `${policyStateSuffix(loaded)} — ${layerStateParts(loaded).join(' ; ')} ${tail}` };
  }
  if (loaded.warnings.length > 0) {
    // A warning with no layer marked `rejected` at all — the migration
    // guard (src/adapter/policy.ts) is the only production source of
    // this shape: it warns without dropping a specific FILE, so no
    // `LayerInfo.rejected` gets set. The load may still be (partially)
    // applied either way — `policyStateSuffix` says which, never a
    // hardcoded "baseline active" that would lie when it's not.
    return { id: 'policy', ok: false, message: `${policyStateSuffix(loaded)} ${tail} — ${loaded.warnings.join('; ')}` };
  }
  return { id: 'policy', ok: true, message: `${policyStateSuffix(loaded)} ${tail}` };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function checkLogWritability(harness: HarnessDeclaration): Promise<DoctorCheck> {
  const logFile = hookLogPathFor(harness, HOOK_NAME);
  const dir = dirname(logFile);
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    if (await fileExists(logFile)) {
      // The file already exists: a writable DIRECTORY says nothing about
      // a read-only FILE inside it (chmod'd by hand, restored from a
      // read-only backup, ...) — and log.ts's appendLogEntry swallows its
      // own write failure (console.error only, by design: a broken log
      // must never crash the hook), so that failure mode is otherwise
      // completely silent audit loss, exactly the class of fault this
      // ticket exists to catch. Opening for append (and immediately
      // closing, writing nothing) is the SAME open() a real appendFile()
      // call makes — the most direct proof available short of writing a
      // real entry, which doctor must not do on a healthy, log-less setup.
      const handle = await open(logFile, 'a');
      await handle.close();
    } else {
      await access(dir, fsConstants.W_OK);
    }
    return { id: 'log', ok: true, message: `writable (${logFile})` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { id: 'log', ok: false, message: `NOT writable (${logFile}): ${message}` };
  }
}

function overrideLinesOf(loaded: LoadResult): string[] {
  return [
    ...loaded.activeOverrides.map((o) => `${o.rule} (${o.action}) — ${o.reason}`),
    ...loaded.activeRelaxations.map((r) => `${r.list}:${r.value} (relax) — ${r.reason}`),
  ];
}

/**
 * Runs every check and assembles the report both output forms read from.
 * `loaded` is the policy already loaded for this invocation (run.ts's
 * single per-invocation load, or cli-commands.ts's own `loadCurrentPolicy`
 * call for the manual command) — doctor never loads policy itself, so a
 * SessionStart invocation never pays for a second load. `harness` is the
 * TARGET harness this invocation is checking (`--harness <id>`, default
 * `claude-code`) — a harness declared without a `wiring` codec (ADR-0006
 * § 6) gets one `wiring: not checkable (declared harness)` line instead of
 * the settings/event/canary checks, which need a codec to mean anything.
 */
export async function runDoctorChecks(
  settingsPathOverride: string | undefined,
  loaded: LoadResult,
  harness: HarnessDeclaration,
): Promise<DoctorReport> {
  const protocol = harness.protocol;
  const wiringChecks: DoctorCheck[] = [];
  let settingsCheck: DoctorCheck | undefined;

  if (protocol === undefined || protocol.wiring === undefined) {
    wiringChecks.push({ id: 'wiring', ok: true, warn: true, message: 'not checkable (declared harness)' });
  } else {
    const codec = wiringCodecFor(protocol.wiring);
    if (codec === undefined) {
      // `rules lint` already proved protocol.wiring is a member of
      // src/policy/harness.ts's KNOWN_WIRINGS before this declaration
      // ever reached run() — an unresolvable name here means the
      // lint-time and runtime registries drifted, not a real wiring
      // problem; fail loud rather than crash the hook.
      wiringChecks.push({
        id: 'wiring',
        ok: false,
        message: `wiring codec ${JSON.stringify(protocol.wiring)} has no runtime implementation`,
      });
    } else {
      const readResult = await codec.read(settingsPathOverride, harness, protocol);
      const { settings: settingsResult, label, path: settingsPath } = readResult;
      settingsCheck = checkSettings(settingsResult, settingsPath, label);
      for (const eventKind of ['pre_tool', 'prompt', 'session_start'] as const) {
        if (protocol.events[eventKind] === undefined) continue;
        wiringChecks.push(checkWiring(settingsResult, protocol, harness.id, eventKind, label));
        if (eventKind === 'pre_tool') wiringChecks.push(checkCanary(settingsResult, protocol, label));
      }
      wiringChecks.push(...await codec.extraChecks(readResult, protocol));
    }
  }

  const checks: DoctorCheck[] = [
    ...(settingsCheck !== undefined ? [settingsCheck] : []),
    ...wiringChecks,
    checkPolicy(loaded),
    await checkLogWritability(harness),
  ];
  const overrideLines = overrideLinesOf(loaded);
  return {
    checks,
    overrideCount: overrideLines.length,
    overrideLines,
    overlayHarnessLines: overlayHarnessLinesOf(loaded),
    ok: checks.every((c) => c.ok),
  };
}

/** The manual `bouncer doctor` form: every check, pass/fail/warn, plus the override count — always printed, healthy or not. */
export function formatDoctorChecklist(report: DoctorReport): string {
  const lines = report.checks.map((c) => `[${c.warn === true ? 'warn' : c.ok ? 'pass' : 'fail'}] ${c.id} — ${c.message}`);
  lines.push(
    report.overrideCount > 0
      ? `overrides: ${report.overrideCount} active`
      : 'overrides: none active',
  );
  lines.push(...report.overrideLines.map((l) => `  - ${l}`));
  lines.push(...report.overlayHarnessLines);
  return lines.join('\n');
}

/**
 * The SessionStart hook form: `null` means fully silent (nothing on
 * stdout at all, indistinguishable from a healthy PreToolUse allow) —
 * reserved for the one case where every check passes, no check is a
 * `[warn]`, AND no override/relaxation is active. Anything else produces
 * a message: a genuine anomaly screams first (settings/wiring/policy/log
 * FAILURES), then two calm blocks — an override/relaxation count, and
 * (review round 3 R3-1) any `[warn]` check (unprovable, never unhealthy:
 * `ok` stays true, so it never joins the scream) — Story 19's
 * "impossible to overlook, never silent" applies even when nothing is
 * actually broken.
 */
export function buildSessionStartContext(report: DoctorReport): string | null {
  const failing = report.checks.filter((c) => !c.ok);
  const warnings = report.checks.filter((c) => c.warn === true);
  if (failing.length === 0 && report.overrideCount === 0 && warnings.length === 0) return null;

  const lines: string[] = [];
  if (failing.length > 0) {
    lines.push(
      `${HOOK_NAME} doctor: WIRING/POLICY PROBLEM DETECTED — this session may be running partially or fully unguarded.`,
    );
    lines.push(...failing.map((f) => `  - ${f.id}: ${f.message}`));
  }
  if (report.overrideCount > 0) {
    lines.push(
      `${HOOK_NAME} doctor: ${report.overrideCount} active override(s)/relaxation(s) — the effective policy is relaxed from the vetted baseline:`,
    );
    lines.push(...report.overrideLines.map((l) => `  - ${l}`));
  }
  if (warnings.length > 0) {
    lines.push(
      `${HOOK_NAME} doctor: ${warnings.length} check(s) unprovable, not broken — visible rather than silently green:`,
    );
    lines.push(...warnings.map((w) => `  - ${w.id}: ${w.message}`));
  }
  return lines.join('\n');
}
