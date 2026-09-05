// The "the hook was cut by accident" detection layer. Claude-Code-specific
// (it reads the CC settings.json hooks shape), so it lives in the adapter,
// not in src/policy/ or src/*.ts.
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

import { access, constants as fsConstants, mkdir, open, readFile, stat } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import type { LoadResult } from '../policy/load.ts';
import { buildCanaryCommand, inspectCanaryCommand } from './canary.ts';
import { HOOK_NAME } from './constants.ts';
import { configDir, hookLogPath } from './log-path.ts';

export interface DoctorCheck {
  readonly id: string;
  readonly ok: boolean;
  readonly message: string;
}

export interface DoctorReport {
  readonly checks: readonly DoctorCheck[];
  readonly overrideCount: number;
  readonly overrideLines: readonly string[];
  readonly ok: boolean;
}

/** `<configDir>/settings.json` — the account's own settings file, same root as the policy overlay and the audit log. */
export function defaultSettingsPath(): string {
  return join(configDir(), 'settings.json');
}

// The three events a working install must wire: PreToolUse (the six guard
// families), UserPromptSubmit (prompt injection), and SessionStart (doctor
// itself — its own absence is exactly the "wiring was cut" case this
// module exists to catch).
const GUARDED_EVENTS = ['PreToolUse', 'UserPromptSubmit', 'SessionStart'] as const;
type GuardedEvent = (typeof GUARDED_EVENTS)[number];

// Representative tool names a PreToolUse matcher must cover. Exported so
// tests/doctor-fixtures.ts can build its scratch-settings matcher FROM this
// list (one source, not a hand-typed dual) instead of drifting apart from
// it — see that file for the settings.json shape these names appear in.
//
// Two real MCP tool names, not one made-up literal: a matcher that only
// happens to keep a synthetic `mcp__example-server__example_tool`-shaped
// name alive can still silently drop every REAL MCP tool call (different
// server-name punctuation, different segment count) — the false negative a
// prior review round flagged. `ctx_execute` is context-mode's actual name
// (this repo's own dev environment runs it); `filesystem`'s `read_file` is
// a second, differently-shaped real server, so a matcher narrowly tuned to
// one server's naming convention still gets caught.
export const EXPECTED_PRETOOLUSE_TOOLS: readonly string[] = [
  'Bash',
  'Read',
  'Edit',
  'MultiEdit',
  'Write',
  'NotebookEdit',
  'Grep',
  'Glob',
  'mcp__plugin_context-mode_context-mode__ctx_execute',
  'mcp__filesystem__read_file',
];

type RawHookEntry = Readonly<Record<string, unknown>>;

type SettingsReadResult =
  | { readonly kind: 'absent'; }
  | { readonly kind: 'ok'; readonly settings: RawHookEntry; }
  | { readonly kind: 'corrupt'; readonly detail: string; };

function recordFrom(value: unknown): RawHookEntry | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as RawHookEntry;
}

function ownValue(record: RawHookEntry, key: string): unknown {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

// Absent and corrupt are NOT the same failure, and reporting them as one
// ("hook missing") would name the wrong problem: a fresh account with no
// settings.json yet is normal (the wiring checks below say so, correctly,
// on their own), but an existing settings.json that fails to read or parse
// means doctor genuinely cannot see the wiring — that is a distinct,
// nameable fault (see checkSettings) the wiring checks must defer to
// rather than lie about.
async function readSettingsFile(settingsPath: string): Promise<SettingsReadResult> {
  let text: string;
  try {
    text = await readFile(settingsPath, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') return { kind: 'absent' };
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `unreadable: ${detail}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `malformed JSON: ${detail}` };
  }
  const settings = recordFrom(parsed);
  if (settings === null) {
    return { kind: 'corrupt', detail: 'settings.json does not contain a JSON object' };
  }
  return { kind: 'ok', settings };
}

function checkSettings(result: SettingsReadResult, settingsPath: string): DoctorCheck {
  if (result.kind === 'corrupt') {
    return { id: 'settings', ok: false, message: `settings.json ${result.detail} (${settingsPath})` };
  }
  if (result.kind === 'absent') {
    return { id: 'settings', ok: true, message: `settings.json not found at ${settingsPath} (no hooks configured yet)` };
  }
  return { id: 'settings', ok: true, message: `settings.json parsed (${settingsPath})` };
}

function entriesFor(settings: RawHookEntry, event: GuardedEvent): readonly RawHookEntry[] {
  const hooks = recordFrom(ownValue(settings, 'hooks'));
  if (hooks === null) return [];
  const forEvent = ownValue(hooks, event);
  if (!Array.isArray(forEvent)) return [];
  return forEvent.flatMap((entry) => {
    const parsed = recordFrom(entry);
    return parsed === null ? [] : [parsed];
  });
}

function commandsOf(entries: readonly RawHookEntry[]): string[] {
  const commands: string[] = [];
  for (const entry of entries) {
    const hooks = ownValue(entry, 'hooks');
    if (!Array.isArray(hooks)) continue;
    for (const rawHook of hooks) {
      const hook = recordFrom(rawHook);
      const command = hook === null ? undefined : ownValue(hook, 'command');
      if (typeof command === 'string') commands.push(command);
    }
  }
  return commands;
}

// A hook entry "points at bouncer" if its command's executable basename is
// this binary's own name and `run` is among its arguments — robust to
// wherever the binary is actually installed (absolute path in the demo,
// a PATH-resolved name in a real install), unlike a literal string match.
function bouncerExecutable(command: unknown): string | undefined {
  if (typeof command !== 'string') return undefined;
  const [executable, ...args] = command.trim().split(/\s+/);
  if (executable === undefined || basename(executable) !== HOOK_NAME || !args.includes('run')) return undefined;
  return executable;
}

function pointsAtBouncer(command: unknown): boolean {
  return bouncerExecutable(command) !== undefined;
}

function entriesPointingAtBouncer(entries: readonly RawHookEntry[]): readonly RawHookEntry[] {
  return entries.filter((entry) => commandsOf([entry]).some(pointsAtBouncer));
}

// Shadow and typo checks consume only true `bouncer run` commands, never
// the paired `sh -c … ping` canary: its shell tokens describe a separate
// liveness grammar and must not affect primary-wiring diagnosis.
function bouncerCommandsOf(entries: readonly RawHookEntry[]): string[] {
  return commandsOf(entries).filter(pointsAtBouncer);
}

// Ticket 08: `run --shadow` already satisfies pointsAtBouncer above (it
// only requires 'run' among the args, which --shadow doesn't remove) —
// this is purely the "say so" half: an entry wired with --shadow is
// healthy wiring, just worth naming in the manual checklist so a human
// running `bouncer doctor` mid-shadow-window sees at a glance which
// events are currently observe-only. Never affects `ok` — info, not fail.
function wiredInShadowMode(entries: readonly RawHookEntry[]): boolean {
  return bouncerCommandsOf(entries).some((command) => command.trim().split(/\s+/).includes('--shadow'));
}

// Ticket 08 review: `run()` itself treats an unrecognized argv token
// safely (never disarms enforcement — see adapter/run.ts's RunOptions
// comment), but a typo in the LIVE settings.json wiring (`--shadwo`
// instead of `--shadow`) is exactly the kind of thing worth a scream at
// SessionStart, not just a quiet log line: the account owner THINKS
// they're in shadow mode and are actually enforcing (safe), or vice
// versa in intent even if not in effect — either way the wiring doesn't
// say what the human meant, and this is the one place (SessionStart) it
// is actually actionable.
const KNOWN_RUN_TOKENS: ReadonlySet<string> = new Set(['run', '--shadow']);

function unrecognizedTokensIn(command: string): string[] {
  const [, ...args] = command.trim().split(/\s+/);
  return args.filter((arg) => !KNOWN_RUN_TOKENS.has(arg));
}

function unrecognizedTokensAmong(entries: readonly RawHookEntry[]): string[] {
  return [...new Set(bouncerCommandsOf(entries).flatMap(unrecognizedTokensIn))];
}

type MatcherCoverage =
  | { readonly kind: 'covers'; }
  | { readonly kind: 'gap'; }
  | { readonly kind: 'unparseable'; readonly matcher: string; readonly detail: string; };

// Claude Code's own matcher semantics, not a generic regex reading: an
// ABSENT matcher on a hook entry means "run for every tool" (the entry
// applies unconditionally), and the literal string `"*"` is CC's
// documented wildcard shorthand for the same thing — neither is a regex
// fragment to compile. Treating them as regex source was a prior review
// round's cry-wolf bug: `new RegExp('^(?:*)$')` throws (nothing to repeat),
// screaming on a config that is actually fully healthy.
function evaluateMatcherCoverage(entries: readonly RawHookEntry[]): MatcherCoverage {
  const matcherFields = entries.map((entry) => ownValue(entry, 'matcher'));
  if (matcherFields.some((m) => m === undefined)) return { kind: 'covers' };

  const stringMatchers = matcherFields.filter((m): m is string => typeof m === 'string');
  if (stringMatchers.some((m) => m === '*')) return { kind: 'covers' };

  const compiled: RegExp[] = [];
  for (const m of stringMatchers) {
    try {
      compiled.push(new RegExp(`^(?:${m})$`));
    } catch (err) {
      // An invalid matcher regex is a wiring fault to REPORT, not a
      // program error to throw — the settings.json a user hand-edits is
      // untrusted input like any other.
      return { kind: 'unparseable', matcher: m, detail: err instanceof Error ? err.message : String(err) };
    }
  }
  const allCovered = EXPECTED_PRETOOLUSE_TOOLS.every((tool) => compiled.some((re) => re.test(tool)));
  return allCovered ? { kind: 'covers' } : { kind: 'gap' };
}

function checkWiring(settingsResult: SettingsReadResult, event: GuardedEvent): DoctorCheck {
  const id = `wiring:${event}`;

  if (settingsResult.kind === 'corrupt') {
    return {
      id,
      ok: false,
      message: `cannot verify — settings.json is unreadable/malformed (see the settings check)`,
    };
  }

  const settings = settingsResult.kind === 'ok' ? settingsResult.settings : {};
  const wired = entriesPointingAtBouncer(entriesFor(settings, event));

  if (wired.length === 0) {
    return {
      id,
      ok: false,
      message: `${event} hook is missing or does not point at ${HOOK_NAME} — this event runs unguarded`,
    };
  }

  const unrecognized = unrecognizedTokensAmong(wired);
  if (unrecognized.length > 0) {
    return {
      id,
      ok: false,
      message: `${event} hook command has unrecognized token(s) ${unrecognized.map((t) => JSON.stringify(t)).join(', ')} `
        + `— likely a typo (e.g. --shadwo instead of --shadow); the tool call itself still runs safely `
        + `(enforce mode), but the wiring doesn't say what you meant`,
    };
  }

  if (event === 'PreToolUse') {
    const coverage = evaluateMatcherCoverage(wired);
    if (coverage.kind === 'unparseable') {
      return {
        id,
        ok: false,
        message: `PreToolUse hook is wired but its matcher ${JSON.stringify(coverage.matcher)} is unparseable `
          + `as a regex (${coverage.detail}) — treated as failing, never silently accepted`,
      };
    }
    if (coverage.kind === 'gap') {
      return {
        id,
        ok: false,
        message: `PreToolUse hook is wired but its matcher does not cover every guarded tool `
          + `(expected Bash/Read/Edit/MultiEdit/Write/NotebookEdit/Grep/Glob/mcp__*) — some tool calls run unguarded`,
      };
    }
  }

  const shadowSuffix = wiredInShadowMode(wired) ? ' (shadow mode)' : '';
  return { id, ok: true, message: `${event} is correctly wired${shadowSuffix}` };
}

function checkCanary(settingsResult: SettingsReadResult): DoctorCheck {
  const id = 'wiring:canary';
  if (settingsResult.kind === 'corrupt') {
    return {
      id,
      ok: false,
      message: 'cannot verify — settings.json is unreadable/malformed (see the settings check)',
    };
  }

  const settings = settingsResult.kind === 'ok' ? settingsResult.settings : {};
  const preToolUseEntries = entriesFor(settings, 'PreToolUse');
  const primaryEntries = entriesPointingAtBouncer(preToolUseEntries);
  if (primaryEntries.length === 0) {
    return {
      id,
      ok: false,
      message: `cannot verify — the primary PreToolUse ${HOOK_NAME} entry is missing`,
    };
  }

  for (const primaryEntry of primaryEntries) {
    const binaryPaths = bouncerCommandsOf([primaryEntry])
      .map((command) => bouncerExecutable(command))
      .filter((path): path is string => path !== undefined);
    const primaryMatcher = JSON.stringify(ownValue(primaryEntry, 'matcher'));
    const pairedEntries = preToolUseEntries.filter(
      (entry) => entry !== primaryEntry && JSON.stringify(ownValue(entry, 'matcher')) === primaryMatcher,
    );
    const canaryCommands = commandsOf(pairedEntries).map(inspectCanaryCommand);
    for (const binaryPath of binaryPaths) {
      if (canaryCommands.some((command) => command.kind === 'canonical' && command.binaryPath === binaryPath)) {
        continue;
      }
      if (canaryCommands.some((command) => command.kind === 'ping-probe' && command.binaryPath === binaryPath)) {
        return {
          id,
          ok: false,
          message: `PreToolUse canary for ${binaryPath} has no canonical deny-on-failure branch`,
        };
      }
      if (canaryCommands.some((command) => command.kind !== 'other')) {
        return {
          id,
          ok: false,
          message: `PreToolUse canary points at a different binary path than ${binaryPath}`,
        };
      }
      return {
        id,
        ok: false,
        message: `PreToolUse canary is missing for ${binaryPath}`,
      };
    }
  }

  const shadowSuffix = wiredInShadowMode(primaryEntries)
    ? ' (primary wiring is in shadow mode; the canary remains enforcing)'
    : '';
  return { id, ok: true, message: `PreToolUse canary is correctly wired${shadowSuffix}` };
}

export type CanonicalCanaryEntry =
  | { readonly entry: string; readonly error?: undefined; }
  | { readonly entry?: undefined; readonly error: string; };

export async function formatCanonicalCanaryEntry(settingsPath: string): Promise<CanonicalCanaryEntry> {
  const settingsResult = await readSettingsFile(settingsPath);
  if (settingsResult.kind !== 'ok') {
    return { error: `cannot read a settings object from ${settingsPath}` };
  }
  const primaryEntry = entriesPointingAtBouncer(entriesFor(settingsResult.settings, 'PreToolUse'))[0];
  if (primaryEntry === undefined) {
    return { error: `no PreToolUse entry points at a bouncer binary in ${settingsPath}` };
  }
  const binaryPath = bouncerCommandsOf([primaryEntry])
    .map((command) => bouncerExecutable(command))
    .find((path): path is string => path !== undefined);
  if (binaryPath === undefined) {
    return { error: `no PreToolUse entry points at a bouncer binary in ${settingsPath}` };
  }

  const entry = {
    ...(Object.hasOwn(primaryEntry, 'matcher') ? { matcher: ownValue(primaryEntry, 'matcher') } : {}),
    hooks: [{ type: 'command', command: buildCanaryCommand(binaryPath) }],
  };
  return { entry: JSON.stringify(entry, null, 2) };
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

async function checkLogWritability(): Promise<DoctorCheck> {
  const logFile = hookLogPath(HOOK_NAME);
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
 * SessionStart invocation never pays for a second load.
 */
export async function runDoctorChecks(settingsPath: string, loaded: LoadResult): Promise<DoctorReport> {
  const settingsResult = await readSettingsFile(settingsPath);
  const wiringChecks: DoctorCheck[] = [];
  for (const event of GUARDED_EVENTS) {
    wiringChecks.push(checkWiring(settingsResult, event));
    if (event === 'PreToolUse') wiringChecks.push(checkCanary(settingsResult));
  }
  const checks: DoctorCheck[] = [
    checkSettings(settingsResult, settingsPath),
    ...wiringChecks,
    checkPolicy(loaded),
    await checkLogWritability(),
  ];
  const overrideLines = overrideLinesOf(loaded);
  return {
    checks,
    overrideCount: overrideLines.length,
    overrideLines,
    ok: checks.every((c) => c.ok),
  };
}

/** The manual `bouncer doctor` form: every check, pass/fail, plus the override count — always printed, healthy or not. */
export function formatDoctorChecklist(report: DoctorReport): string {
  const lines = report.checks.map((c) => `[${c.ok ? 'pass' : 'fail'}] ${c.id} — ${c.message}`);
  lines.push(
    report.overrideCount > 0
      ? `overrides: ${report.overrideCount} active`
      : 'overrides: none active',
  );
  lines.push(...report.overrideLines.map((l) => `  - ${l}`));
  return lines.join('\n');
}

/**
 * The SessionStart hook form: `null` means fully silent (nothing on
 * stdout at all, indistinguishable from a healthy PreToolUse allow) —
 * reserved for the one case where every check passes AND no
 * override/relaxation is active. Anything else produces a message: a
 * genuine anomaly screams first (settings/wiring/policy/log), an override/
 * relaxation count is announced calmly after — Story 19's "impossible to
 * overlook, never silent" applies even when nothing is actually broken.
 */
export function buildSessionStartContext(report: DoctorReport): string | null {
  const failing = report.checks.filter((c) => !c.ok);
  if (failing.length === 0 && report.overrideCount === 0) return null;

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
  return lines.join('\n');
}
