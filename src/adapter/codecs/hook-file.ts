// The `hook-file` wiring codec (ADR-0006 § 6): doctor's "was the hook cut
// by accident" detection, generalized off the pre-15a hardcoded Claude
// Code settings.json reader — reads the JSON file named by this codec's
// own convention (`<configDir>/settings.json`, Claude Code's own shape)
// under the TARGET harness's account directory, checks that each of its
// declared events (`protocol.events.pre_tool`/`prompt`/`session_start`)
// names a command whose executable basename is `bouncer`, whose args
// contain `run` and — for any harness other than `claude-code` — also
// `--harness <id>` (a bare `bouncer run` under a non-default harness would
// silently run with the DEFAULT harness's table instead, ADR-0006 § 9).
// Matcher coverage, the canary entry, and the shadow/typo token checks are
// moved here verbatim from the pre-15a src/adapter/doctor.ts.

import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { HarnessDeclaration, HarnessProtocol, HarnessToolRow } from '../../policy/schema.ts';
import { buildCanaryCommand, inspectCanaryCommand } from '../canary.ts';
import { DEFAULT_HARNESS_ID, HOOK_NAME } from '../constants.ts';
import type { DoctorCheck } from '../doctor.ts';
import { configDirFor } from '../log-path.ts';

export type SettingsReadResult =
  | { readonly kind: 'absent'; }
  | { readonly kind: 'ok'; readonly settings: RawHookEntry; }
  | { readonly kind: 'corrupt'; readonly detail: string; };

type RawHookEntry = Readonly<Record<string, unknown>>;

/** `<configDir>/settings.json` — this codec's own file, under the target harness's account directory. */
export function settingsPathFor(harness: HarnessDeclaration): string {
  return join(configDirFor(harness), 'settings.json');
}

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
export async function readSettingsFile(settingsPath: string): Promise<SettingsReadResult> {
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

export function checkSettings(result: SettingsReadResult, settingsPath: string): DoctorCheck {
  if (result.kind === 'corrupt') {
    return { id: 'settings', ok: false, message: `settings.json ${result.detail} (${settingsPath})` };
  }
  if (result.kind === 'absent') {
    return { id: 'settings', ok: true, message: `settings.json not found at ${settingsPath} (no hooks configured yet)` };
  }
  return { id: 'settings', ok: true, message: `settings.json parsed (${settingsPath})` };
}

function entriesFor(settings: RawHookEntry, event: string): readonly RawHookEntry[] {
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

function wiredInShadowMode(entries: readonly RawHookEntry[]): boolean {
  return bouncerCommandsOf(entries).some((command) => command.trim().split(/\s+/).includes('--shadow'));
}

// Every harness other than `claude-code` MUST carry `--harness <id>` on
// its own wiring — a bare `bouncer run` reads as claude-code's table
// (ADR-0006 § 9), silently fail-open on any harness whose confirm
// degrades differently. `claude-code` itself does not require the flag
// (it is the default), but tolerates it redundantly.
function knownRunTokens(harnessId: string): ReadonlySet<string> {
  return new Set(['run', '--shadow', '--harness', harnessId]);
}

function hasHarnessFlag(command: string, harnessId: string): boolean {
  const tokens = command.trim().split(/\s+/);
  const flagIndex = tokens.indexOf('--harness');
  return flagIndex !== -1 && tokens[flagIndex + 1] === harnessId;
}

function unrecognizedTokensIn(command: string, harnessId: string): string[] {
  const [, ...args] = command.trim().split(/\s+/);
  const known = knownRunTokens(harnessId);
  return args.filter((arg) => !known.has(arg));
}

function unrecognizedTokensAmong(entries: readonly RawHookEntry[], harnessId: string): string[] {
  return [...new Set(bouncerCommandsOf(entries).flatMap((command) => unrecognizedTokensIn(command, harnessId)))];
}

type MatcherCoverage =
  | { readonly kind: 'covers'; }
  | { readonly kind: 'gap'; }
  | { readonly kind: 'unparseable'; readonly matcher: string; readonly detail: string; };

// Every literal tool name a PreToolUse matcher must cover, derived from
// the harness's OWN tools map (not a hardcoded list) — an exact row name
// verbatim, a trailing-`*` glob row substituted with one representative
// literal name so the coverage check has something concrete to test a
// compiled matcher regex against.
export function representativeToolNames(tools: Readonly<Record<string, HarnessToolRow>>): readonly string[] {
  return Object.keys(tools).map((name) => (name.endsWith('*') ? `${name.slice(0, -1)}example__probe` : name));
}

// Claude Code's own matcher semantics, not a generic regex reading: an
// ABSENT matcher on a hook entry means "run for every tool" (the entry
// applies unconditionally), and the literal string `"*"` is CC's
// documented wildcard shorthand for the same thing — neither is a regex
// fragment to compile. Treating them as regex source was a prior review
// round's cry-wolf bug: `new RegExp('^(?:*)$')` throws (nothing to repeat),
// screaming on a config that is actually fully healthy.
function evaluateMatcherCoverage(entries: readonly RawHookEntry[], expectedTools: readonly string[]): MatcherCoverage {
  const matcherFields = entries.map((entry) => ownValue(entry, 'matcher'));
  if (matcherFields.some((m) => m === undefined)) return { kind: 'covers' };

  const stringMatchers = matcherFields.filter((m): m is string => typeof m === 'string');
  if (stringMatchers.some((m) => m === '*')) return { kind: 'covers' };

  const compiled: RegExp[] = [];
  for (const m of stringMatchers) {
    try {
      compiled.push(new RegExp(`^(?:${m})$`));
    } catch (err) {
      return { kind: 'unparseable', matcher: m, detail: err instanceof Error ? err.message : String(err) };
    }
  }
  const allCovered = expectedTools.every((tool) => compiled.some((re) => re.test(tool)));
  return allCovered ? { kind: 'covers' } : { kind: 'gap' };
}

export type WiringEventKind = 'pre_tool' | 'prompt' | 'session_start';

export function checkWiring(
  settingsResult: SettingsReadResult,
  protocol: HarnessProtocol,
  harnessId: string,
  eventKind: WiringEventKind,
): DoctorCheck {
  const eventName = protocol.events[eventKind];
  // Review round 2 R2-1: `prompt`/`session_start` are optional on a
  // harness's own declaration now — the caller (doctor.ts's
  // runDoctorChecks) skips this event entirely when the harness doesn't
  // declare it, so this is unreachable in practice; kept as a real
  // check, not a non-null assertion, so a future caller that forgets to
  // skip fails loud instead of crashing.
  if (eventName === undefined) {
    return { id: `wiring:${eventKind}`, ok: false, message: `harness declares no ${eventKind} event — nothing to check` };
  }
  const id = `wiring:${eventName}`;

  if (settingsResult.kind === 'corrupt') {
    return { id, ok: false, message: `cannot verify — settings.json is unreadable/malformed (see the settings check)` };
  }

  const settings = settingsResult.kind === 'ok' ? settingsResult.settings : {};
  const wired = entriesPointingAtBouncer(entriesFor(settings, eventName));

  if (wired.length === 0) {
    return {
      id,
      ok: false,
      message: `${eventName} hook is missing or does not point at ${HOOK_NAME} — this event runs unguarded`,
    };
  }

  const unrecognized = unrecognizedTokensAmong(wired, harnessId);
  if (unrecognized.length > 0) {
    return {
      id,
      ok: false,
      message: `${eventName} hook command has unrecognized token(s) ${unrecognized.map((t) => JSON.stringify(t)).join(', ')} `
        + `— likely a typo (e.g. --shadwo instead of --shadow); the tool call itself still runs safely `
        + `(enforce mode), but the wiring doesn't say what you meant`,
    };
  }

  if (harnessId !== DEFAULT_HARNESS_ID && !bouncerCommandsOf(wired).some((command) => hasHarnessFlag(command, harnessId))) {
    return {
      id,
      ok: false,
      message: `${eventName} hook does not carry --harness ${harnessId} — a bare "${HOOK_NAME} run" would judge `
        + `this tool call against claude-code's table instead`,
    };
  }

  if (eventKind === 'pre_tool') {
    const coverage = evaluateMatcherCoverage(wired, representativeToolNames(protocol.tools));
    if (coverage.kind === 'unparseable') {
      return {
        id,
        ok: false,
        message: `${eventName} hook is wired but its matcher ${JSON.stringify(coverage.matcher)} is unparseable `
          + `as a regex (${coverage.detail}) — treated as failing, never silently accepted`,
      };
    }
    if (coverage.kind === 'gap') {
      return {
        id,
        ok: false,
        message: `${eventName} hook is wired but its matcher does not cover every guarded tool declared by `
          + `${harnessId}'s protocol — some tool calls run unguarded`,
      };
    }
  }

  const shadowSuffix = wiredInShadowMode(wired) ? ' (shadow mode)' : '';
  return { id, ok: true, message: `${eventName} is correctly wired${shadowSuffix}` };
}

export function checkCanary(settingsResult: SettingsReadResult, protocol: HarnessProtocol): DoctorCheck {
  const id = 'wiring:canary';
  if (settingsResult.kind === 'corrupt') {
    return { id, ok: false, message: 'cannot verify — settings.json is unreadable/malformed (see the settings check)' };
  }

  const preToolUseEventName = protocol.events.pre_tool;
  const settings = settingsResult.kind === 'ok' ? settingsResult.settings : {};
  const preToolUseEntries = entriesFor(settings, preToolUseEventName);
  const primaryEntries = entriesPointingAtBouncer(preToolUseEntries);
  if (primaryEntries.length === 0) {
    return { id, ok: false, message: `cannot verify — the primary ${preToolUseEventName} ${HOOK_NAME} entry is missing` };
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
        return { id, ok: false, message: `${preToolUseEventName} canary for ${binaryPath} has no canonical deny-on-failure branch` };
      }
      if (canaryCommands.some((command) => command.kind !== 'other')) {
        return { id, ok: false, message: `${preToolUseEventName} canary points at a different binary path than ${binaryPath}` };
      }
      return { id, ok: false, message: `${preToolUseEventName} canary is missing for ${binaryPath}` };
    }
  }

  const shadowSuffix = wiredInShadowMode(primaryEntries)
    ? ' (primary wiring is in shadow mode; the canary remains enforcing)'
    : '';
  return { id, ok: true, message: `${preToolUseEventName} canary is correctly wired${shadowSuffix}` };
}

export type CanonicalCanaryEntry =
  | { readonly entry: string; readonly error?: undefined; }
  | { readonly entry?: undefined; readonly error: string; };

export async function formatCanonicalCanaryEntry(settingsPath: string, protocol: HarnessProtocol): Promise<CanonicalCanaryEntry> {
  const settingsResult = await readSettingsFile(settingsPath);
  if (settingsResult.kind !== 'ok') {
    return { error: `cannot read a settings object from ${settingsPath}` };
  }
  const primaryEntry = entriesPointingAtBouncer(entriesFor(settingsResult.settings, protocol.events.pre_tool))[0];
  if (primaryEntry === undefined) {
    return { error: `no ${protocol.events.pre_tool} entry points at a bouncer binary in ${settingsPath}` };
  }
  const binaryPath = bouncerCommandsOf([primaryEntry])
    .map((command) => bouncerExecutable(command))
    .find((path): path is string => path !== undefined);
  if (binaryPath === undefined) {
    return { error: `no ${protocol.events.pre_tool} entry points at a bouncer binary in ${settingsPath}` };
  }

  const entry = {
    ...(Object.hasOwn(primaryEntry, 'matcher') ? { matcher: ownValue(primaryEntry, 'matcher') } : {}),
    hooks: [{ type: 'command', command: buildCanaryCommand(binaryPath) }],
  };
  return { entry: JSON.stringify(entry, null, 2) };
}
