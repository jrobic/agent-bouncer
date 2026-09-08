// The `codex-hooks` wiring codec (ADR-0006 § 6, ticket 15b): doctor's
// "was the hook cut by accident" detection for Codex CLI. Reads TWO
// additive sources under the target harness's account directory —
// `<dir>/hooks.json` (this codec's own file, same JSON hook-entry shape
// as Claude Code's `settings.json`) and the `[hooks]` table of
// `<dir>/config.toml` (Codex loads and runs hooks from BOTH, additively —
// measured 2026-09-07, hooks reference at developers.openai.com/codex/hooks)
// — merges them per event, then hands the merged result to
// src/adapter/codecs/wiring/hook-file.ts's own checkSettings/checkWiring/
// checkCanary/buildCanonicalCanaryEntry UNCHANGED: those functions only
// ever look at a `SettingsReadResult`'s `{hooks: {...}}` shape, never at
// which file it came from, so a merged multi-source read is a real,
// legal input to them, not a special case.
//
// Adds the one check hook-file.ts has no equivalent of: hook TRUST.
// Codex requires every hook definition to be trusted by hash before it
// runs (`/hooks` in the TUI); an untrusted or stale-hash hook is silently
// SKIPPED, so a wiring that looks complete can still leave a session
// unguarded. The trust ledger lives in `config.toml`'s own
// `[hooks.state."<source>:<event_snake>:<i>:<j>"]` table:
//   - `<source>` — the absolute path of the hooks.json file the entry
//     came from (`<plugin>@<marketplace>:hooks/codex-hooks.json` for a
//     plugin-provided file — not produced by this codec, which only ever
//     writes user-level `hooks.json`/`config.toml`), or, for an entry
//     read from config.toml's OWN `[hooks]` table, this codec's own
//     `configTomlPathFor(harness)` (a working hypothesis — see the 15b
//     report's trust-hash-rule section for how this was checked and
//     what to verify first if it turns out wrong).
//   - `<event_snake>` — the event name in snake_case (`PreToolUse` ->
//     `pre_tool_use`), verified against a real, populated
//     `~/.codex/config.toml` on 2026-09-07.
//   - `<i>` — the index of the matcher group within THAT SOURCE's own
//     array for the event (hooks.json and config.toml are indexed
//     independently — each is its own file Codex loads separately).
//   - `<j>` — the index of the handler within that group's own `hooks`
//     array.
// `trusted_hash = "sha256:<64 hex>"` — the exact hashing rule (command
// string only, the handler's own canonical JSON, or the whole matcher
// group) is UNDETERMINED as of this module's writing; see the 15b
// report. Until it is confirmed, this codec checks PRESENCE ONLY: every
// bouncer-pointing handler has SOME trust record with a non-empty
// `trusted_hash`, never that the hash is CURRENT — a real limitation
// (ADR-0006 § Consequences: "lint proves shape, never behavior" applies
// here to doctor's own trust check too), documented rather than silently
// assumed.

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { HarnessDeclaration, HarnessProtocol } from '../../../policy/schema.ts';
import type { DoctorCheck } from '../../doctor.ts';
import { configDirFor } from '../../log-path.ts';
import {
  bouncerExecutable,
  buildCanonicalCanaryEntry,
  type CanonicalCanaryEntry,
  entriesFor,
  type RawHookEntry,
  readSettingsFile,
  recordFrom,
  type SettingsReadResult,
  type WiringReadResult,
} from './hook-file.ts';

/** `<configDir>/hooks.json` — this codec's own primary source, under the target harness's account directory. */
export function hooksJsonPathFor(harness: HarnessDeclaration): string {
  return join(configDirFor(harness), 'hooks.json');
}

/** `<configDir>/config.toml` — Codex's own configuration file; its `[hooks]` table is this codec's second, additive source. */
export function configTomlPathFor(harness: HarnessDeclaration): string {
  return join(configDirFor(harness), 'config.toml');
}

type ConfigTomlHooksResult =
  | { readonly kind: 'absent'; }
  | { readonly kind: 'ok'; readonly hooks: RawHookEntry; readonly state: RawHookEntry; }
  | { readonly kind: 'corrupt'; readonly detail: string; };

async function readConfigTomlHooks(configTomlPath: string): Promise<ConfigTomlHooksResult> {
  let text: string;
  try {
    text = await readFile(configTomlPath, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') return { kind: 'absent' };
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `unreadable: ${detail}` };
  }
  let parsed: unknown;
  try {
    parsed = Bun.TOML.parse(text);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `malformed TOML: ${detail}` };
  }
  const root = recordFrom(parsed);
  if (root === null) return { kind: 'corrupt', detail: 'config.toml does not contain a table' };
  return { kind: 'ok', hooks: recordFrom(root['hooks']) ?? {}, state: recordFrom(recordFrom(root['hooks'])?.['state']) ?? {} };
}

function eventArray(hooksTable: RawHookEntry, event: string): unknown[] {
  const value = hooksTable[event];
  return Array.isArray(value) ? value : [];
}

/**
 * Reads BOTH sources once — S-5: the ONE place either entry point below
 * (readCodexHooksForDoctor, checkCodexTrust) touches the filesystem, so
 * they can never drift into two different reads of the same account.
 * Review round 2 C-2: the result is carried on `WiringReadResult.raw`
 * (readCodexHooksForDoctor, below) so `checkCodexTrust` can reuse it
 * from there instead of calling this a second time per `doctor` run —
 * not exported: codex-hooks.ts is the only module that ever creates or
 * consumes this shape, same module, never serialized.
 */
interface CodexRawSources {
  readonly hooksJsonPath: string;
  readonly configTomlPath: string;
  readonly hooksJsonResult: SettingsReadResult;
  readonly configTomlResult: ConfigTomlHooksResult;
}

async function readSources(pathOverride: string | undefined, harness: HarnessDeclaration): Promise<CodexRawSources> {
  const hooksJsonPath = pathOverride ?? hooksJsonPathFor(harness);
  const configTomlPath = configTomlPathFor(harness);
  const [hooksJsonResult, configTomlResult] = await Promise.all([
    readSettingsFile(hooksJsonPath),
    readConfigTomlHooks(configTomlPath),
  ]);
  return { hooksJsonPath, configTomlPath, hooksJsonResult, configTomlResult };
}

function mergedEventTable(
  events: readonly string[],
  hooksJsonResult: SettingsReadResult,
  configTomlResult: ConfigTomlHooksResult,
): RawHookEntry {
  const hooksJsonTable = hooksJsonResult.kind === 'ok' ? recordFrom(hooksJsonResult.settings['hooks']) ?? {} : {};
  const configTomlTable = configTomlResult.kind === 'ok' ? configTomlResult.hooks : {};
  const mergedHooks: Record<string, unknown> = {};
  for (const event of events) {
    mergedHooks[event] = [...eventArray(hooksJsonTable, event), ...eventArray(configTomlTable, event)];
  }
  return mergedHooks;
}

/**
 * Reads BOTH sources and merges them additively, per event — hooks.json
 * entries first, then config.toml `[hooks]` entries, for every event the
 * protocol declares (`pre_tool`, and `prompt`/`session_start` when
 * declared). The result is a real `SettingsReadResult`, the exact shape
 * hook-file.ts's own checkSettings/checkWiring/checkCanary already
 * consume — this codec adds no parallel checking logic for the merged
 * shape, only for the trust ledger (checkCodexTrust, below).
 *
 * `absent` only when BOTH files are missing outright — a `config.toml`
 * that exists but has no `[hooks]` table (Codex creates one on first run
 * regardless of hooks) contributes zero entries, which is `ok`, not
 * `absent`: nothing is unreadable, there is simply nothing wired from
 * that source yet. Either source unreadable/malformed makes the merged
 * read `corrupt` — doctor genuinely cannot see the wiring, the same
 * "cannot verify" contract a single corrupt settings.json already has.
 */
export async function readCodexHooks(
  pathOverride: string | undefined,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
): Promise<SettingsReadResult> {
  return (await readCodexHooksForDoctor(pathOverride, harness, protocol)).settings;
}

// Review round 1 S-1/S-2/P-5: doctor used to blame `hooksJsonPathFor()`
// for EVERY corrupt/absent/ok state regardless of which source actually
// produced it, and always said "settings.json" even for this codec's own
// `hooks.json`/`config.toml [hooks]`. `corrupt` now names the ONE file
// that broke; `absent` names both candidate paths (neither exists yet);
// `ok` names exactly the file(s) that were actually read — `hooks.json`
// alone, `config.toml [hooks]` alone, or both, never a file that was
// never opened. Review round 2 C-2: every branch also carries the raw
// sources on `.raw`, so `checkCodexTrust` (below, via registry.ts's
// `extraChecks`) never re-reads them.
export async function readCodexHooksForDoctor(
  pathOverride: string | undefined,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
): Promise<WiringReadResult> {
  const sources = await readSources(pathOverride, harness);
  const { hooksJsonPath, configTomlPath, hooksJsonResult, configTomlResult } = sources;

  if (hooksJsonResult.kind === 'corrupt') {
    return { settings: { kind: 'corrupt', detail: hooksJsonResult.detail }, label: 'hooks.json', path: hooksJsonPath, raw: sources };
  }
  if (configTomlResult.kind === 'corrupt') {
    return {
      settings: { kind: 'corrupt', detail: configTomlResult.detail },
      label: 'config.toml [hooks]',
      path: configTomlPath,
      raw: sources,
    };
  }
  if (hooksJsonResult.kind === 'absent' && configTomlResult.kind === 'absent') {
    return {
      settings: { kind: 'absent' },
      label: 'hooks.json / config.toml [hooks]',
      path: `${hooksJsonPath} or ${configTomlPath}`,
      raw: sources,
    };
  }

  const events = [protocol.events.pre_tool, protocol.events.prompt, protocol.events.session_start]
    .filter((event): event is string => event !== undefined);
  const mergedHooks = mergedEventTable(events, hooksJsonResult, configTomlResult);

  const presentLabels: string[] = [];
  const presentPaths: string[] = [];
  if (hooksJsonResult.kind === 'ok') {
    presentLabels.push('hooks.json');
    presentPaths.push(hooksJsonPath);
  }
  if (configTomlResult.kind === 'ok') {
    presentLabels.push('config.toml [hooks]');
    presentPaths.push(configTomlPath);
  }
  return {
    settings: { kind: 'ok', settings: { hooks: mergedHooks } },
    label: presentLabels.join(' + '),
    path: presentPaths.join(', '),
    raw: sources,
  };
}

// "PreToolUse" -> "pre_tool_use" — verified against real trust keys in
// `~/.codex/config.toml` on this workstation (2026-09-07): `pre_tool_use`,
// `user_prompt_submit`, `session_start`, `post_tool_use`, and six more
// events this codec never declares, all the same snake_case-of-CamelCase
// shape.
function eventSnakeCase(eventName: string): string {
  return eventName.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

interface TrustEntry {
  readonly source: string;
  readonly eventSnake: string;
  readonly groupIndex: number;
  readonly handlerIndex: number;
}

function bouncerTrustEntries(hooksTable: RawHookEntry, source: string, events: readonly string[]): TrustEntry[] {
  const out: TrustEntry[] = [];
  for (const event of events) {
    const groups = entriesFor({ hooks: hooksTable }, event);
    groups.forEach((group, groupIndex) => {
      const handlers = group['hooks'];
      if (!Array.isArray(handlers)) return;
      handlers.forEach((rawHandler, handlerIndex) => {
        const handler = recordFrom(rawHandler);
        if (handler !== null && bouncerExecutable(handler['command']) !== undefined) {
          out.push({ source, eventSnake: eventSnakeCase(event), groupIndex, handlerIndex });
        }
      });
    });
  }
  return out;
}

function isTrusted(state: RawHookEntry, entry: TrustEntry): boolean {
  const key = `${entry.source}:${entry.eventSnake}:${entry.groupIndex}:${entry.handlerIndex}`;
  const record = recordFrom(state[key]);
  const hash = record === null ? undefined : record['trusted_hash'];
  return typeof hash === 'string' && hash.length > 0;
}

/**
 * `wiring:trust` — every bouncer-pointing handler across BOTH sources
 * needs a trust record (presence-only, see the module comment above).
 * Zero bouncer handlers at all (nothing wired yet) is `ok`, not a
 * failure — checkWiring's own checks already name that as a missing
 * primary entry; this check only ever screams about handlers that ARE
 * wired but not (yet, or no longer) trusted. Review round 2 C-2: pure
 * and synchronous — reads `result.raw`, the SAME sources
 * `readCodexHooksForDoctor` already read for this `doctor` run, rather
 * than touching the filesystem again.
 */
export function checkCodexTrust(result: WiringReadResult, protocol: HarnessProtocol): DoctorCheck {
  // This codec's own read() (readCodexHooksForDoctor, above) always sets
  // `raw` to exactly this shape — same module, never serialized, so a
  // runtime shape check would only ever prove what the type already
  // guarantees.
  const sources = result.raw as CodexRawSources;
  const { hooksJsonPath, configTomlPath, hooksJsonResult, configTomlResult } = sources;
  if (hooksJsonResult.kind === 'corrupt' || configTomlResult.kind === 'corrupt') {
    return { id: 'wiring:trust', ok: false, message: 'cannot verify — a hooks source is unreadable/malformed (see the settings check)' };
  }

  const events = [protocol.events.pre_tool, protocol.events.prompt, protocol.events.session_start]
    .filter((event): event is string => event !== undefined);
  const hooksJsonTable = hooksJsonResult.kind === 'ok' ? recordFrom(hooksJsonResult.settings['hooks']) ?? {} : {};
  const configTomlTable = configTomlResult.kind === 'ok' ? configTomlResult.hooks : {};
  const state = configTomlResult.kind === 'ok' ? configTomlResult.state : {};

  const entries = [
    ...bouncerTrustEntries(hooksJsonTable, hooksJsonPath, events),
    ...bouncerTrustEntries(configTomlTable, configTomlPath, events),
  ];
  if (entries.length === 0) {
    return { id: 'wiring:trust', ok: true, message: 'no bouncer hook entries to trust yet' };
  }
  const untrusted = entries.filter((entry) => !isTrusted(state, entry));
  if (untrusted.length > 0) {
    return {
      id: 'wiring:trust',
      ok: false,
      message: `${untrusted.length} bouncer hook(s) need review in /hooks; they are skipped, this session runs unguarded`,
    };
  }
  return { id: 'wiring:trust', ok: true, message: `${entries.length} bouncer hook(s) trust recorded (hash not verifiable)` };
}

/** `doctor --print-canary --harness codex` — the canonical `hooks.json`-shaped canary entry, from the merged, additive read. */
export async function formatCodexCanonicalCanaryEntry(
  pathOverride: string | undefined,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
): Promise<CanonicalCanaryEntry> {
  const merged = await readCodexHooks(pathOverride, harness, protocol);
  if (merged.kind !== 'ok') {
    return { error: `cannot read a hooks object from ${hooksJsonPathFor(harness)} or ${configTomlPathFor(harness)}` };
  }
  return buildCanonicalCanaryEntry(merged.settings, protocol, hooksJsonPathFor(harness));
}
