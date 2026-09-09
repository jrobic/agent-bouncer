// The tools map (ADR-0006 § 3): turns a harness's own tool-call shape
// (`tool_name` + `tool_input`) into the engine's neutral vocabulary — a
// NeutralCall — by walking the row a `[harness.protocol.tools]` name
// resolves to. This is the ONE place that reads a dotted-path selector
// string out of TOML; src/adapter/dispatch.ts and every family checker it
// wires (src/*-rules.ts) never see a tool name or a field name again.
//
// Ported straight from the pre-15a hardcoded readers (src/targets.ts,
// src/adapter/dispatch.ts's NATIVE_FILE_PATH_FIELD/writeSecretText) —
// same stderr diagnostics, same array-entry leniency, same defaults —
// just driven by a selector string instead of a hardcoded key.

import { isAbsolute, resolve } from 'node:path';
import type { HarnessProtocol, HarnessRole, HarnessToolRow } from '../policy/schema.ts';
import { inputCodecFor } from './codecs/input/registry.ts';
import { warn } from './codecs/warn.ts';

// ADR-0006 § 3: "a relative path is resolved against the envelope's cwd
// before canonicalisation" — a no-op whenever `cwd` is unset (no `cwd`
// selector, or the harness's envelope simply doesn't send one, Claude
// Code's own case) or `path` is already absolute.
function joinCwd(path: string, cwd: string | null): string {
  return cwd === null || isAbsolute(path) ? path : resolve(cwd, path);
}

// Review round 1 L-1 (lead): a raw path selector's value may carry a
// harness-specific SUFFIX or LIST that never reaches the filesystem
// verbatim — pi-agent's own `read`/`grep`/`find`/`ls` (and omp's `glob`)
// let a model append a trailing `:<selector>` (`~/.zsh_history:1-5`, this
// codebase's own `read`/`archive.zip:inner/.env` convention) or join
// several targets with `;` (`~/.ssh; ~/.aws`) — and every `$`-anchored
// path rule (`ssh-key`, `dotenv`, …) is written against the LITERAL
// target, never a superstring carrying extra trailing text. Measured
// live (ticket 15c review round 1): `~/.zsh_history:1-5` and
// `proj/secrets.pem:1-2` both read as `allow` against the unmodified
// path string alone — the suffix defeats the `$`-anchor. Fix: for every
// role="read" row's `path` selector, judge the WHOLE candidate set this
// raw value could plausibly mean, never just the raw string: itself;
// each `;`-split segment, trimmed; and, for every segment (including the
// unsplit raw value), every progressive strip of a trailing `:<segment>`
// (`a:b:c` → `a:b`, then `a` — `db.sqlite:table` also yields the bare
// `db.sqlite`, harmless). A superset can only ADD verdicts across
// `paths`' existing loop in dispatch.ts's own family checkers — this
// needs no new selector grammar, no TOML change, and is a no-op for any
// path that never contained `;` or `:` to begin with (every other
// harness's own fixtures stay byte-identical).
export function expandPathCandidates(raw: string): readonly string[] {
  const candidates = new Set<string>();
  const addWithColonStrips = (value: string): void => {
    candidates.add(value);
    let current = value;
    let colonIndex = current.lastIndexOf(':');
    while (colonIndex !== -1) {
      current = current.slice(0, colonIndex);
      if (current.length === 0) break;
      candidates.add(current);
      colonIndex = current.lastIndexOf(':');
    }
  };
  addWithColonStrips(raw);
  for (const rawSegment of raw.split(';')) {
    const segment = rawSegment.trim();
    if (segment.length > 0) addWithColonStrips(segment);
  }
  return [...candidates];
}

// What every family checker in dispatch.ts actually inspects, independent
// of which harness or tool produced it. `role` decides which extra
// families a `paths`/`commands` hit reaches (see dispatch.ts): `write`
// additionally reaches protected-write on `paths`; every role reaches
// secret on whichever of `commands`/`pattern`/`paths`/`urls` it
// populated. `paths` is plural (ADR-0006 § 6): a selector-derived row
// ever populates at most one entry, but a `codec` row can name several in
// one call (Codex's `apply_patch` move writes both its source and
// destination) — every family that reaches `paths` loops it exactly as
// it already loops `commands`/`urls`.
export interface NeutralCall {
  readonly toolName: string;
  readonly role: HarnessRole;
  readonly commands: readonly string[];
  readonly paths: readonly string[];
  readonly pattern: string | null;
  readonly text: string | null;
  readonly urls: readonly string[];
  readonly mcpName: string | null;
}

// Exact rows win over a trailing-`*` glob row (ADR-0006 § 3) — checked
// first and independently, so a glob can never shadow an explicit row
// regardless of object key order.
function findToolRow(tools: Readonly<Record<string, HarnessToolRow>>, toolName: string): HarnessToolRow | null {
  if (Object.hasOwn(tools, toolName)) return tools[toolName]!;
  for (const [pattern, row] of Object.entries(tools)) {
    if (pattern.endsWith('*') && toolName.startsWith(pattern.slice(0, -1))) return row;
  }
  return null;
}

type ArraySelector = Readonly<{ base: string; rest: string; }>;

// A selector is a dotted path, optionally containing exactly one `[]`
// step: "file_path" (plain), "edits[].new_string" / "commands[].command"
// / "requests[].url" (array — `base` is the array field, `rest` the
// per-element field the string-vs-object leniency below reads off it).
function parseArraySelector(selector: string): ArraySelector | null {
  const index = selector.indexOf('[]');
  if (index === -1) return null;
  const base = selector.slice(0, index);
  const rest = selector.slice(index + 2).replace(/^\./, '');
  return { base, rest };
}

// Review round 4 R4-1: the inverse of readCommandsSelector's own parsing
// — given a tool row's own `command` selector string, builds the ONE
// input-bag shape that selector reads a single command string back from.
// `check` (src/cli-commands.ts) is the one caller: it has no real
// envelope to read, just a command string and the row it is dry-running
// against, so IT must build the bag the row's OWN selector expects
// (a plain key, `commands[].command`, or a bare `items[]`) rather than
// assuming a fixed key name (`"Bash"`'s `command` was never the general
// case — `sh = { role = "command", command = "cmd" }` needs `{cmd: …}`,
// not `{command: …}`).
export function buildCommandInputBag(selector: string, command: string): Record<string, unknown> {
  const arraySelector = parseArraySelector(selector);
  if (arraySelector === null) return { [selector]: command };
  return { [arraySelector.base]: [arraySelector.rest === '' ? command : { [arraySelector.rest]: command }] };
}

// A plain (non-array) selector's single value — mirrors src/targets.ts's
// pre-15a readStringField: absent/null is silently "no value", a
// non-string logs the diagnostic every dispatch.ts family relied on.
function readPlainSelector(ti: Record<string, unknown>, selector: string, hookName: string): string | null {
  const value = ti[selector];
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') {
    warn(hookName, `expected string for tool_input.${selector}, got ${typeof value} — allowing`);
    return null;
  }
  return value;
}

// Command-shaped array selector (ctx_batch_execute's `commands[].command`)
// — a string element is the command directly, an object element reads
// `rest` off it, and an unreadable entry is skipped with a diagnostic
// rather than crashing the guard into failing open silently. Mirrors
// src/targets.ts's pre-15a readBatchCommands.
function readCommandsSelector(ti: Record<string, unknown>, selector: string, hookName: string): readonly string[] {
  const arraySelector = parseArraySelector(selector);
  if (arraySelector === null) {
    const value = readPlainSelector(ti, selector, hookName);
    return value === null ? [] : [value];
  }
  const raw = ti[arraySelector.base];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    warn(hookName, `expected array for tool_input.${arraySelector.base}, got ${typeof raw}`);
    return [];
  }
  const commands: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') {
      commands.push(entry);
      continue;
    }
    if (entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>)[arraySelector.rest] === 'string') {
      commands.push((entry as Record<string, unknown>)[arraySelector.rest] as string);
      continue;
    }
    warn(hookName, `skipping unreadable entry in tool_input.${arraySelector.base}`);
  }
  return commands;
}

// URL-shaped array selector (ctx_fetch_and_index's `requests[].url`) —
// entries missing a string `rest` field are silently dropped (mirrors
// src/targets.ts's pre-15a readBatchUrls: no per-entry diagnostic, only
// the whole-field type check does).
function readUrlsSelector(ti: Record<string, unknown>, selector: string, hookName: string): readonly string[] {
  const arraySelector = parseArraySelector(selector);
  if (arraySelector === null) {
    const value = readPlainSelector(ti, selector, hookName);
    return value === null ? [] : [value];
  }
  const raw = ti[arraySelector.base];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    warn(hookName, `expected array for tool_input.${arraySelector.base}, got ${typeof raw}`);
    return [];
  }
  return raw
    .filter((entry): entry is Record<string, unknown> =>
      Boolean(entry) && typeof entry === 'object' && typeof (entry as Record<string, unknown>)[arraySelector.rest] === 'string'
    )
    .map((entry) => entry[arraySelector.rest] as string);
}

// Text-shaped array selector (MultiEdit's `edits[].new_string`) — the
// single scanned string every element joins into, one line each; an
// entry missing a string `rest` field contributes an empty line rather
// than being dropped (mirrors src/adapter/dispatch.ts's pre-15a
// writeSecretText exactly, including its silence on a non-array `edits`).
function readTextSelector(ti: Record<string, unknown>, selector: string, hookName: string): string | null {
  const arraySelector = parseArraySelector(selector);
  if (arraySelector === null) return readPlainSelector(ti, selector, hookName);
  const raw = ti[arraySelector.base];
  const entries = Array.isArray(raw) ? raw : [];
  return entries
    .map((entry) =>
      entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>)[arraySelector.rest] === 'string'
        ? (entry as Record<string, unknown>)[arraySelector.rest] as string
        : ''
    )
    .join('\n');
}

// ADR-0006 § 6: a tool row's `codec` field names a runtime codec through
// src/adapter/codecs/input/registry.ts — the runtime counterpart of
// src/policy/harness.ts's KNOWN_INPUT_CODECS lint-time registry (the two
// MUST name the same set, or a declaration that lints clean could still
// find nothing to dispatch to here; both are reviewed together).

/**
 * Builds the neutral call a tool name's row describes, or `null` when no
 * row (exact or glob) matches — "not judged", exactly as before ticket
 * 15a. `ti` is the envelope's raw input bag (`tool_input` for Claude
 * Code); `cwd` is the envelope's own working directory (`null` when the
 * harness's input map has no `cwd` selector or the envelope didn't send
 * one — Claude Code sends absolute paths and never sends `cwd`, so this
 * is a no-op for it): ADR-0006 § 3, a RELATIVE path is resolved against
 * it before the caller's own canonicalisation, so a harness whose patches
 * are relative to the session directory (Codex) still names a real file
 * — for BOTH a selector-derived `path` and every path a `codec` row
 * returns. `hookName` only feeds the stderr diagnostics above.
 *
 * A `codec` row (ADR-0006 § 6) short-circuits every selector: the named
 * codec reads `ti` itself and returns `{paths, text}` in the same shape
 * selectors would have produced, cwd-joined here exactly like a plain
 * `path` selector.
 */
export function buildNeutralCall(
  protocol: HarnessProtocol,
  toolName: string,
  ti: Record<string, unknown>,
  cwd: string | null,
  hookName: string,
): NeutralCall | null {
  const row = findToolRow(protocol.tools, toolName);
  if (row === null) return null;

  if (row.codec !== undefined) {
    const codec = inputCodecFor(row.codec);
    // Review round 1 S-3: `rules lint` already proved row.codec is a
    // member of src/policy/harness.ts's KNOWN_INPUT_CODECS before this
    // declaration ever reached run() — an unresolvable name here means
    // the lint-time and runtime registries drifted, not a real envelope
    // problem. Fails closed to "not judged" (never throws, never crashes
    // the hook into reading as unguarded) but, same as doctor.ts's own
    // wiring-drift branch, never SILENTLY — one stderr line names the
    // drifted codec, matching this codec kind's own header contract.
    let result: { readonly paths: readonly string[]; readonly text: string | null; };
    if (codec === undefined) {
      warn(hookName, `input codec ${JSON.stringify(row.codec)} has no runtime implementation`);
      result = { paths: [], text: null };
    } else {
      result = codec(ti, hookName);
    }
    return {
      toolName,
      role: row.role,
      commands: [],
      paths: result.paths.map((p) => joinCwd(p, cwd)),
      pattern: null,
      text: result.text,
      urls: [],
      mcpName: row.role === 'mcp' ? toolName : null,
    };
  }

  const commands = row.command === undefined ? [] : readCommandsSelector(ti, row.command, hookName);
  const rawPath = row.path === undefined ? null : readPlainSelector(ti, row.path, hookName);
  const paths = rawPath === null
    ? []
    : (row.role === 'read' ? expandPathCandidates(rawPath) : [rawPath]).map((p) => joinCwd(p, cwd));
  const pattern = row.pattern === undefined ? null : readPlainSelector(ti, row.pattern, hookName);
  const text = row.text === undefined ? null : readTextSelector(ti, row.text, hookName);
  const singleUrl = row.url === undefined ? null : readPlainSelector(ti, row.url, hookName);
  const batchUrls = row.urls === undefined ? [] : readUrlsSelector(ti, row.urls, hookName);
  const urls = singleUrl === null ? batchUrls : [singleUrl, ...batchUrls];

  return {
    toolName,
    role: row.role,
    commands,
    paths,
    pattern,
    text,
    urls,
    mcpName: row.role === 'mcp' ? toolName : null,
  };
}
