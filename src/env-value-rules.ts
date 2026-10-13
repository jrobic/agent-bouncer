// Env-value guard (ticket 58, decision F2 / 1a): text about to be written that
// carries the VALUE of a protected environment variable. It is `write_secret`
// with the exact value instead of a regex — it catches the secret an agent
// copies into a file after a test or a script printed it, whatever printed it.
// Its second use (ticket 59, ADR-0008, decision F2 / 1b): every tool's output,
// before the model sees it — the same values, replaced by `[redacted: NAME]`.
// Both uses are one guard (createEnvValueGuard, below: `check` and `redact`).
// Pure — no Bun/Node APIs, no harness protocol shapes, and no environment of
// its own: run() (src/adapter/run.ts) takes the record at the edge, once per
// invocation, and every policy binding (the overlay-aware one, then the
// baseline retry) reads it. So this module and its tests stay
// environment-free.
//
// ─── The invariant ───────────────────────────────────────────────────
// A value is a MATCHING KEY and nothing else. It appears in no returned
// structure, no thrown error, no log argument, no message, and it is never
// compiled into a RegExp (a SyntaxError message embeds the source, and a value
// is not regex-safe): matching is `String.prototype.includes` over variants
// computed once. Everything that leaves this module names the variable.
//
// ─── What counts ─────────────────────────────────────────────────────
// A variable whose NAME is protected (src/protected-names.ts — the one shared
// definition, ticket 57's suffix list) and whose value is at least
// MIN_ENV_VALUE_LENGTH characters long (the floor against noise: `TOKEN=true`).
// Three forms of the value are looked for:
//   - plain:   the value itself;
//   - base64:  the value's UTF-8 bytes, STANDARD (`+/`) and URL-SAFE (`-_`)
//              alphabet, padded or not, at ANY of the three alignments the
//              value can take inside a longer encoded stream. For each
//              alignment the needle is the run of characters fixed by the
//              value's own bits alone — the characters that share a 3-byte
//              group with the bytes before it, or with the bytes after it, are
//              left out, which is also what makes the padding irrelevant;
//   - hex:     the value's UTF-8 bytes, all lowercase or all uppercase.
// Not covered, on purpose (a net, not a barrier): a value split, reversed,
// ROT13'd, hashed or re-encoded (percent-, JSON- or HTML-escaped), base64 or hex
// broken across lines or by separators, base64 of UTF-16, a mixed-case hex
// string, a multi-line value of which only some lines are written, and a value
// with leading or trailing whitespace of which only the trimmed part is
// written (the value is matched exactly as the environment holds it).
//
// ─── How the baseline reaches it ─────────────────────────────────────
// policy/write-secret.toml carries ONE row, `env-value`, marked
// `special = "env_value"`. The row is what makes the guard visible in `rules
// list` and reachable by `[[override]]`. The regex scan (createScanSecrets)
// never fires it: no handler for that `special` is bound there. The guard
// (createEnvValueGuard, below) reads the row for its two uses differently:
//   - `check` (writes, through the dispatcher, ahead of the regex table): the
//     environment lookup comes first; when it finds a value, the row's
//     `regex` / `except` gate which written texts the guard applies to (an
//     `env_value` handler passed to firstMatch) — what an `[[override]]`
//     replace narrows — and the verdict kind and id come from the row like
//     any other (a relax override, the row's own `verdict`, then `block`).
//   - `redact` (tool output, the post-tool event): the row's `regex`,
//     `except` and verdict govern nothing here (decision H6) — every output
//     text is scanned. Only the row's presence (`disable` removes it → off),
//     a relax (any `verdict_override` → off, decision H3) and its id (the
//     audit entry's `rule_id`) count.

import { type CompiledRule, compileRules, firstMatch, type SpecialHandlers } from './policy/match.ts';
import type { RegexRule } from './policy/schema.ts';
import { isProtectedName } from './protected-names.ts';
import type { Verdict } from './types.ts';

/** A process environment: what `process.env` is, as a plain record. */
export type EnvRecord = Readonly<Record<string, string | undefined>>;

/** The shortest value the guard looks for, in characters. */
export const MIN_ENV_VALUE_LENGTH = 8;

/** The `special` a baseline row names to be recognised by this module. */
export const ENV_VALUE_SPECIAL = 'env_value';

export type EnvValueForm = 'plain' | 'base64' | 'hex';

/** One protected variable found in a text, and the form it was found in. Never the value. */
export interface EnvValueMatch {
  readonly name: string;
  readonly form: EnvValueForm;
}

/** Every (variable, form) of the environment found in `text`, in the environment's own order. */
export type ScanEnvValues = (text: string) => readonly EnvValueMatch[];

/** The distinct variable names among `matches`, in order — all a verdict or a log line may say about a find. */
export function namesOf(matches: readonly EnvValueMatch[]): readonly string[] {
  return [...new Set(matches.map((match) => match.name))];
}

/**
 * The notice that stands in for a text that carried a protected value — a path
 * in a verdict, an error message in a log line — in ONE wording, so the places
 * that withhold text cannot drift apart. Names are allowed in it, values never.
 */
export function withheldNotice(what: string, names: readonly string[] = []): string {
  const why = 'it contains the value of a protected environment variable';
  return names.length === 0 ? `(${what} withheld: ${why})` : `(${what} withheld: ${why}: ${names.join(', ')})`;
}

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ENCODER = new TextEncoder();

/** Standard base64 of `bytes`, with zero bytes standing in for the missing end of the last group (never padded). */
function base64Encode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const group = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += BASE64_ALPHABET[(group >> 18) & 63]! + BASE64_ALPHABET[(group >> 12) & 63]!
      + BASE64_ALPHABET[(group >> 6) & 63]! + BASE64_ALPHABET[group & 63]!;
  }
  return out;
}

/**
 * One spelling of one variable's value, as searched for — a matching key,
 * never returned. `edges` is set on a base64 needle only (base64Needles).
 */
interface Needle {
  readonly name: string;
  readonly form: EnvValueForm;
  readonly text: string;
  readonly edges?: Base64Edges;
}

/**
 * What a base64 needle leaves out of the encoded value: whether its first
 * (`left`) and its last (`right`) character are PARTIAL — they mix the value's
 * bits with a neighbouring byte's, so no needle can include them — and how
 * many `=` can follow the last one when the value ends the stream. A
 * complete edge (alignment 0 at the start, `(k+n) % 3 == 0` at the end) has
 * no partial character: the needle already reaches the encoding's boundary.
 */
interface Base64Edges {
  readonly left: boolean;
  readonly right: boolean;
  readonly padding: number;
}

/** Two needles with the same text: a partial edge from either counts. */
function joinEdges(a: Base64Edges, b: Base64Edges | undefined): Base64Edges;
function joinEdges(a: Base64Edges | undefined, b: Base64Edges | undefined): Base64Edges | undefined;
function joinEdges(a: Base64Edges | undefined, b: Base64Edges | undefined): Base64Edges | undefined {
  if (a === undefined || b === undefined) return a ?? b;
  return { left: a.left || b.left, right: a.right || b.right, padding: Math.max(a.padding, b.padding) };
}

/**
 * The base64 needles of `value`: for each alignment `k` (the value starts `k`
 * bytes into a 3-byte group), the characters of base64(`k` filler bytes + value)
 * that depend on the value's bits ONLY. Characters 0..ceil(8k/6)-1 mix in the
 * `k` bytes before the value; characters from floor(8(k+n)/6) on mix in the
 * bytes after it (or the padding). What is left is identical wherever the value
 * sits in the stream, padded or not. The URL-safe needle is the same run with
 * `+/` → `-_`. Identical needles are kept once, their edges joined (a partial
 * edge from either alignment counts).
 */
function base64Needles(name: string, bytes: Uint8Array): readonly Needle[] {
  const byText = new Map<string, Needle>();
  for (let alignment = 0; alignment < 3; alignment += 1) {
    const stream = new Uint8Array(alignment + bytes.length);
    stream.set(bytes, alignment);
    const start = Math.ceil((alignment * 8) / 6);
    const end = Math.floor((stream.length * 8) / 6);
    const tail = stream.length % 3;
    const edges: Base64Edges = { left: alignment !== 0, right: tail !== 0, padding: tail === 0 ? 0 : 3 - tail };
    const standard = base64Encode(stream).slice(start, end);
    for (const text of [standard, standard.replaceAll('+', '-').replaceAll('/', '_')]) {
      byText.set(text, { name, form: 'base64', text, edges: joinEdges(edges, byText.get(text)?.edges) });
    }
  }
  return [...byText.values()];
}

function hexNeedles(name: string, bytes: Uint8Array): readonly Needle[] {
  let lower = '';
  for (const byte of bytes) lower += byte.toString(16).padStart(2, '0');
  return [...new Set([lower, lower.toUpperCase()])].map((text) => ({ name, form: 'hex', text }));
}

/**
 * Every needle of the environment, in the environment's own order, then
 * plain, base64, hex — the ONE place that decides which variables count (a
 * protected name, a value of at least MIN_ENV_VALUE_LENGTH characters). The
 * scanner and the redactor both read this list; a value shared by two names
 * yields a needle for each.
 */
function needlesOf(env: EnvRecord): readonly Needle[] {
  const needles: Needle[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== 'string' || value.length < MIN_ENV_VALUE_LENGTH || !isProtectedName(name)) continue;
    const bytes = ENCODER.encode(value);
    needles.push({ name, form: 'plain', text: value }, ...base64Needles(name, bytes), ...hexNeedles(name, bytes));
  }
  return needles;
}

function scannerOver(needles: readonly Needle[]): ScanEnvValues {
  return (text) => {
    if (!text) return [];
    const matches: EnvValueMatch[] = [];
    for (const { name, form, text: needle } of needles) {
      if (matches.some((m) => m.name === name && m.form === form)) continue;
      if (text.includes(needle)) matches.push({ name, form });
    }
    return matches;
  };
}

/** Builds the scanner for one environment: names and forms out, never a value. */
export function createEnvValueScanner(env: EnvRecord): ScanEnvValues {
  return scannerOver(needlesOf(env));
}

/** A text with every protected value replaced (ADR-0008). Never a value. */
export interface EnvValueRedaction {
  readonly text: string;
  /** Present exactly when something was replaced: the variables (in the order their markers appear) and the id of the `env_value` row that governs the redaction. */
  readonly found?: { readonly names: readonly string[]; readonly ruleId: string; };
}

export type RedactEnvValues = (text: string) => EnvValueRedaction;

/** What stands in for a protected value in a redacted text — names only, never a fragment of a value. */
export function redactionMarker(names: readonly string[]): string {
  return `[redacted: ${names.join(', ')}]`;
}

// The base64 alphabets (standard and URL-safe) — a fixed class, never built
// from a value.
const BASE64_CHAR = /[A-Za-z0-9+/_-]/;

/** One place a needle was found: `[start, end)` of the original text. */
interface Occurrence {
  readonly name: string;
  readonly start: number;
  readonly end: number;
}

/** What a marker replaces: occurrences merged, `end` growing while they overlap. */
interface Span {
  readonly start: number;
  end: number;
  readonly names: string[];
}

// A base64 needle found at `[at, end)`, widened over the encoded value's own
// PARTIAL edges only (Base64Edges): one base64 character on a partial side,
// then, after a partial last character, up to `padding` `=`. A complete edge
// is never widened, so a neighbour from the base64 alphabet (`/`, `_`, `-`,
// a letter) that is not part of the encoding stays.
function base64Occurrence(text: string, name: string, at: number, end: number, edges: Base64Edges): Occurrence {
  const start = edges.left && at > 0 && BASE64_CHAR.test(text[at - 1]!) ? at - 1 : at;
  if (!edges.right || end >= text.length || !BASE64_CHAR.test(text[end]!)) return { name, start, end };
  let stop = end + 1;
  for (let pad = 0; pad < edges.padding && text[stop] === '='; pad += 1) stop += 1;
  return { name, start, end: stop };
}

/** The redactor before the policy switch: the replaced text and the names replaced (empty when nothing was). */
type ReplaceEnvValues = (text: string) => { readonly text: string; readonly names: readonly string[]; };

/**
 * The redactor over one environment's needles: every occurrence of every
 * needle in a text is replaced by `[redacted: NAME]`. One pass over the
 * ORIGINAL text: occurrences are located first, then spliced, so an inserted
 * marker is never scanned again. An occurrence lying wholly inside another is
 * absorbed by it (the longer value names the span); occurrences that partly
 * overlap merge into one span naming every variable involved, so no tail of a
 * value is left in clear. A needle two variables share belongs to the name
 * that sorts first, in code-unit order (deterministic, whatever the
 * environment's order). A base64 occurrence is widened over its partial
 * edges; replacing it inside a longer stream breaks that stream, on purpose
 * (ADR-0008 § 4).
 */
function redactorOver(all: readonly Needle[]): ReplaceEnvValues {
  // One entry per needle text — a Map, not a record: the keys are values
  // (`__proto__` is a legal one).
  const byText = new Map<string, Needle>();
  for (const needle of all) {
    const held = byText.get(needle.text);
    if (held === undefined) {
      byText.set(needle.text, needle);
      continue;
    }
    const edges = joinEdges(held.edges, needle.edges);
    byText.set(needle.text, {
      ...(needle.name < held.name ? needle : held),
      ...(edges === undefined ? {} : { edges }),
    });
  }
  const needles = [...byText.values()];
  return (text) => {
    if (needles.length === 0 || text === '') return { text, names: [] };
    const found: Occurrence[] = [];
    for (const { name, text: needle, edges } of needles) {
      for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + 1)) {
        const end = at + needle.length;
        found.push(edges === undefined ? { name, start: at, end } : base64Occurrence(text, name, at, end, edges));
      }
    }
    if (found.length === 0) return { text, names: [] };
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const spans: Span[] = [];
    for (const occurrence of found) {
      const last = spans.at(-1);
      if (last === undefined || occurrence.start >= last.end) {
        spans.push({ start: occurrence.start, end: occurrence.end, names: [occurrence.name] });
      } else if (occurrence.end > last.end) {
        last.end = occurrence.end;
        if (!last.names.includes(occurrence.name)) last.names.push(occurrence.name);
      }
    }
    let redacted = '';
    let cursor = 0;
    const names: string[] = [];
    for (const span of spans) {
      redacted += text.slice(cursor, span.start) + redactionMarker(span.names);
      cursor = span.end;
      for (const name of span.names) if (!names.includes(name)) names.push(name);
    }
    return { text: redacted + text.slice(cursor), names };
  };
}

export type CheckEnvValue = (text: string, target: string) => Verdict | null;

// The row's own `regex` / `except` decide which WRITTEN texts the guard applies
// to — the environment lookup has already found a value when this runs. The
// redaction never consults them (decision H6).
const GATE: SpecialHandlers = {
  [ENV_VALUE_SPECIAL]: (row: CompiledRule, text: string) => row.re.test(text) && !row.exceptRe?.test(text),
};

/** The env-value row's two uses, bound to one table and one environment. */
export interface EnvValueGuard {
  /** Ticket 58: a write that carries a value → a verdict naming the variables. */
  readonly check: CheckEnvValue;
  /** Ticket 59 (ADR-0008): a tool's output text → the same text, values replaced. */
  readonly redact: RedactEnvValues;
}

/**
 * Binds the guard to the effective `write_secret` table and an environment.
 * The rows marked `special = "env_value"` are the policy side: none left (a
 * consumer disabled it) → both uses are off; a relaxed row (an `[[override]]`
 * relax) still checks writes with its softer verdict but redacts nothing
 * (decision H3, one switch). The row's `regex` / `except` — what an
 * `[[override]]` replace narrows — gate the write check only: the redaction
 * reads nothing of the row but its presence, its relax and its id, and scans
 * every output text (decision H6: an override written for the write guard
 * must not silently narrow what is hidden from the model). The environment is
 * read once, on first use, for both: a call that neither writes nor answers a
 * post-tool event never reads it, and a pre-tool call never builds the
 * redactor.
 *
 * `check`: the verdict names the variables in its reason and in `envVars`;
 * its `target` is the path, unless the path carries a protected value itself.
 * `redact`: the governing row's id names the redaction.
 */
export function createEnvValueGuard(rules: readonly RegexRule[], env: EnvRecord): EnvValueGuard {
  const rows = compileRules(rules.filter((rule) => rule.special === ENV_VALUE_SPECIAL));
  const redactRow = rows.find((row) => row.verdict_override === undefined);
  let needles: readonly Needle[] | undefined;
  let scan: ScanEnvValues | undefined;
  let replace: ReplaceEnvValues | undefined;

  const check: CheckEnvValue = (text, target) => {
    if (rows.length === 0 || !text) return null;
    scan ??= scannerOver(needles ??= needlesOf(env));
    const matches = scan(text);
    if (matches.length === 0) return null;
    // firstMatch's own `target` is the whole text: replaced below, never returned.
    const hit = firstMatch(rows, text, 'block', GATE);
    if (hit === null) return null;
    const envVars = namesOf(matches);
    return {
      ...hit,
      reason: `${hit.reason} — variable${envVars.length === 1 ? '' : 's'}: ${envVars.join(', ')}`,
      target: scan(target).length === 0 ? target : withheldNotice('path'),
      envVars,
    };
  };

  const redact: RedactEnvValues = (text) => {
    if (redactRow === undefined || !text) return { text };
    replace ??= redactorOver(needles ??= needlesOf(env));
    const { text: redacted, names } = replace(text);
    return names.length === 0 ? { text } : { text: redacted, found: { names, ruleId: redactRow.id } };
  };

  return { check, redact };
}
