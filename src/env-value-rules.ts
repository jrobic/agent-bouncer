// Env-value guard (ticket 58, decision F2 / 1a): text about to be written that
// carries the VALUE of a protected environment variable. It is `write_secret`
// with the exact value instead of a regex — it catches the secret an agent
// copies into a file after a test or a script printed it, whatever printed it.
// Pure — no Bun/Node APIs, no harness protocol shapes, and no environment of
// its own: run() (src/adapter/run.ts) takes the record at the edge, once per
// invocation, and hands it to the dispatcher; every dispatcher construction
// (the overlay-aware one, then the baseline retry) reads it. So this module and
// its tests stay environment-free.
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
// list` and reachable by `[[override]]` (disable, relax; `replace` narrows which
// texts the guard looks at). The regex scan (createScanSecrets) never fires it:
// no handler for that `special` is bound there. The dispatcher evaluates it
// separately, ahead of the regex table, through createCheckEnvValue: the
// environment lookup comes first; when it finds a value, the row's `regex` /
// `except` gate which texts the guard applies to (an `env_value` handler passed
// to firstMatch), and the verdict kind and id come from the row like any other
// (a relax override, the row's own `verdict`, then `block`).

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
 * The base64 needles of `value`: for each alignment `k` (the value starts `k`
 * bytes into a 3-byte group), the characters of base64(`k` filler bytes + value)
 * that depend on the value's bits ONLY. Characters 0..ceil(8k/6)-1 mix in the
 * `k` bytes before the value; characters from floor(8(k+n)/6) on mix in the
 * bytes after it (or the padding). What is left is identical wherever the value
 * sits in the stream, padded or not. The URL-safe needle is the same run with
 * `+/` → `-_`; identical needles are kept once.
 */
function base64Needles(bytes: Uint8Array): readonly string[] {
  const needles = new Set<string>();
  for (let alignment = 0; alignment < 3; alignment += 1) {
    const stream = new Uint8Array(alignment + bytes.length);
    stream.set(bytes, alignment);
    const start = Math.ceil((alignment * 8) / 6);
    const end = Math.floor((stream.length * 8) / 6);
    const standard = base64Encode(stream).slice(start, end);
    needles.add(standard);
    needles.add(standard.replaceAll('+', '-').replaceAll('/', '_'));
  }
  return [...needles];
}

function hexNeedles(bytes: Uint8Array): readonly string[] {
  let lower = '';
  for (const byte of bytes) lower += byte.toString(16).padStart(2, '0');
  return [...new Set([lower, lower.toUpperCase()])];
}

interface Probe {
  readonly name: string;
  readonly form: EnvValueForm;
  readonly needles: readonly string[];
}

function probesOf(name: string, value: string): readonly Probe[] {
  const bytes = ENCODER.encode(value);
  return [
    { name, form: 'plain', needles: [value] },
    { name, form: 'base64', needles: base64Needles(bytes) },
    { name, form: 'hex', needles: hexNeedles(bytes) },
  ];
}

/**
 * Builds the scanner for one environment. The variants are computed here,
 * once; the returned function holds them in its closure and returns names and
 * forms only (ticket 59 reuses it to replace, not only to test).
 */
export function createEnvValueScanner(env: EnvRecord): ScanEnvValues {
  const probes: Probe[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== 'string' || value.length < MIN_ENV_VALUE_LENGTH || !isProtectedName(name)) continue;
    probes.push(...probesOf(name, value));
  }
  return (text) => {
    if (!text) return [];
    return probes
      .filter((probe) => probe.needles.some((needle) => text.includes(needle)))
      .map(({ name, form }) => ({ name, form }));
  };
}

export type CheckEnvValue = (text: string, target: string) => Verdict | null;

// The row's own `regex` / `except` decide which texts the guard applies to —
// the environment lookup has already found a value when this runs.
const GATE: SpecialHandlers = {
  [ENV_VALUE_SPECIAL]: (row: CompiledRule, text: string) => row.re.test(text) && !row.exceptRe?.test(text),
};

/**
 * Binds the guard to the effective `write_secret` table and an environment.
 * The rows marked `special = "env_value"` are the policy side: none left (a
 * consumer disabled it) → the guard is off. The verdict names the variables in
 * its reason and in `envVars`; its `target` is the path, unless the path
 * carries a protected value itself.
 */
export function createCheckEnvValue(rules: readonly RegexRule[], env: EnvRecord): CheckEnvValue {
  const rows = compileRules(rules.filter((rule) => rule.special === ENV_VALUE_SPECIAL));
  if (rows.length === 0) return () => null;
  const scan = createEnvValueScanner(env);
  return (text, target) => {
    if (!text) return null;
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
}
