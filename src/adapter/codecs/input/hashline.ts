// The `hashline` input codec (ADR-0006 § 6, ticket 15c): omp's `edit`
// tool takes ONE patch string, not discrete `path`/`text` fields — a
// field-map selector can name a key, never parse a grammar, so this is
// a codec: named by `codec = "hashline"` on a tool row (src/policy/
// harness.ts's parseToolRow — mutually exclusive with every selector
// key on that same row), reached from src/adapter/neutral-call.ts's
// buildNeutralCall exactly where a plain selector would otherwise run.
// pi 0.84.1's OWN `edit` tool is a STRUCTURALLY DIFFERENT schema despite
// sharing omp's extension HOOK api (ADR-0006 fact 5 covers `pi.on(...)`/
// `ctx.ui.confirm`/etc., never the tool set itself, which omp is free to
// replace): `{ path: string, edits: [{ oldText, newText }] }`
// (`edit.d.ts:10-16`, review round 1 P-1) — no `input.input` string at
// all. This codec recognizes BOTH shapes; see `hashlineCodec` below.
//
// Grammar (confirmed live, firsthand: this ticket's own dev session runs
// under omp/pi-agent, and its OWN `edit` tool is exactly this format —
// not a secondhand doc reading): one or more `[PATH#TAG]` section
// headers (`PATH` may be relative or absolute, `TAG` a 4-hex snapshot
// id), each followed by zero or more OPERATION lines (`PUT N.=M:`, bare
// `PUT >N @name`, `CUT N.=M`, `REM`, `MV DEST`, ...) — only a
// colon-terminated `PUT`/`CUT` header carries BODY rows after it, and
// every body row is `+TEXT` (a literal, verbatim line to write). There is
// NO `-old`/bare/context row in this grammar (unlike apply-patch's
// diff-style hunks) — a line starting with `-`, or any plain line that
// isn't a header, a `+` row, or a recognized operation keyword, carries
// no judged content and is read past. An optional `*** Begin Patch`/
// `*** End Patch` envelope (ADR-0006 § 3's own doc excerpt: "optionally
// enveloppée") wraps the whole payload in some clients; those two marker
// lines are themselves read past exactly like any other non-header,
// non-`+` line — no special-casing needed.
//
// Every named path is a WRITE (protected-write and secret targets); a
// payload naming several sections has `paths` genuinely plural, mirroring
// apply-patch's own move-writes-two-paths reasoning. `text` is every `+`
// row across EVERY section, joined by `\n` — the exact string
// write-secret scans, same convention as apply-patch's own hunk text.
//
// A payload with NO recognized `[PATH#TAG]` header anywhere is fully
// unparseable: no paths, no text, nothing to partially trust — never a
// thrown error that could crash the hook into reading as unguarded. A
// payload WITH at least one valid header keeps every path and every `+`
// row already found even if later lines are unrecognized noise (the same
// "judge what was seen" philosophy as apply-patch's own partial-parse
// case) — there is no equivalent of apply-patch's own "unrecognized
// directive line" failure mode here, since every non-header/non-`+` line
// is legitimately ignorable in this grammar (an operation keyword line
// carries no judged content by design, not by parse failure). Either way
// a payload found unparseable in its ENTIRETY logs one stderr line naming
// the failure, the same "no value" contract apply-patch and every plain
// selector already share.

import { warn } from '../warn.ts';

export interface HashlineResult {
  readonly paths: readonly string[];
  readonly text: string | null;
}

const NOT_JUDGED: HashlineResult = { paths: [], text: null };

// `TAG` is a 4-hex snapshot id (`[foo.ts#A1B2]`) — `PATH` is everything
// between `[` and `#`, taken verbatim (a relative path is resolved
// against `cwd` by buildNeutralCall, same as every other codec's paths).
const SECTION_HEADER = /^\[(.+)#[0-9A-Fa-f]{4}\]$/;

/**
 * Parses one hashline payload (already known to be a string — the codec
 * entry point below does that check) into every path its section headers
 * name and the joined text of every `+` row, across every section.
 */
export function parseHashline(raw: string, hookName: string): HashlineResult {
  const lines = raw.split(/\r\n|\r|\n/);
  const paths: string[] = [];
  const textLines: string[] = [];

  for (const line of lines) {
    const header = SECTION_HEADER.exec(line);
    if (header !== null) {
      paths.push(header[1]!);
      continue;
    }
    // Only a literal `+` prefix ever carries judged content in this
    // grammar — never a bare/context/`-` row (those do not exist in
    // hashline), and never an operation keyword line (`PUT`/`CUT`/`REM`/
    // `MV`/the `*** Begin Patch`/`*** End Patch` envelope markers), which
    // are read past exactly like this.
    if (line.startsWith('+')) textLines.push(line.slice(1));
  }

  if (paths.length === 0) {
    warn(hookName, 'hashline payload has no [PATH#TAG] section header — not judged');
    return NOT_JUDGED;
  }
  return { paths, text: textLines.length > 0 ? textLines.join('\n') : null };
}

/**
 * Reads pi's OWN edit shape (`{ path, edits: [{ oldText, newText }] }`,
 * review round 1 P-1) directly off the raw input bag — `undefined` when
 * `path` is not a string or `edits` is not an array, so the caller can
 * fall through to "neither shape recognized" rather than guessing.
 * `oldText` is never read: only `newText` — the content actually
 * WRITTEN — is what write-secret/protected-write need to scan, mirroring
 * every other codec's own "only the written text" convention.
 */
function parsePiEditShape(ti: Record<string, unknown>): HashlineResult | undefined {
  const path = Object.hasOwn(ti, 'path') ? ti['path'] : undefined;
  const edits = Object.hasOwn(ti, 'edits') ? ti['edits'] : undefined;
  if (typeof path !== 'string' || !Array.isArray(edits)) return undefined;
  const textLines = edits
    .filter((entry): entry is { newText: string; } =>
      Boolean(entry) && typeof entry === 'object' && typeof (entry as Record<string, unknown>)['newText'] === 'string'
    )
    .map((entry) => entry.newText);
  return { paths: [path], text: textLines.length > 0 ? textLines.join('\n') : null };
}

/**
 * The `hashline` codec entry point buildNeutralCall reaches for a tool
 * row declaring `codec = "hashline"` — the `edit` tool's own patch shape
 * differs by binary (review round 1 P-1): omp sends one hashline patch
 * string under `input.input` (ADR-0006's own doc excerpt: "`edit`
 * `{input}`: hashline patch string"); pi 0.84.1 sends `{path, edits[]}`
 * instead (this file's own header comment, `edit.d.ts:10-16`). Tried in
 * that order — `input.input` a string wins outright; otherwise the pi
 * shape; neither recognized is NOT_JUDGED, now WITH a stderr line (P-1:
 * silently NOT_JUDGED here is exactly how an AWS key written through
 * pi's real `edit` tool passed unjudged during the dedicated test phase
 * — the omp-shaped check alone can never see a real pi payload at all).
 */
export function hashlineCodec(ti: Record<string, unknown>, hookName: string): HashlineResult {
  const raw = Object.hasOwn(ti, 'input') ? ti['input'] : undefined;
  if (typeof raw === 'string') return parseHashline(raw, hookName);
  if (raw !== undefined && raw !== null) {
    warn(hookName, `expected string for tool_input.input, got ${typeof raw} — allowing`);
    return NOT_JUDGED;
  }
  const piShape = parsePiEditShape(ti);
  if (piShape !== undefined) return piShape;
  warn(hookName, 'edit payload matches neither the omp hashline (`input`) nor the pi (`path`+`edits[]`) shape — not judged');
  return NOT_JUDGED;
}
