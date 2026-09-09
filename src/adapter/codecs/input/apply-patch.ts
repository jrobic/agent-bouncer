// The `apply-patch` input codec (ADR-0006 § 6, fact 4): Codex has no
// Read/Edit/Write/MultiEdit/NotebookEdit tools — edits arrive as
// `tool_name: "apply_patch"` with `tool_input.command` holding Codex's own
// patch-text grammar. A field-map selector can name a key, never parse a
// grammar, so this is a codec: named by `codec = "apply-patch"` on a tool
// row (src/policy/harness.ts's parseToolRow — mutually exclusive with
// every selector key on that same row), reached from
// src/adapter/neutral-call.ts's buildNeutralCall exactly where a plain
// selector would otherwise run.
//
// Grammar: `*** Begin Patch` … `*** End Patch`, each file section one of
// `*** Add File: <path>`, `*** Update File: <path>` (optionally followed
// immediately by `*** Move to: <path>`), or `*** Delete File: <path>`,
// each optionally followed by hunk lines (`@@` headers, ` ` context, `-`
// removed, `+` added — Add/Update sections only; Delete has none).
//
// Every named path is a WRITE (a move writes both ends — the source is
// renamed away, the destination is created; both are protected-write and
// secret targets). `text` is every `+` hunk line of an Add/Update section,
// joined by `\n` — the exact string write-secret scans, mirroring
// MultiEdit's `edits[].new_string` text selector. Relative paths are
// resolved against the envelope's `cwd` by buildNeutralCall, same as a
// selector-derived `path` (Codex patches are relative to the session
// directory, ADR-0006 § 3).
//
// A patch missing its FRAME (`*** Begin Patch`/`*** End Patch`) is fully
// unparseable: no paths, no text, nothing to partially trust — the call
// is judged on nothing, never a thrown error that could crash the hook
// into reading as unguarded. A patch WITH a valid frame whose body hits
// a line matching no recognized directive/hunk shape (review round 1
// S-9) keeps every path and `+` text line already parsed before that
// line — judge what was seen, say what was not — rather than discarding
// an otherwise-good prefix over one bad trailing line. Either way, one
// stderr line names the failure so a human debugging a silent allow (or
// an unexpectedly narrow judgement) can find it.

import { warn } from '../warn.ts';

export interface ApplyPatchResult {
  readonly paths: readonly string[];
  readonly text: string | null;
}

const BEGIN_MARKER = '*** Begin Patch';
const END_MARKER = '*** End Patch';
const ADD_PREFIX = '*** Add File: ';
const UPDATE_PREFIX = '*** Update File: ';
const DELETE_PREFIX = '*** Delete File: ';
const MOVE_PREFIX = '*** Move to: ';
const DIRECTIVE_PREFIX = '*** ';

const NOT_JUDGED: ApplyPatchResult = { paths: [], text: null };

// Collects every `+` hunk line from `start` up to (not including) the
// next `*** ` directive or the closing `*** End Patch` — `@@` headers and
// ` `/`-` context/removed lines are read past without contributing to
// `text`, exactly why "mixed hunks" (context, removed, AND added lines in
// one section) is its own test: only the `+` lines must survive.
function consumeHunkLines(lines: readonly string[], start: number, bodyEnd: number, textLines: string[]): number {
  let index = start;
  while (index < bodyEnd && !lines[index]!.startsWith(DIRECTIVE_PREFIX)) {
    const line = lines[index]!;
    if (line.startsWith('+')) textLines.push(line.slice(1));
    index += 1;
  }
  return index;
}

/**
 * Parses Codex's `apply_patch` patch text (already known to be a string —
 * see `applyPatchCodec` below for the non-string field contract). Exported
 * directly for unit tests that want to exercise the grammar without a
 * `tool_input` wrapper.
 */
export function parseApplyPatch(raw: string, hookName: string): ApplyPatchResult {
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = normalized.split('\n');
  // A single trailing empty line is the final "\n" every real patch ends
  // with — dropped so `*** End Patch` lands as the last LOGICAL line;
  // never more than one, so a genuinely blank body line still counts.
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();

  if (lines.length === 0 || lines[0] !== BEGIN_MARKER) {
    warn(hookName, `apply_patch envelope did not parse: missing "${BEGIN_MARKER}" — not judged`);
    return NOT_JUDGED;
  }
  if (lines[lines.length - 1] !== END_MARKER) {
    warn(hookName, `apply_patch envelope did not parse: missing "${END_MARKER}" — not judged`);
    return NOT_JUDGED;
  }

  const paths: string[] = [];
  const textLines: string[] = [];
  const bodyEnd = lines.length - 1; // index of the "*** End Patch" line itself
  let index = 1;

  while (index < bodyEnd) {
    const line = lines[index]!;
    if (line.startsWith(ADD_PREFIX)) {
      paths.push(line.slice(ADD_PREFIX.length).trim());
      index = consumeHunkLines(lines, index + 1, bodyEnd, textLines);
      continue;
    }
    if (line.startsWith(UPDATE_PREFIX)) {
      paths.push(line.slice(UPDATE_PREFIX.length).trim());
      index += 1;
      if (index < bodyEnd && lines[index]!.startsWith(MOVE_PREFIX)) {
        paths.push(lines[index]!.slice(MOVE_PREFIX.length).trim());
        index += 1;
      }
      index = consumeHunkLines(lines, index, bodyEnd, textLines);
      continue;
    }
    if (line.startsWith(DELETE_PREFIX)) {
      paths.push(line.slice(DELETE_PREFIX.length).trim());
      index += 1;
      continue;
    }
    // Review round 1 S-9: keeps every path and `+` text line already
    // parsed before this point — judge what was seen, say what was
    // not — rather than discarding a partially-good patch just because
    // its body goes off the rails partway through. Only a patch missing
    // the two FRAME lines (`*** Begin Patch`/`*** End Patch` above)
    // stays fully "not judged": there is nothing to partially trust
    // when the grammar's own envelope was never established.
    warn(
      hookName,
      `apply_patch envelope: unrecognized line ${JSON.stringify(line)} at body line ${index + 1} — parsed prefix judged, rest skipped`,
    );
    break;
  }

  return { paths, text: textLines.length > 0 ? textLines.join('\n') : null };
}

/**
 * The `apply-patch` codec entry point buildNeutralCall reaches for a
 * `codec = "apply-patch"` tool row — reads `tool_input.command` itself
 * (Codex's own field for the patch text, ADR-0006 fact 4; a codec row
 * carries no selectors to name it with) and hands a real string to
 * `parseApplyPatch`. A non-string/absent field is the SAME "no value"
 * contract every plain selector already has (src/adapter/neutral-call.ts's
 * readPlainSelector) — silent when absent, one stderr line when present
 * but the wrong type — never a special case for this one codec.
 */
export function applyPatchCodec(ti: Record<string, unknown>, hookName: string): ApplyPatchResult {
  const raw = Object.hasOwn(ti, 'command') ? ti['command'] : undefined;
  if (raw === undefined || raw === null) return NOT_JUDGED;
  if (typeof raw !== 'string') {
    warn(hookName, `expected string for tool_input.command, got ${typeof raw} — allowing`);
    return NOT_JUDGED;
  }
  return parseApplyPatch(raw, hookName);
}
