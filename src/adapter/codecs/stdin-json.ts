// The `stdin-json` transport codec (ADR-0006 § 6) — every harness
// declared in this ticket speaks it: one JSON object on stdin, no framing.
// Kept as its own module (rather than an inline `JSON.parse` in run.ts) so
// the codec registry names a real thing: a future transport (a length-
// prefixed stream, say) is a sibling file here, not a rewrite of run.ts's
// dispatch.

/** Parses a stdin-json envelope. `null` for empty input, invalid JSON, or
 * anything that doesn't parse to a JSON object — the adapter's fail-open
 * contract for a malformed envelope (src/adapter/run.ts). */
export function parseStdinJson(raw: string): Record<string, unknown> | null {
  if (raw.trim() === '') return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
    ? parsed as Record<string, unknown>
    : null;
}
