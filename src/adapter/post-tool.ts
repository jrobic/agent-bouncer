// The post-tool rewrite (ADR-0008 § 4 and § 6): a tool's response, as the
// harness sent it, walked into the SAME shape with protected values replaced.
// Harness-neutral on purpose — no tool knowledge: Claude Code validates a
// built-in tool's rewritten output against that tool's schema and IGNORES a
// value of another shape (showing the original), so the only safe rewrite is
// a transform of the received value: every key, array position and
// non-string value kept, replacement inside string leaves only. The walk runs
// on the parsed envelope, so a value holding `"`, `\` or a newline is matched
// as the environment holds it, never as JSON escapes it.

import { type EnvValueFinding, MIN_ENV_VALUE_LENGTH, type RedactEnvValues } from '../env-value-rules.ts';

/** The text that stands in for a string leaf of a response bouncer could not check. */
export const POST_TOOL_WITHHELD = 'bouncer: post-tool check failed — output withheld';

export interface RedactedResponse {
  /** The response in its own shape — rewritten when `found` is set, the received one otherwise. */
  readonly response: unknown;
  /** Present exactly when something was replaced: the variables (in the order first found) and the id of the env-value row that governs the redaction. Never a value. */
  readonly found?: EnvValueFinding;
}

// The ONE walk both answers use. Rebuilds `node` in its own shape and passes
// every string leaf, with the key it sits under (none for an array element),
// through `leaf`. Image data is not text: an object whose `type`
// is `"image"` is kept whole — an image content block (`{type, data,
// mimeType}`, MCP and omp/pi) and a Claude Code Read of an image (`{type:
// "image", file: {base64, …}}`) alike.
function mapStringLeaves(node: unknown, leaf: (text: string, key: string | undefined) => string, key?: string): unknown {
  if (typeof node === 'string') return leaf(node, key);
  if (Array.isArray(node)) return node.map((child) => mapStringLeaves(child, leaf));
  if (node !== null && typeof node === 'object') {
    if ('type' in node && node.type === 'image') return node;
    return Object.fromEntries(Object.entries(node).map(([childKey, child]) => [childKey, mapStringLeaves(child, leaf, childKey)]));
  }
  return node;
}

/** Replaces protected values inside the response's string leaves, keeping its shape. */
export function redactResponse(response: unknown, redact: RedactEnvValues): RedactedResponse {
  const names: string[] = [];
  let ruleId: string | undefined;
  const rewritten = mapStringLeaves(response, (text) => {
    const { text: redacted, found } = redact(text);
    if (found !== undefined) {
      for (const name of found.names) if (!names.includes(name)) names.push(name);
      ruleId ??= found.ruleId;
    }
    return redacted;
  });
  return ruleId === undefined ? { response } : { response: rewritten, found: { names, ruleId } };
}

/**
 * The answer when the check itself failed in-process (ADR-0008 § 6): the
 * response in its own shape, every string leaf that COULD hold a value
 * replaced by POST_TOOL_WITHHELD. Kept as they are: a `type` discriminator
 * (a schema needs it to recognise the shape at all), images, and any string
 * shorter than MIN_ENV_VALUE_LENGTH — it cannot hold a value in any form (a
 * plain value has at least that many characters, its base64 and hex needles
 * more), and enum leaves such as Grep's `mode: "content"` live there. A
 * built-in tool whose schema constrains a longer string leaf (Grep's
 * `files_with_matches`) still rejects the answer under Claude Code — the
 * documented residual.
 */
export function withheldResponse(response: unknown): unknown {
  return mapStringLeaves(response, (text, key) => (key === 'type' || text.length < MIN_ENV_VALUE_LENGTH ? text : POST_TOOL_WITHHELD));
}
