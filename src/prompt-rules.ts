// Prompt-injection detection. Pure — no Bun/Node APIs, no harness protocol
// shapes (`buildContextOutput` moved to src/adapter/envelopes.ts in ticket
// 05). The rule table is policy data (policy/prompt.toml,
// `[[rules.prompt]]` — the base64-blob signature is now a plain 7th entry
// in that same table rather than a module constant evaluated apart from
// it); this module owns only the scanning algorithm.
//
// ─── Posture (this is a layer, not a wall) ───────────────────────────
// Prompt injection ultimately exploits the LLM, which remains fallible; no
// regex catches every phrasing. Callers are expected to WARN (flag) rather
// than block — the adapter's degradation table maps `flag` to
// additionalContext, never to a hard stop.

import { BASELINE } from './policy/baseline.ts';
import { allMatches, compileRules } from './policy/match.ts';
import type { RegexRule } from './policy/schema.ts';
import type { Verdict } from './types.ts';

export type ScanPrompt = (prompt: string) => Verdict[];

/**
 * Builds a scanPrompt() bound to the given rule table (baseline, or a
 * merged baseline+overlay+override set from src/policy/load.ts).
 */
export function createScanPrompt(rules: readonly RegexRule[]): ScanPrompt {
  const compiled = compileRules(rules);
  return (prompt) => allMatches(compiled, prompt, 'flag');
}

/**
 * Returns all injection signatures matched in the prompt (empty if clean),
 * each as a `flag` Verdict — this family never blocks or confirms. Uses
 * the embedded baseline.
 */
export const scanPrompt: ScanPrompt = createScanPrompt(BASELINE.rules.prompt);
