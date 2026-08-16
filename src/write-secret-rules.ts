// Write-secret guard: high-signal secret token shapes embedded in text
// about to be written (a file, an MCP payload). Pure — no Bun/Node APIs,
// no harness protocol shapes. The rule table itself is policy data
// (policy/baseline.toml, `[[rules.write_secret]]`); this module owns only
// the scanning algorithm, parameterized over whichever table is loaded
// (createScanSecrets) — `scanSecrets` is that algorithm bound to the
// embedded baseline, for callers that don't need overlay/override
// awareness (most tests, all 214 fixtures).
//
// ─── Posture (defense in depth, not a vault) ─────────────────────────
// REGEX-only and fast (a PreToolUse gate must be cheap): it catches
// high-signal token shapes. Obfuscated or novel encodings slip through by
// design — deeper, entropy-based / history-wide detection is a separate
// GIT-LEVEL net (gitleaks) wired at pre-commit, not here.

import { BASELINE } from './policy/baseline.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { RegexRule } from './policy/schema.ts';
import type { Verdict } from './types.ts';

export type ScanSecrets = (text: string, target: string) => Verdict | null;

/**
 * Builds a scanSecrets() bound to the given rule table (baseline, or a
 * merged baseline+overlay+override set from src/policy/load.ts).
 */
export function createScanSecrets(rules: readonly RegexRule[]): ScanSecrets {
  const compiled = compileRules(rules);
  return (text, target) => {
    if (!text) return null;
    const hit = firstMatch(compiled, text, 'block');
    return hit ? { ...hit, target } : null;
  };
}

/** Scans text for an embedded secret value, using the embedded baseline. */
export const scanSecrets: ScanSecrets = createScanSecrets(BASELINE.rules.write_secret);
