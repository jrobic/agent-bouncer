// Write-secret guard rules: high-signal secret token shapes embedded in
// text about to be written (a file, an MCP payload). Pure — no Bun/Node
// APIs, no harness protocol shapes.
//
// ─── Posture (defense in depth, not a vault) ─────────────────────────
// REGEX-only and fast (a PreToolUse gate must be cheap): it catches
// high-signal token shapes. Obfuscated or novel encodings slip through by
// design — deeper, entropy-based / history-wide detection is a separate
// GIT-LEVEL net (gitleaks) wired at pre-commit, not here.

import type { Verdict } from './types.ts';

interface SecretRule {
  regex: RegExp;
  ruleId: string;
  reason: string;
}

// High-signal token shapes only — distinctive enough that a match is almost
// always a real credential. Trade-off: a realistic-SHAPED placeholder (e.g. a
// doc token of the right form) can still trip a rule; we favour blocking. The
// entropy-based catch-all is deliberately left to gitleaks (pre-commit).
export const SECRET_RULES: readonly SecretRule[] = [
  {
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    ruleId: 'private-key',
    reason: 'PEM/OpenSSH private key block',
  },
  { regex: /\bAKIA[0-9A-Z]{16}\b/, ruleId: 'aws-access-key-id', reason: 'AWS access key id' },
  {
    regex: /\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
    ruleId: 'github-pat',
    reason: 'GitHub personal access token',
  },
  {
    regex: /\bgh[ousr]_[A-Za-z0-9]{36}\b/,
    ruleId: 'github-token',
    reason: 'GitHub OAuth/app/refresh token',
  },
  {
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    ruleId: 'slack-token',
    reason: 'Slack token',
  },
  { regex: /\bAIza[0-9A-Za-z_-]{35}\b/, ruleId: 'google-api-key', reason: 'Google API key' },
  {
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/,
    ruleId: 'stripe-secret-key',
    reason: 'Stripe live secret key',
  },
  {
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    ruleId: 'jwt',
    reason: 'JSON Web Token (possible embedded credential)',
  },
];

/**
 * Scans text for an embedded secret value. Returns the first matching rule
 * as a block Verdict, or null if clean.
 */
export function scanSecrets(text: string, target: string): Verdict | null {
  if (!text) return null;
  for (const rule of SECRET_RULES) {
    if (rule.regex.test(text)) {
      return { verdict: 'block', ruleId: rule.ruleId, reason: rule.reason, target };
    }
  }
  return null;
}
