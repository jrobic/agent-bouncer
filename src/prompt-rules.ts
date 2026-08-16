// Prompt-injection detection rules. Pure — no Bun/Node APIs, no harness
// protocol shapes. `buildContextOutput` (the Claude Code `UserPromptSubmit`
// `hookSpecificOutput.additionalContext` envelope) has moved to
// src/adapter/envelopes.ts — this module now speaks only the abstract
// verdict vocabulary, like every other rule family.
//
// ─── Posture (this is a layer, not a wall) ───────────────────────────
// Prompt injection ultimately exploits the LLM, which remains fallible; no
// regex catches every phrasing. Callers are expected to WARN (flag) rather
// than block — the adapter's degradation table maps `flag` to
// additionalContext, never to a hard stop.

import type { Verdict } from './types.ts';

interface PromptRule {
  regex: RegExp;
  ruleId: string;
  reason: string;
}

export const PROMPT_RULES: readonly PromptRule[] = [
  {
    regex:
      /\bignore\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|context|rules?)\b/i,
    ruleId: 'ignore-previous',
    reason: 'attempt to override prior instructions',
  },
  {
    regex: /\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|system)\b/i,
    ruleId: 'disregard',
    reason: 'attempt to discard prior context',
  },
  {
    regex:
      /\b(?:you\s+are\s+now|from\s+now\s+on|act\s+as|pretend\s+to\s+be)\b[^.\n]{0,60}\b(?:dan|jailbreak|unrestricted|no\s+(?:restrictions?|rules?|limits?)|developer\s+mode|do\s+anything)\b/i,
    ruleId: 'role-override',
    reason: 'role/jailbreak override',
  },
  {
    regex: /<\/?\s*(?:system|instructions?|assistant|developer|tool_call|function_call)\s*>/i,
    ruleId: 'injected-role-tag',
    reason: 'injected role/system tag',
  },
  {
    regex:
      /\b(?:new|updated|real|actual|important)\s+(?:system\s+)?(?:instructions?|prompt|directives?)\s*:/i,
    ruleId: 'new-instructions',
    reason: 'injected new-instructions block',
  },
  {
    regex:
      /\b(?:reveal|print|show|repeat|output|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+(?:prompt|instructions)|developer\s+(?:prompt|message))\b/i,
    ruleId: 'prompt-exfil',
    reason: 'attempt to exfiltrate the system prompt',
  },
];

// Long base64-ish blob — a possible encoded payload smuggled into the prompt.
export const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/;

/**
 * Returns all injection signatures matched in the prompt (empty if clean),
 * each as a `flag` Verdict — this family never blocks or confirms.
 */
export function scanPrompt(prompt: string): Verdict[] {
  const hits: Verdict[] = [];
  for (const rule of PROMPT_RULES) {
    if (rule.regex.test(prompt)) {
      hits.push({ verdict: 'flag', ruleId: rule.ruleId, reason: rule.reason, target: prompt });
    }
  }
  if (BASE64_BLOB.test(prompt)) {
    hits.push({
      verdict: 'flag',
      ruleId: 'base64-blob',
      reason: 'long base64 blob (possible encoded payload)',
      target: prompt,
    });
  }
  return hits;
}
