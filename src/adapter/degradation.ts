// The Claude Code degradation table: how each of the core's four abstract
// verdicts maps onto a harness that only understands "deny", "ask", and
// additionalContext — explicit and fail-closed, per the spec's core/adapter
// split (an adapter that cannot express a verdict must degrade toward the
// SAFER outcome, never toward silence).

import type { Verdict } from '../types.ts';

export type CcAction =
  | { readonly kind: 'deny'; readonly reason: string }
  | { readonly kind: 'ask'; readonly reason: string }
  | { readonly kind: 'logOnly' };

// ─── The table ─────────────────────────────────────────────────────────
//
//   block    -> deny              hard stop, tool call never runs
//   confirm  -> ask                interactive prompt
//   flag     -> additionalContext  (handled separately — see envelopes.ts;
//                                   it is UserPromptSubmit-shaped, not
//                                   PreToolUse-shaped, so it never reaches
//                                   this function)
//   observe  -> logOnly            allow proceeds; only the audit log sees it
//
// Measured fact, the reason "confirm -> ask" is still fail-closed and not
// merely a UX nicety: under `--dangerously-skip-permissions`, Claude Code
// has no human to answer an "ask" permissionDecision, and a probe run on
// 2026-08-16 (recorded in the workstation THREAT_MODEL §1) measured that an
// unanswerable "ask" is enforced as an EFFECTIVE DENY, not a silent pass.
// The degradation direction (confirm -> ask, never confirm -> allow) holds
// under both the interactive and the bypass-mode session.
export function degradeToClaudeCode(verdict: Verdict): CcAction {
  switch (verdict.verdict) {
    case 'block':
      return { kind: 'deny', reason: `${verdict.ruleId}: ${verdict.reason}` };
    case 'confirm':
      return { kind: 'ask', reason: `${verdict.ruleId}: ${verdict.reason}` };
    case 'observe':
      return { kind: 'logOnly' };
    case 'flag':
      // Reachable only if a caller mis-routes a flag verdict through the
      // PreToolUse path; flag verdicts always come from the prompt family
      // and are built into a UserPromptSubmit additionalContext envelope
      // directly (see run.ts), never through this table. Degrading toward
      // logOnly here — not deny — would be wrong (no tool call to stop);
      // failing loudly is safer than guessing.
      throw new Error(
        `degradeToClaudeCode: a "flag" verdict reached the PreToolUse degradation table `
          + `(ruleId ${verdict.ruleId}) — flag belongs to UserPromptSubmit only`,
      );
  }
}
