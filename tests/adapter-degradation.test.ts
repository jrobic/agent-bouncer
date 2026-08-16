// One protocol case per abstract-verdict -> Claude Code mapping. The table
// itself lives in src/adapter/degradation.ts with its rationale; this file
// only proves each mapping actually produces the action it claims to.

import { describe, expect, test } from 'bun:test';
import type { Verdict } from '../src/types.ts';
import { degradeToClaudeCode } from '../src/adapter/degradation.ts';

function verdict(kind: Verdict['verdict'], ruleId = 'some-rule'): Verdict {
  return { verdict: kind, ruleId, reason: 'because reasons', target: 'target' };
}

describe('degradeToClaudeCode: one case per mapping', () => {
  test('block -> deny', () => {
    const action = degradeToClaudeCode(verdict('block', 'rm-rf-dangerous'));
    expect(action.kind).toBe('deny');
    expect(action).toMatchObject({ kind: 'deny', reason: 'rm-rf-dangerous: because reasons' });
  });

  test('confirm -> ask', () => {
    const action = degradeToClaudeCode(verdict('confirm', 'git-protected'));
    expect(action.kind).toBe('ask');
    expect(action).toMatchObject({ kind: 'ask', reason: 'git-protected: because reasons' });
  });

  test('observe -> logOnly (nothing surfaces to the model)', () => {
    const action = degradeToClaudeCode(verdict('observe', 'git-conditional-pull'));
    expect(action).toEqual({ kind: 'logOnly' });
  });

  test('flag reaching the PreToolUse table is a routing bug, not a silent no-op', () => {
    // flag verdicts belong to UserPromptSubmit and are built into an
    // additionalContext envelope directly (see envelopes.test.ts) — they
    // must never reach this table. Failing loudly here catches a future
    // mis-route instead of silently doing nothing.
    expect(() => degradeToClaudeCode(verdict('flag', 'ignore-previous'))).toThrow(/flag/);
  });
});
