// Unit coverage for dispatch.ts's cross-family severity ordering. No
// current PreToolUse family actually emits `flag` (it belongs to the
// prompt family, UserPromptSubmit-only), so the misrouting guard is
// exercised directly against hand-built FamilyVerdict objects — there is no
// real input that reaches it through inspectPreToolUse today, and that is
// exactly the point: this proves the guard still fires even though nothing
// currently triggers it in practice.

import { describe, expect, test } from 'bun:test';
import type { FamilyVerdict } from '../src/adapter/dispatch.ts';
import { strictestOf } from '../src/adapter/dispatch.ts';

function hit(family: FamilyVerdict['family'], verdictKind: FamilyVerdict['verdict']['verdict'], ruleId: string): FamilyVerdict {
  return {
    family,
    verdict: { verdict: verdictKind, ruleId, reason: 'because reasons', target: 'target' },
  };
}

describe('strictestOf: severity ordering', () => {
  test('block beats confirm regardless of which family found it first', () => {
    const hits = [hit('command', 'confirm', 'git-protected'), hit('secret', 'block', 'bash-git-leak')];
    expect(strictestOf(hits)?.verdict.ruleId).toBe('bash-git-leak');
    // Order-independence: the same two hits, reversed, must agree.
    expect(strictestOf([...hits].reverse())?.verdict.ruleId).toBe('bash-git-leak');
  });

  test('confirm beats observe', () => {
    const hits = [hit('command', 'observe', 'git-conditional-pull'), hit('mcp-write', 'confirm', 'mcp-write')];
    expect(strictestOf(hits)?.verdict.ruleId).toBe('mcp-write');
  });

  test('a single hit is returned as-is', () => {
    const hits = [hit('secret', 'block', 'dotenv')];
    expect(strictestOf(hits)?.verdict.ruleId).toBe('dotenv');
  });

  test('no hits is null', () => {
    expect(strictestOf([])).toBeNull();
  });
});

describe('strictestOf: a flag verdict on PreToolUse is a routing bug, not a silent swallow', () => {
  test('a flag co-occurring with a block does not get swallowed by the max-reduce — it throws', () => {
    // flag has the LOWEST severity (0) — a naive max-reduce would silently
    // pick the block and never surface that a family misrouted a flag onto
    // PreToolUse at all. That silent swallow is exactly what this guard
    // exists to prevent.
    const hits = [hit('command', 'block', 'rm-rf-dangerous'), hit('prompt', 'flag', 'ignore-previous')];
    expect(() => strictestOf(hits)).toThrow(/flag/);
  });

  test('a lone flag hit still throws (not dependent on co-occurrence)', () => {
    expect(() => strictestOf([hit('prompt', 'flag', 'ignore-previous')])).toThrow(/flag/);
  });
});
