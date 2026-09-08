// One protocol case per abstract-verdict -> harness-action mapping,
// against a hand-built HarnessOutputTable — protocol-agnostic (the
// pre-15a src/adapter/degradation.ts hardcoded Claude Code's own table;
// this proves the pure lookup itself, not any one harness's data). See
// tests/fixtures-protocol.test.ts for proof the REAL claude-code
// declaration produces the same actions end to end.

import { describe, expect, test } from 'bun:test';
import { degradePreToolUseVerdict } from '../src/adapter/degrade.ts';
import type { HarnessOutputTable } from '../src/policy/schema.ts';
import type { Verdict } from '../src/types.ts';

const OUTPUT: HarnessOutputTable = {
  block: 'deny',
  confirm: 'ask',
  observe: 'silent',
  flag: 'context',
  on_malformed: 'allow',
  ask_probe: 'test probe',
};

function verdict(kind: Verdict['verdict'], ruleId = 'some-rule'): Verdict {
  return { verdict: kind, ruleId, reason: 'because reasons', target: 'target' };
}

describe('degradePreToolUseVerdict: one case per mapping', () => {
  test('block -> the table\'s "block" action', () => {
    expect(degradePreToolUseVerdict('block', OUTPUT)).toBe('deny');
  });

  test('confirm -> the table\'s "confirm" action', () => {
    expect(degradePreToolUseVerdict('confirm', OUTPUT)).toBe('ask');
  });

  test('observe -> the table\'s "observe" action (always silent, lint-enforced)', () => {
    expect(degradePreToolUseVerdict('observe', OUTPUT)).toBe('silent');
  });

  test('a deny-only harness (confirm also "deny") degrades confirm to deny', () => {
    const { ask_probe: _askProbe, ...withoutProbe } = OUTPUT;
    const denyOnly: HarnessOutputTable = { ...withoutProbe, confirm: 'deny' };
    expect(degradePreToolUseVerdict('confirm', denyOnly)).toBe('deny');
  });

  test('flag reaching the PreToolUse table is a routing bug, not a silent no-op', () => {
    // flag verdicts belong to UserPromptSubmit and are rendered through
    // renderAction(protocol, protocol.output.flag, ...) directly (see
    // tests/adapter-render.test.ts) — they must never reach this table.
    // Failing loudly here catches a future mis-route instead of silently
    // doing nothing. dispatch.ts's strictestOf already guards this on the
    // real PreToolUse path (tests/adapter-dispatch.test.ts); this is
    // defense in depth against the same bug reaching this function some
    // other way.
    expect(() => degradePreToolUseVerdict(verdict('flag', 'ignore-previous').verdict, OUTPUT)).toThrow(/flag/);
  });
});
