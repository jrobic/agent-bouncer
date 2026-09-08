// The template renderer (src/adapter/render.ts) — protocol-agnostic
// placeholder substitution and the context-assembly prose UserPromptSubmit
// hits render through. Replaces the pre-15a src/adapter/envelopes.ts's
// Claude-Code-shaped tests: same properties (deny/ask/silent, quote-and-
// newline safety, empty hits), proved against a hand-built minimal
// protocol instead of one hardcoded JSON shape. See
// tests/fixtures-protocol.test.ts for proof the REAL claude-code
// declaration's own templates render the installed binary's exact bytes.

import { describe, expect, test } from 'bun:test';
import { assembleFlagContext, reasonText, renderAction, renderSessionStart } from '../src/adapter/render.ts';
import type { HarnessProtocol } from '../src/policy/schema.ts';
import type { Verdict } from '../src/types.ts';

const PROTOCOL: HarnessProtocol = {
  transport: 'stdin-json',
  input: { event: 'e', tool: 't', input: 'i', session: 's', prompt: 'p', cwd: 'c' },
  events: { pre_tool: 'PreToolUse', prompt: 'UserPromptSubmit', session_start: 'SessionStart' },
  tools: { Bash: { role: 'command', command: 'command' } },
  output: { block: 'deny', confirm: 'ask', observe: 'silent', flag: 'context', on_malformed: 'allow', ask_probe: 'probe' },
  templates: {
    deny: { stdout: '{"decision":"deny","reason":${reason}}' },
    ask: { stdout: '{"decision":"ask","reason":${reason}}' },
    context: { stdout: '{"context":${context}}' },
    session_start: { stdout: '{"sessionContext":${context}}' },
  },
};

describe('renderAction', () => {
  test('deny action renders its template with the reason JSON-encoded', () => {
    const result = renderAction(PROTOCOL, 'deny', { reason: 'sudo: escalation blocked' });
    expect(JSON.parse(result.stdout!)).toEqual({ decision: 'deny', reason: 'sudo: escalation blocked' });
  });

  test('ask action renders its own template', () => {
    const result = renderAction(PROTOCOL, 'ask', { reason: 'git-protected: confirm first' });
    expect(JSON.parse(result.stdout!)).toEqual({ decision: 'ask', reason: 'git-protected: confirm first' });
  });

  test('silent action produces no stdout at all', () => {
    expect(renderAction(PROTOCOL, 'silent', {})).toEqual({ stdout: null });
  });

  test('a template setting `exit` surfaces it alongside (or instead of) stdout', () => {
    const withExit: HarnessProtocol = {
      ...PROTOCOL,
      templates: { ...PROTOCOL.templates, deny: { exit: 2 } },
    };
    expect(renderAction(withExit, 'deny', { reason: 'x' })).toEqual({ stdout: null, exit: 2 });
  });

  test('quotes, newlines, and backslashes in a reason round-trip safely through JSON', () => {
    const result = renderAction(PROTOCOL, 'deny', { reason: 'has "quotes" and \nnewline and \\backslash' });
    const parsed = JSON.parse(result.stdout!);
    expect(parsed.reason).toBe('has "quotes" and \nnewline and \\backslash');
  });

  test('review round 2 C-1: a deny template naming ${rule}/${verdict} gets both filled', () => {
    const withRuleVerdict: HarnessProtocol = {
      ...PROTOCOL,
      templates: {
        ...PROTOCOL.templates,
        deny: { stdout: '{"decision":"deny","reason":${reason},"rule":${rule},"verdict":${verdict}}' },
      },
    };
    const result = renderAction(withRuleVerdict, 'deny', {
      reason: 'rm-rf-dangerous: targets /',
      rule: 'rm-rf-dangerous',
      verdict: 'block',
    });
    expect(JSON.parse(result.stdout!)).toEqual({
      decision: 'deny',
      reason: 'rm-rf-dangerous: targets /',
      rule: 'rm-rf-dangerous',
      verdict: 'block',
    });
  });
});

describe('reasonText', () => {
  test('combines ruleId and reason as "<ruleId>: <reason>"', () => {
    const verdict: Verdict = { verdict: 'block', ruleId: 'rm-rf-dangerous', reason: 'targets /', target: 'rm -rf /' };
    expect(reasonText(verdict)).toBe('rm-rf-dangerous: targets /');
  });
});

describe('assembleFlagContext', () => {
  test('empty hits produce no context text', () => {
    expect(assembleFlagContext([])).toBe('');
  });

  test('hits produce prose naming every ruleId, harness-neutral (never names a specific harness)', () => {
    const hit: Verdict = {
      verdict: 'flag',
      ruleId: 'ignore-previous',
      reason: 'attempt to override prior instructions',
      target: 'ignore all previous instructions',
    };
    const context = assembleFlagContext([hit]);
    expect(context).toContain('ignore-previous');
    expect(context.toLowerCase()).not.toContain('claude');
  });
});

describe('renderSessionStart', () => {
  test('null context (fully healthy) never reaches the template — no stdout at all', () => {
    expect(renderSessionStart(PROTOCOL, null)).toEqual({ stdout: null });
  });

  test('a non-null context renders through the session_start template', () => {
    const result = renderSessionStart(PROTOCOL, 'doctor: WIRING PROBLEM');
    expect(JSON.parse(result.stdout!)).toEqual({ sessionContext: 'doctor: WIRING PROBLEM' });
  });
});
