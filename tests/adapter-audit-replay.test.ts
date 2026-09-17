// Ticket 54 replay is direct reconstruction: no selectors or codecs run, and
// no tool is executed. Superset surfaces err toward still-friction; named
// exclusions stay as logged instead of inventing a replayable payload.
import { describe, expect, test } from 'bun:test';
import { replayEntries, transitionFor } from '../src/adapter/audit-replay.ts';
import type { AuditEntry } from '../src/adapter/audit.ts';
import { createDispatcher } from '../src/adapter/dispatch.ts';
import type { Dispatcher, FamilyVerdict } from '../src/adapter/dispatch.ts';
import { findToolRow } from '../src/adapter/neutral-call.ts';
import type { NeutralCall } from '../src/adapter/neutral-call.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { HarnessProtocol, HarnessToolRow } from '../src/policy/schema.ts';
import type { VerdictKind } from '../src/types.ts';

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: '2026-09-16T12:00:00.000Z',
    sessionId: 'session-1',
    toolName: 'Bash',
    harness: 'claude-code',
    family: 'command',
    verdict: 'confirm',
    ruleId: 'git-protected',
    target: 'git push origin main',
    truncated: false,
    ...overrides,
  };
}

function protocol(tools: Readonly<Record<string, HarnessToolRow>>): HarnessProtocol {
  return {
    transport: 'stdin-json',
    input: {
      event: 'hook_event_name',
      tool: 'tool_name',
      input: 'tool_input',
      session: 'session_id',
      cwd: 'cwd',
    },
    events: { pre_tool: 'PreToolUse' },
    tools,
    output: {
      block: 'deny',
      confirm: 'ask',
      observe: 'silent',
      flag: 'context',
      on_malformed: 'allow',
    },
    templates: {},
  };
}

function recordingDispatcher(
  preToolHit: FamilyVerdict | null = null,
  observeHit: FamilyVerdict | null = null,
): { readonly dispatcher: Dispatcher; readonly calls: NeutralCall[]; } {
  const calls: NeutralCall[] = [];
  return {
    calls,
    dispatcher: {
      inspectPreToolUse: async (call) => {
        calls.push(call);
        return preToolHit;
      },
      classifyObserve: () => observeHit,
      inspectUserPromptSubmit: () => [],
    },
  };
}

describe('findToolRow', () => {
  test('prefers an exact tool row over a matching trailing-star row', () => {
    const exact: HarnessToolRow = { role: 'command', command: 'command' };
    const glob: HarnessToolRow = { role: 'mcp' };
    expect(findToolRow({ 'mcp__sample__execute': exact, 'mcp__*': glob }, 'mcp__sample__execute')).toBe(exact);
    expect(findToolRow({ 'mcp__*': glob }, 'mcp__other__execute')).toBe(glob);
  });
});

describe('replayEntries', () => {
  test('preserves policy surfaces by replaying resolved rows through the real dispatcher', async () => {
    const entries = [
      entry({
        toolName: 'ExecuteFile',
        target: '/workspace/.env',
        family: 'secret',
        verdict: 'block',
        ruleId: 'dotenv',
      }),
      entry({
        toolName: 'Read',
        target: 'notes.txt; /workspace/.env:1-5',
        family: 'secret',
        verdict: 'block',
        ruleId: 'dotenv',
      }),
      entry({
        toolName: 'Glob',
        target: '/workspace/.env',
        family: 'secret',
        verdict: 'block',
        ruleId: 'dotenv',
      }),
      entry({
        toolName: 'CodecTool',
        target: '/workspace/.env',
        family: 'secret',
        verdict: 'block',
        ruleId: 'dotenv',
      }),
    ];
    const result = await replayEntries(
      entries,
      'claude-code',
      protocol({
        ExecuteFile: { role: 'command', command: 'command', path: 'path' },
        Read: { role: 'read', path: 'path' },
        Glob: { role: 'read', path: 'path', pattern: 'pattern' },
        CodecTool: { role: 'mcp', codec: 'apply-patch' },
      }),
      createDispatcher(BASELINE.rules),
    );

    expect(result.replayedCount).toBe(4);
    expect(result.results).toMatchObject([
      { replayed: { family: 'secret', verdict: { verdict: 'block', ruleId: 'bash-dotenv' } } },
      { replayed: { family: 'secret', verdict: { verdict: 'block', ruleId: 'dotenv' } } },
      { replayed: { family: 'secret', verdict: { verdict: 'block', ruleId: 'dotenv' } } },
      { replayed: { family: 'secret', verdict: { verdict: 'block', ruleId: 'dotenv' } } },
    ]);
  });

  test('runs the pre-tool judge before observe, and awaits entries sequentially', async () => {
    const firstDone = Promise.withResolvers<void>();
    let started = 0;
    let observed = false;
    const dispatcher: Dispatcher = {
      inspectPreToolUse: async () => {
        started += 1;
        if (started === 1) await firstDone.promise;
        return null;
      },
      classifyObserve: () => {
        observed = true;
        return null;
      },
      inspectUserPromptSubmit: () => [],
    };

    const replaying = replayEntries(
      [entry(), entry({ target: 'git push origin release' })],
      'claude-code',
      protocol({ Bash: { role: 'command', command: 'command' } }),
      dispatcher,
    );
    await Promise.resolve();
    expect(started).toBe(1);
    firstDone.resolve();
    await replaying;
    expect(started).toBe(2);
    expect(observed).toBe(true);
  });

  test('keeps a pre-tool hit instead of allowing observe to shadow it', async () => {
    const preToolHit: FamilyVerdict = {
      family: 'command',
      verdict: { verdict: 'block', ruleId: 'rm-rf-dangerous', reason: 'dangerous', target: 'rm -rf /' },
    };
    const { dispatcher } = recordingDispatcher(preToolHit, {
      family: 'command',
      verdict: { verdict: 'observe', ruleId: 'git-conditional-status', reason: 'safe', target: 'git status' },
    });

    const { results } = await replayEntries(
      [entry({ verdict: 'confirm' })],
      'claude-code',
      protocol({ Bash: { role: 'command', command: 'command' } }),
      dispatcher,
    );

    expect(results).toEqual([{ replayed: preToolHit, transition: 'hardened' }]);
  });

  test('excludes each non-replayable entry with an independent header count', async () => {
    const { dispatcher } = recordingDispatcher();
    const { results, exclusions } = await replayEntries(
      [
        entry({ truncated: true }),
        entry({ family: 'write-secret' }),
        entry({ family: 'prompt', verdict: 'flag' }),
        entry({ toolName: null }),
        entry({ harness: 'codex' }),
      ],
      'claude-code',
      protocol({ Bash: { role: 'command', command: 'command' } }),
      dispatcher,
    );

    expect(results).toEqual([
      { excluded: 'truncated' },
      { excluded: 'write-secret' },
      { excluded: 'prompt' },
      { excluded: 'unknown-tool' },
      { excluded: 'other-harness' },
    ]);
    expect(exclusions).toEqual({ truncated: 1, 'write-secret': 1, prompt: 1, 'unknown-tool': 1, 'other-harness': 1 });
  });
});

describe('transitionFor', () => {
  const historicalVerdicts: readonly VerdictKind[] = ['block', 'confirm', 'observe', 'flag'];
  const currentVerdicts: readonly (VerdictKind | 'allow')[] = ['allow', 'block', 'confirm', 'observe'];
  type Transition = 'resolved' | 'softened' | 'hardened' | 'drift' | null;
  const expected: Readonly<Record<VerdictKind, readonly Transition[]>> = {
    block: ['resolved', null, 'softened', 'softened'],
    confirm: ['resolved', 'hardened', null, 'softened'],
    observe: ['drift', 'hardened', 'hardened', null],
    flag: [null, null, null, null],
  };

  test('classifies every historical and current verdict pair', () => {
    for (const historical of historicalVerdicts) {
      for (const [index, current] of currentVerdicts.entries()) {
        expect(transitionFor(historical, current)).toBe(expected[historical][index]!);
      }
    }
  });
});
