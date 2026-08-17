// Pure audit-diff logic (ticket 08, code-only scope): parsing the TS
// generation's own log lines (guard-command.log etc — schema read from
// ~/dotfiles/claude/hooks/_shared/lib.ts's logDeny, read-only
// reference), correlating them against bouncer's shadow-mode log entries,
// and classifying the three divergence kinds. No filesystem — see
// tests/cli-commands-audit-diff.test.ts for the `runAudit({ diff: true })`
// command-level tests (real files on disk).

import { describe, expect, test } from 'bun:test';
import {
  clusterDivergences,
  type DiffDivergence,
  diffLogs,
  EXPECTED_DIVERGENCES,
  expectedFamilyOf,
  parseTsLogEntries,
  renderDiffReport,
  type TsLogEntry,
} from '../src/adapter/audit-diff.ts';
import type { AuditEntry } from '../src/adapter/audit.ts';

function tsEntry(overrides: Partial<TsLogEntry> = {}): TsLogEntry {
  return {
    timestamp: '2026-08-10T12:00:00.000Z',
    sessionId: 'sess-1',
    toolName: 'Bash',
    decision: 'deny',
    ruleId: 'rm-rf-dangerous',
    target: 'rm -rf /',
    ...overrides,
  };
}

function bouncerEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: '2026-08-10T12:00:00.000Z',
    sessionId: 'sess-1',
    toolName: 'Bash',
    family: 'command',
    verdict: 'block',
    ruleId: 'rm-rf-dangerous',
    target: 'rm -rf /',
    mode: 'shadow',
    ...overrides,
  };
}

// Convenience wrapper so most tests can keep asserting on the divergence
// array directly, same shape as before diffLogs started returning volumes
// too (DiffResult).
function divergencesOf(ts: readonly TsLogEntry[], bouncer: readonly AuditEntry[], days: number, now: Date): DiffDivergence[] {
  return [...diffLogs(ts, bouncer, days, now).divergences];
}

const REPORT_OPTIONS_STUB = { tsEventCount: 0, shadowEntryCount: 0, matchedCount: 0, tsIgnoredLineCount: 0 };

describe('parseTsLogEntries', () => {
  test('parses a logDeny-shaped JSONL line', () => {
    const line = JSON.stringify({
      timestamp: '2026-08-10T12:00:00.000Z',
      session_id: 'sess-1',
      tool_name: 'Bash',
      decision: 'deny',
      rule_id: 'rm-rf-dangerous',
      target: 'rm -rf /',
    });
    const { entries, ignoredLineCount } = parseTsLogEntries(line);
    expect(entries[0]).toEqual({
      timestamp: '2026-08-10T12:00:00.000Z',
      sessionId: 'sess-1',
      toolName: 'Bash',
      decision: 'deny',
      ruleId: 'rm-rf-dangerous',
      target: 'rm -rf /',
    });
    expect(ignoredLineCount).toBe(0);
  });

  test('parses an "ask" decision line too', () => {
    const line = JSON.stringify({
      timestamp: '2026-08-10T12:00:00.000Z',
      session_id: null,
      tool_name: 'Bash',
      decision: 'ask',
      rule_id: 'git-protected',
      target: 'git push origin main',
    });
    expect(parseTsLogEntries(line).entries[0]?.decision).toBe('ask');
  });

  test('a corrupt line is skipped AND counted, not silently dropped', () => {
    const good = JSON.stringify({
      timestamp: '2026-08-10T12:00:00.000Z',
      tool_name: 'Bash',
      decision: 'deny',
      rule_id: 'rm-rf-dangerous',
      target: 'rm -rf /',
    });
    const text = `not json {{{\n${good}\n`;
    const { entries, ignoredLineCount } = parseTsLogEntries(text);
    expect(entries).toHaveLength(1);
    expect(ignoredLineCount).toBe(1);
  });

  test('a line with neither "deny" nor "ask" as decision is not a verdict line, and IS counted as ignored', () => {
    const line = JSON.stringify({ timestamp: '2026-08-10T12:00:00.000Z', decision: 'allow', rule_id: 'x', target: 'y' });
    const { entries, ignoredLineCount } = parseTsLogEntries(line);
    expect(entries).toHaveLength(0);
    expect(ignoredLineCount).toBe(1);
  });

  test('blank lines are skipped WITHOUT counting as ignored — nothing was there to parse', () => {
    const { entries, ignoredLineCount } = parseTsLogEntries('\n\n   \n');
    expect(entries).toEqual([]);
    expect(ignoredLineCount).toBe(0);
  });

  test('multiple corrupt/unrecognized lines all count', () => {
    const text = 'not json\n' + JSON.stringify({ decision: 'allow', rule_id: 'x', timestamp: 't', target: 'y' }) + '\nalso not json\n';
    expect(parseTsLogEntries(text).ignoredLineCount).toBe(3);
  });
});

describe('diffLogs: volumes (tsEventCount / shadowEntryCount / matchedCount)', () => {
  test('reports the grouped TS event count, the shadow entry count, and how many matched', () => {
    const now = new Date('2026-08-10T12:00:10.000Z');
    const ts = [tsEntry(), tsEntry({ ruleId: 'sudo', target: 'sudo apt update', decision: 'deny' })];
    const bouncer = [bouncerEntry()]; // matches the first ts entry only
    const result = diffLogs(ts, bouncer, 30, now);
    expect(result.tsEventCount).toBe(2);
    expect(result.shadowEntryCount).toBe(1);
    expect(result.matchedCount).toBe(1);
  });

  test('a non-shadow bouncer entry never counts toward shadowEntryCount', () => {
    const now = new Date('2026-08-10T12:00:10.000Z');
    const { mode: _omit, ...withoutMode } = bouncerEntry();
    const result = diffLogs([], [withoutMode as AuditEntry], 30, now);
    expect(result.shadowEntryCount).toBe(0);
  });
});

describe('diffLogs: bouncer-would-allow (TS denied/asked, no matched bouncer entry)', () => {
  test('an unmatched TS deny is reported as bouncer-would-allow, naming the TS rule id', () => {
    const divergences = divergencesOf([tsEntry()], [], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(1);
    expect(divergences[0]).toMatchObject({
      kind: 'bouncer-would-allow',
      tsRuleIds: ['rm-rf-dangerous'],
      bouncerRuleId: null,
    });
  });

  test('a bouncer entry OUTSIDE the ±2s window still counts as unmatched', () => {
    const ts = tsEntry({ timestamp: '2026-08-10T12:00:00.000Z' });
    const be = bouncerEntry({ timestamp: '2026-08-10T12:00:05.000Z' }); // 5s away
    const divergences = divergencesOf([ts], [be], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences.filter((d) => d.kind === 'bouncer-would-allow')).toHaveLength(1);
    expect(divergences.filter((d) => d.kind === 'ts-allowed')).toHaveLength(1); // the bouncer entry, now also unmatched
  });
});

describe('diffLogs: ts-allowed (bouncer block/confirm, no matched TS entry)', () => {
  test('an unmatched bouncer block is reported as ts-allowed, naming the bouncer rule id', () => {
    const divergences = divergencesOf([], [bouncerEntry()], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(1);
    expect(divergences[0]).toMatchObject({
      kind: 'ts-allowed',
      tsRuleIds: [],
      bouncerRuleId: 'rm-rf-dangerous',
    });
  });

  test('an unmatched bouncer "observe" entry produces NO divergence — observe is bouncer\'s own silent allow', () => {
    const observeEntry = bouncerEntry({ verdict: 'observe', ruleId: 'git-conditional-apply' });
    const divergences = divergencesOf([], [observeEntry], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(0);
  });

  test('a non-shadow bouncer entry (no mode) is ignored entirely — the diff only compares the shadow window', () => {
    const { mode: _omit, ...withoutMode } = bouncerEntry();
    const divergences = divergencesOf([], [withoutMode as AuditEntry], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(0);
  });
});

describe('diffLogs: verdict-divergence (matched, different verdicts)', () => {
  test('TS deny matched with bouncer confirm is a verdict divergence', () => {
    const divergences = divergencesOf(
      [tsEntry({ decision: 'deny' })],
      [bouncerEntry({ verdict: 'confirm' })],
      30,
      new Date('2026-08-10T12:00:10.000Z'),
    );
    expect(divergences).toHaveLength(1);
    expect(divergences[0]).toMatchObject({
      kind: 'verdict-divergence',
      tsDecision: 'deny',
      bouncerVerdict: 'confirm',
    });
  });

  test('TS deny matched with bouncer "observe" is ALSO a verdict divergence, not silently dropped', () => {
    const divergences = divergencesOf(
      [tsEntry({ decision: 'deny' })],
      [bouncerEntry({ verdict: 'observe' })],
      30,
      new Date('2026-08-10T12:00:10.000Z'),
    );
    expect(divergences).toHaveLength(1);
    expect(divergences[0]?.kind).toBe('verdict-divergence');
  });

  test('matched TS deny + bouncer block: SAME semantic bucket, no divergence at all', () => {
    const divergences = divergencesOf(
      [tsEntry({ decision: 'deny' })],
      [bouncerEntry({ verdict: 'block' })],
      30,
      new Date('2026-08-10T12:00:10.000Z'),
    );
    expect(divergences).toHaveLength(0);
  });

  test('matched TS ask + bouncer confirm: SAME semantic bucket, no divergence', () => {
    const divergences = divergencesOf(
      [tsEntry({ decision: 'ask', ruleId: 'git-protected', target: 'git push origin main' })],
      [bouncerEntry({ verdict: 'confirm', ruleId: 'git-protected', target: 'git push origin main' })],
      30,
      new Date('2026-08-10T12:00:10.000Z'),
    );
    expect(divergences).toHaveLength(0);
  });

  test('a matched pair with DIFFERENT rule ids on each side but the SAME verdict bucket is zero divergence '
    + '(ticket 06 disambiguation: device-redirect split into device-redirect-shell/tee, etc.)', () => {
    const divergences = divergencesOf(
      [tsEntry({ decision: 'deny', ruleId: 'device-redirect', target: '> /dev/sda1' })],
      [bouncerEntry({ verdict: 'block', ruleId: 'device-redirect-shell', target: '> /dev/sda1' })],
      30,
      new Date('2026-08-10T12:00:10.000Z'),
    );
    expect(divergences).toHaveLength(0);
  });
});

describe('diffLogs: TS event grouping is GAP-BASED, not a fixed time bucket (review round on ticket 08)', () => {
  test('two TS lines 1999ms apart, straddling where a Math.floor(t/2000) bucket boundary WOULD fall, still collapse into one event', () => {
    // A fixed-bucket scheme (`Math.floor(t / 2000)`) puts 12:00:01.999 and
    // 12:00:02.001 in DIFFERENT buckets (1999 and 2001) despite being 2ms
    // apart — a phantom split. Gap-based grouping (sorted, new event only
    // when the GAP exceeds the threshold) must not do that.
    const target = 'git config credential.helper store';
    const first = tsEntry({ decision: 'ask', ruleId: 'git-protected', target, timestamp: '2026-08-10T12:00:01.999Z' });
    const second = tsEntry({
      decision: 'deny',
      ruleId: 'bash-git-leak-credential',
      target,
      timestamp: '2026-08-10T12:00:02.001Z',
    });
    const bouncerHit = bouncerEntry({
      verdict: 'block',
      ruleId: 'bash-git-leak-credential',
      target,
      timestamp: '2026-08-10T12:00:02.000Z',
    });

    const result = diffLogs([first, second], [bouncerHit], 30, new Date('2026-08-10T12:01:00.000Z'));
    expect(result.tsEventCount).toBe(1); // ONE combined event, not two
    expect(result.divergences).toHaveLength(0); // strictest (deny) matches bouncer's block
  });

  test('two TS lines genuinely far apart (different real calls) stay TWO separate events', () => {
    const target = 'sudo apt update';
    const first = tsEntry({ ruleId: 'sudo', target, timestamp: '2026-08-10T12:00:00.000Z' });
    const second = tsEntry({ ruleId: 'sudo', target, timestamp: '2026-08-10T12:05:00.000Z' }); // 5 minutes later
    const result = diffLogs([first, second], [], 30, new Date('2026-08-10T12:10:00.000Z'));
    expect(result.tsEventCount).toBe(2);
  });
});

describe('diffLogs: severity-max parity (ticket 05) — a combined multi-family match is NOT a divergence', () => {
  test('two TS hook files denying/asking the SAME real call at the same moment collapse into ONE event, matching bouncer\'s single combined verdict', () => {
    // git config credential.helper store: command family asks (confirm),
    // secret family denies (block) — bouncer keeps the strictest (block).
    // The TS side is genuinely TWO independently-registered hooks, so it
    // would produce two log lines (one per guard file) for the SAME real
    // tool call — diffLogs must collapse them into one TS "event" using
    // the strictest decision (deny), which then correctly matches
    // bouncer's own single "block" entry: no divergence.
    const target = 'git config credential.helper store';
    const tsCommandHit = tsEntry({ decision: 'ask', ruleId: 'git-protected', target });
    const tsSecretHit = tsEntry({ decision: 'deny', ruleId: 'bash-git-leak-credential', target });
    const bouncerHit = bouncerEntry({ verdict: 'block', ruleId: 'bash-git-leak-credential', target });

    const divergences = divergencesOf([tsCommandHit, tsSecretHit], [bouncerHit], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(0);
  });

  test('a GENUINE severity-max mismatch (bouncer picked the wrong strictest verdict) still surfaces as a real divergence', () => {
    const target = 'git config credential.helper store';
    const tsCommandHit = tsEntry({ decision: 'ask', ruleId: 'git-protected', target });
    const tsSecretHit = tsEntry({ decision: 'deny', ruleId: 'bash-git-leak-credential', target });
    // Bug scenario: bouncer wrongly kept the WEAKER (confirm) verdict.
    const bouncerHit = bouncerEntry({ verdict: 'confirm', ruleId: 'git-protected', target });

    const divergences = divergencesOf([tsCommandHit, tsSecretHit], [bouncerHit], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(1);
    expect(divergences[0]?.kind).toBe('verdict-divergence');
  });
});

describe('EXPECTED_DIVERGENCES: the pre-triaged families (ticket 08 § "Divergences attendues") — tightened predicates', () => {
  test('has exactly the three tag-as-expected families', () => {
    expect(EXPECTED_DIVERGENCES.map((f) => f.id).toSorted()).toEqual([
      'guard-log-reads',
      'pull-merge-ff-only-ask',
      'transcripts-deny-to-confirm',
    ]);
  });

  test('every family cites a ticket reference', () => {
    for (const family of EXPECTED_DIVERGENCES) {
      expect(family.ticketRef.length).toBeGreaterThan(0);
    }
  });

  describe('pull-merge-ff-only-ask', () => {
    test('git pull --ff-only (TS allowed, bouncer git-protected) is tagged expected', () => {
      const d: DiffDivergence = {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: 'git-protected',
        tsDecision: null,
        bouncerVerdict: 'confirm',
        toolName: 'Bash',
        target: 'git pull --ff-only',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)?.id).toBe('pull-merge-ff-only-ask');
    });

    test('near-miss: a BARE git pull (no --ff-only at all) is NOT tagged — a real, separate divergence', () => {
      const d: DiffDivergence = {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: 'git-protected',
        tsDecision: null,
        bouncerVerdict: 'confirm',
        toolName: 'Bash',
        target: 'git pull origin main',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)).toBeNull();
    });
  });

  describe('guard-log-reads', () => {
    test('a Read of guard-command.log (TS allowed, no bouncer rule) is tagged expected', () => {
      const d: DiffDivergence = {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: null,
        tsDecision: null,
        bouncerVerdict: null,
        toolName: 'Read',
        target: '/proj/hooks/guard-command.log',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)?.id).toBe('guard-log-reads');
    });

    test('near-miss: bouncer BLOCKING a Bash deletion of guard-command.log is NOT tagged — a real, more severe divergence', () => {
      const d: DiffDivergence = {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: 'hook-log',
        tsDecision: null,
        bouncerVerdict: 'block',
        toolName: 'Bash', // not a read-shaped tool
        target: 'rm /proj/hooks/guard-command.log',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)).toBeNull();
    });
  });

  describe('transcripts-deny-to-confirm', () => {
    test('TS deny + bouncer confirm on transcript-backup, EXACTLY that direction, is tagged expected', () => {
      const d: DiffDivergence = {
        kind: 'verdict-divergence',
        tsRuleIds: ['transcript-backup'],
        bouncerRuleId: 'transcript-backup',
        tsDecision: 'deny',
        bouncerVerdict: 'confirm',
        toolName: 'Read',
        target: '/home/user/.claude/transcripts/foo.json',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)?.id).toBe('transcripts-deny-to-confirm');
    });

    test('near-miss: the REVERSE direction (bouncer weaker than confirm — "observe") is NEVER tagged, even for the same rule id', () => {
      const d: DiffDivergence = {
        kind: 'verdict-divergence',
        tsRuleIds: ['transcript-backup'],
        bouncerRuleId: 'transcript-backup',
        tsDecision: 'deny',
        bouncerVerdict: 'observe',
        toolName: 'Read',
        target: '/home/user/.claude/transcripts/foo.json',
        timestamp: '2026-08-10T12:00:00.000Z',
      };
      expect(expectedFamilyOf(d)).toBeNull();
    });
  });

  test('an ordinary, un-pre-triaged divergence is NOT tagged expected', () => {
    const d: DiffDivergence = {
      kind: 'ts-allowed',
      tsRuleIds: [],
      bouncerRuleId: 'sudo',
      tsDecision: null,
      bouncerVerdict: 'block',
      toolName: 'Bash',
      target: 'sudo apt update',
      timestamp: '2026-08-10T12:00:00.000Z',
    };
    expect(expectedFamilyOf(d)).toBeNull();
  });

  test('end to end through diffLogs: a pull --ff-only TS-allow divergence comes out pre-tagged', () => {
    const ts: TsLogEntry[] = []; // TS never logged this — it allowed silently
    const be = bouncerEntry({ verdict: 'confirm', ruleId: 'git-protected', target: 'git pull --ff-only' });
    const divergences = divergencesOf(ts, [be], 30, new Date('2026-08-10T12:00:10.000Z'));
    expect(divergences).toHaveLength(1);
    expect(expectedFamilyOf(divergences[0]!)?.id).toBe('pull-merge-ff-only-ask');
  });
});

describe('clusterDivergences + renderDiffReport', () => {
  test('groups repeated divergences and reports rule ids on both sides, with counts', () => {
    const divergences: DiffDivergence[] = [
      {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: 'sudo',
        tsDecision: null,
        bouncerVerdict: 'block',
        toolName: 'Bash',
        target: 'sudo apt update',
        timestamp: '2026-08-10T12:00:00.000Z',
      },
      {
        kind: 'ts-allowed',
        tsRuleIds: [],
        bouncerRuleId: 'sudo',
        tsDecision: null,
        bouncerVerdict: 'block',
        toolName: 'Bash',
        target: 'sudo apt install', // same 3-token shape as "sudo apt update" — clusters together
        timestamp: '2026-08-10T12:05:00.000Z',
      },
    ];
    const clusters = clusterDivergences(divergences);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]?.count).toBe(2);
    expect(clusters[0]?.bouncerRuleId).toBe('sudo');

    const report = renderDiffReport(clusters, { days: 30, ...REPORT_OPTIONS_STUB });
    expect(report).toContain('bouncer would deny/ask, TS allowed');
    expect(report).toContain('sudo');
    expect(report).toContain('2x');
  });

  test('renders each of the three section headings even when empty', () => {
    const report = renderDiffReport([], { days: 7, ...REPORT_OPTIONS_STUB });
    expect(report).toContain('TS denied/asked, bouncer would allow');
    expect(report).toContain('bouncer would deny/ask, TS allowed');
    expect(report).toContain('matched, but verdicts differ');
    expect(report.toLowerCase()).toContain('none');
  });

  test('an [expected] tag appears on a pre-triaged cluster, naming the ticket reference', () => {
    const d: DiffDivergence = {
      kind: 'verdict-divergence',
      tsRuleIds: ['transcript-backup'],
      bouncerRuleId: 'transcript-backup',
      tsDecision: 'deny',
      bouncerVerdict: 'confirm',
      toolName: 'Read',
      target: '/home/user/.claude/transcripts/foo.json',
      timestamp: '2026-08-10T12:00:00.000Z',
    };
    const report = renderDiffReport(clusterDivergences([d]), { days: 30, ...REPORT_OPTIONS_STUB });
    expect(report).toContain('[expected');
    expect(report).toContain('ticket 13');
  });

  test('the report states the correlation heuristic explicitly', () => {
    const report = renderDiffReport([], { days: 30, ...REPORT_OPTIONS_STUB });
    expect(report.toLowerCase()).toContain('heuristic');
  });

  test('the report states the settings.json permissions blind spot explicitly (review round on ticket 08)', () => {
    const report = renderDiffReport([], { days: 30, ...REPORT_OPTIONS_STUB });
    expect(report.toLowerCase()).toContain('permissions');
    expect(report.toLowerCase()).toContain('invisible');
  });

  test('the header prints the TS event / shadow entry / matched volumes and the ignored-line count', () => {
    const report = renderDiffReport([], {
      days: 30,
      tsEventCount: 512,
      shadowEntryCount: 480,
      matchedCount: 470,
      tsIgnoredLineCount: 3,
    });
    expect(report).toContain('512');
    expect(report).toContain('480');
    expect(report).toContain('470');
    expect(report).toContain('3');
  });
});
