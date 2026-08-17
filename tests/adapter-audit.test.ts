// Pure audit logic (ticket 10): JSONL parsing, target normalization,
// clustering, dead-conditional-rule detection, and report/suggest
// rendering. No filesystem — see tests/cli-commands-audit.test.ts for the
// `runAudit` command-level tests (log file + policy overlay on disk).

import { describe, expect, test } from 'bun:test';
import {
  clusterEntries,
  conditionalRuleIdsOf,
  findDeadConditionalRules,
  MCP_TOOL_NAME,
  normalizeTarget,
  parseLogEntries,
  RELAX_LEVERS,
  renderReport,
  renderSuggestions,
  withinWindow,
} from '../src/adapter/audit.ts';
import { createCheckMcpWrite } from '../src/mcp-write-rules.ts';
import { loadPolicyFromOverlayText } from '../src/policy/load.ts';
import { resolvableRuleIds } from '../src/policy/lint.ts';
import { RELAXABLE_LISTS } from '../src/policy/schema.ts';
import type { AuditEntry } from '../src/adapter/audit.ts';

const BASELINE_POLICY = loadPolicyFromOverlayText(null).policy;

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: '2026-08-10T12:00:00.000Z',
    sessionId: 'sess-1',
    toolName: 'Bash',
    family: 'command',
    verdict: 'confirm',
    ruleId: 'git-protected',
    target: 'git push origin main',
    ...overrides,
  };
}

describe('parseLogEntries', () => {
  test('parses a verdict JSONL line into an AuditEntry', () => {
    const line = JSON.stringify({
      timestamp: '2026-08-10T12:00:00.000Z',
      session_id: 'sess-1',
      tool_name: 'Bash',
      family: 'command',
      verdict: 'confirm',
      rule_id: 'git-protected',
      target: 'git push origin main',
    });
    const entries = parseLogEntries(line);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({
      timestamp: '2026-08-10T12:00:00.000Z',
      sessionId: 'sess-1',
      toolName: 'Bash',
      family: 'command',
      verdict: 'confirm',
      ruleId: 'git-protected',
      target: 'git push origin main',
    });
  });

  test('skips audit-header and policy-warning lines (no rule_id/verdict/family)', () => {
    const lines = [
      JSON.stringify({ timestamp: 't', kind: 'audit-header', overrides: [], relaxations: [] }),
      JSON.stringify({ timestamp: 't', kind: 'policy-warning', message: 'oops' }),
      JSON.stringify({
        timestamp: 't',
        session_id: null,
        tool_name: 'Bash',
        family: 'command',
        verdict: 'block',
        rule_id: 'rm-rf-dangerous',
        target: 'rm -rf /',
      }),
    ].join('\n');
    const entries = parseLogEntries(lines);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.ruleId).toBe('rm-rf-dangerous');
  });

  test('skips a corrupted line without failing the whole parse', () => {
    const lines = [
      'not valid json {{{',
      JSON.stringify({
        timestamp: 't',
        tool_name: 'Bash',
        family: 'command',
        verdict: 'block',
        rule_id: 'sudo',
        target: 'sudo rm -rf /',
      }),
    ].join('\n');
    const entries = parseLogEntries(lines);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.ruleId).toBe('sudo');
  });

  test('ignores blank lines and an empty log', () => {
    expect(parseLogEntries('')).toHaveLength(0);
    expect(parseLogEntries('\n\n  \n')).toHaveLength(0);
  });

  test('session_id/tool_name default to null when absent or non-string', () => {
    const line = JSON.stringify({
      timestamp: 't',
      family: 'command',
      verdict: 'block',
      rule_id: 'sudo',
      target: 'sudo ls',
    });
    const [parsed] = parseLogEntries(line);
    expect(parsed!.sessionId).toBeNull();
    expect(parsed!.toolName).toBeNull();
  });
});

describe('withinWindow', () => {
  const now = new Date('2026-08-16T00:00:00.000Z');

  test('keeps entries inside the day window, drops entries outside it', () => {
    const inside = entry({ timestamp: '2026-08-10T00:00:00.000Z' }); // 6 days ago
    const outside = entry({ timestamp: '2026-07-01T00:00:00.000Z' }); // way older
    const kept = withinWindow([inside, outside], 30, now);
    expect(kept).toEqual([inside]);
  });

  test('drops entries with an unparseable timestamp', () => {
    const bad = entry({ timestamp: 'not-a-date' });
    expect(withinWindow([bad], 30, now)).toHaveLength(0);
  });
});

describe('normalizeTarget', () => {
  test('collapses a home-directory prefix to ~', () => {
    expect(normalizeTarget('/Users/jrobic/project/.env')).toBe('~/project/.env');
    expect(normalizeTarget('/home/alice/.ssh/config')).toBe('~/.ssh/config');
  });

  test('collapses a bare home directory with no trailing path', () => {
    expect(normalizeTarget('/Users/jrobic')).toBe('~');
  });

  test('collapses a commit-hash-shaped token', () => {
    expect(normalizeTarget('a1b2c3d')).toBe('<hash>');
    expect(normalizeTarget('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b')).toBe('<hash>');
  });

  test('collapses a pure-number token', () => {
    expect(normalizeTarget('12345')).toBe('<n>');
  });

  test('collapses a UUID-shaped token', () => {
    expect(normalizeTarget('550e8400-e29b-41d4-a716-446655440000')).toBe('<uuid>');
  });

  test('collapses a specific filename with an extension', () => {
    expect(normalizeTarget('notes.txt')).toBe('<file>');
  });

  test('two git push invocations differing only by branch name cluster to the same shape', () => {
    expect(normalizeTarget('git push origin main')).toBe(normalizeTarget('git push origin feature-x'));
    expect(normalizeTarget('git push origin main')).toBe('git push <arg> <arg>');
  });

  test('keeps flags literal (structure, not data) while collapsing trailing positionals', () => {
    expect(normalizeTarget('git rebase -i HEAD~3')).toBe('git rebase -i <arg>');
  });

  test('a single bare word (no spaces) below the positional-collapse threshold stays literal', () => {
    expect(normalizeTarget('mcp__github__push_files')).toBe('mcp__github__push_files');
  });
});

describe('clusterEntries', () => {
  test('groups same rule id + shape together, counting occurrences', () => {
    const entries: AuditEntry[] = [
      entry({ target: 'git push origin main', timestamp: '2026-08-10T00:00:00.000Z' }),
      entry({ target: 'git push origin feature-x', timestamp: '2026-08-12T00:00:00.000Z' }),
      entry({ target: 'git push upstream dev', timestamp: '2026-08-11T00:00:00.000Z' }),
    ];
    const clusters = clusterEntries(entries);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.count).toBe(3);
    expect(clusters[0]!.ruleId).toBe('git-protected');
    expect(clusters[0]!.shape).toBe('git push <arg> <arg>');
    expect(clusters[0]!.lastSeen).toBe('2026-08-12T00:00:00.000Z');
  });

  test('keeps different rule ids or different shapes in separate clusters', () => {
    const entries: AuditEntry[] = [
      entry({ ruleId: 'git-protected', target: 'git push origin main' }),
      entry({ ruleId: 'git-protected', target: 'git rebase -i HEAD~3' }),
      entry({ ruleId: 'sudo', target: 'sudo ls', verdict: 'block' }),
    ];
    const clusters = clusterEntries(entries);
    expect(clusters).toHaveLength(3);
  });

  test('sorts by frequency (desc) then recency (desc)', () => {
    const entries: AuditEntry[] = [
      entry({ ruleId: 'a', target: 'x', timestamp: '2026-08-01T00:00:00.000Z' }),
      entry({ ruleId: 'b', target: 'y', timestamp: '2026-08-15T00:00:00.000Z' }),
      entry({ ruleId: 'b', target: 'y', timestamp: '2026-08-14T00:00:00.000Z' }),
    ];
    const clusters = clusterEntries(entries);
    expect(clusters[0]!.ruleId).toBe('b'); // 2 hits beats 1
    expect(clusters[1]!.ruleId).toBe('a');
  });

  test('caps stored example targets without capping the count', () => {
    const entries: AuditEntry[] = Array.from({ length: 10 }, (_, i) =>
      entry({ target: `git push origin branch-${i}`, timestamp: `2026-08-0${(i % 9) + 1}T00:00:00.000Z` }));
    const [cluster] = clusterEntries(entries);
    expect(cluster!.count).toBe(10);
    expect(cluster!.exampleTargets.length).toBeLessThanOrEqual(3);
  });

  // Pin (review round on ticket 08): the classic `audit` report never
  // distinguishes shadow-tagged entries from enforced ones — `mode` is not
  // part of the clustering key at all, deliberately (audit-diff.ts, not
  // this module, is where the shadow/enforce distinction matters). A log
  // spanning a shadow-mode window and a post-cutover enforced window still
  // clusters as one continuous history.
  test('a MIXED shadow+enforce log clusters identically to an all-enforce one — mode plays no part', () => {
    const mixed: AuditEntry[] = [
      entry({ target: 'git push origin main', timestamp: '2026-08-10T00:00:00.000Z', mode: 'shadow' }),
      entry({ target: 'git push origin feature-x', timestamp: '2026-08-12T00:00:00.000Z' }), // enforced, no mode
      entry({ target: 'git push upstream dev', timestamp: '2026-08-11T00:00:00.000Z', mode: 'shadow' }),
    ];
    const allEnforced: AuditEntry[] = mixed.map(({ mode: _omit, ...rest }) => rest);

    const mixedClusters = clusterEntries(mixed);
    const enforcedClusters = clusterEntries(allEnforced);
    expect(mixedClusters).toHaveLength(1);
    expect(mixedClusters[0]!.count).toBe(3);
    // Same shape/count/lastSeen regardless of which entries were shadow —
    // the only thing that could differ is fields clusterEntries doesn't
    // even read.
    expect(mixedClusters[0]!.count).toBe(enforcedClusters[0]!.count);
    expect(mixedClusters[0]!.shape).toBe(enforcedClusters[0]!.shape);
    expect(mixedClusters[0]!.lastSeen).toBe(enforcedClusters[0]!.lastSeen);
  });
});

describe('conditionalRuleIdsOf / findDeadConditionalRules', () => {
  test('enumerates every git-conditional-<sub> id the baseline policy can produce', () => {
    const ids = conditionalRuleIdsOf(BASELINE_POLICY.command.git);
    expect(ids).toContain('git-conditional-apply');
    expect(ids).toContain('git-conditional-branch');
    expect(ids).toContain('git-conditional-checkout');
    expect(ids).toContain('git-conditional-restore');
    // Unconditionally-safe subcommands (status, log, ...) never produce an
    // observe verdict at all — they must not appear here.
    expect(ids).not.toContain('git-conditional-status');
  });

  test('a rule id present in the fired set is not reported dead', () => {
    const fired = new Set(['git-conditional-apply']);
    const dead = findDeadConditionalRules(BASELINE_POLICY, fired);
    expect(dead).not.toContain('git-conditional-apply');
    expect(dead).toContain('git-conditional-branch');
  });

  test('an empty fired set reports every conditional rule as dead', () => {
    const dead = findDeadConditionalRules(BASELINE_POLICY, new Set());
    expect(dead.length).toBe(conditionalRuleIdsOf(BASELINE_POLICY.command.git).length);
  });
});

// Extracts one `## <heading>`-delimited section's own body — used instead
// of a whole-report `.toContain(id)` so a test can assert an id is absent
// from ONE section specifically without a false pass when that same id is
// (correctly) present in a DIFFERENT section, or sits on the report's last
// line with no trailing newline to match against.
function sectionOf(report: string, heading: string): string {
  const lines = report.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`## ${heading}`));
  if (start === -1) return '';
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('## '));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

describe('renderReport', () => {
  test('surfaces frequent friction with count and shape', () => {
    const clusters = clusterEntries([
      entry({ target: 'git push origin main' }),
      entry({ target: 'git push origin feature-x' }),
    ]);
    const report = renderReport(clusters, [], { days: 30 });
    expect(report).toContain('Frequent friction');
    expect(report).toContain('git-protected');
    expect(report).toContain('2x');
    expect(report).toContain('allowlist candidate');
  });

  test('surfaces dead conditional rules by id', () => {
    const report = renderReport([], ['git-conditional-tag', 'git-conditional-worktree'], { days: 30 });
    expect(report).toContain('Dead conditional rules');
    expect(report).toContain('git-conditional-tag');
    expect(report).toContain('git-conditional-worktree');
  });

  test('says explicitly when a section is empty rather than omitting it', () => {
    const report = renderReport([], [], { days: 7 });
    expect(report).toContain('Frequent friction');
    expect(report).toContain('Conditional rules that fired');
    expect(report).toContain('Dead conditional rules');
    expect(report.toLowerCase()).toContain('none');
  });

  test('only block/confirm clusters count as friction — observe clusters are excluded from that section', () => {
    const clusters = clusterEntries([
      entry({ ruleId: 'git-conditional-apply', verdict: 'observe', target: 'git apply --check p.diff' }),
    ]);
    const report = renderReport(clusters, [], { days: 30 });
    expect(sectionOf(report, 'Frequent friction')).not.toContain('git-conditional-apply');
  });

  test('Story 10: a conditional rule that fired is surfaced in its OWN section, not just absent from friction/dead', () => {
    const clusters = clusterEntries([
      entry({ ruleId: 'git-conditional-apply', verdict: 'observe', target: 'git apply --check p.diff' }),
      entry({ ruleId: 'git-conditional-apply', verdict: 'observe', target: 'git apply --check p.diff' }),
    ]);
    const deadIds = findDeadConditionalRules(BASELINE_POLICY, new Set(['git-conditional-apply']));
    const report = renderReport(clusters, deadIds, { days: 30 });

    const fired = sectionOf(report, 'Conditional rules that fired');
    expect(fired).toContain('git-conditional-apply');
    expect(fired).toContain('2x');

    // The section is placed between friction and dead rules, and the same
    // id must not ALSO appear as dead (it fired) or as friction (it's an
    // observe, not a block/confirm).
    expect(sectionOf(report, 'Dead conditional rules')).not.toContain('git-conditional-apply');
    expect(sectionOf(report, 'Frequent friction')).not.toContain('git-conditional-apply');
    const friction = report.indexOf('## Frequent friction');
    const firedHeading = report.indexOf('## Conditional rules that fired');
    const dead = report.indexOf('## Dead conditional rules');
    expect(friction).toBeLessThan(firedHeading);
    expect(firedHeading).toBeLessThan(dead);
  });

  test('a conditional rule that never fired says so explicitly rather than omitting the section', () => {
    const report = renderReport([], [], { days: 30 });
    expect(sectionOf(report, 'Conditional rules that fired').toLowerCase()).toContain('none');
  });
});

describe('renderSuggestions', () => {
  const resolvable = resolvableRuleIds(BASELINE_POLICY);

  test('a command.git.safe_subcommands relax for frequent git-protected friction ships COMMENTED, never active '
    + '(round-3 review: an uncommented [[relax]] on this list silently bypasses the WHOLE subcommand grammar, '
    + '--force included, not just the audited shape)', () => {
    const clusters = clusterEntries([
      entry({ target: 'git push origin main' }),
      entry({ target: 'git push origin feature-x' }),
    ]);
    const text = renderSuggestions(clusters, resolvable, { days: 30 });

    // Every line of the block is commented — not just wrapped in a leading
    // explanatory comment with an active block still inside it.
    expect(text).toContain('# [[relax]]');
    expect(text).toContain('# list = "command.git.safe_subcommands"');
    expect(text).toContain('# value = "push"');
    expect(text).toMatch(/# reason = ".+"/);
    // No UNcommented occurrence of the block header sneaks through either.
    expect(text).not.toMatch(/^\[\[relax\]\]$/m);

    // The reason states the scope risk explicitly, not just count/shape.
    expect(text.toLowerCase()).toContain('--force');
    expect(text.toLowerCase()).toContain('every git push form');

    // And structurally: loading this text applies zero relaxation to
    // safe_subcommands — the comment is genuinely inert, not just visually
    // de-emphasized.
    const result = loadPolicyFromOverlayText(text);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.git.safe_subcommands).not.toContain('push');
  });

  test('emits a [[override]] relax snippet for a resolvable regex-rule id', () => {
    const clusters = clusterEntries([
      entry({ ruleId: 'dotenv', family: 'secret', verdict: 'block', target: '/Users/jrobic/project/.env' }),
    ]);
    const text = renderSuggestions(clusters, resolvable, { days: 30 });
    expect(text).toContain('[[override]]');
    expect(text).toContain('rule = "dotenv"');
    expect(text).toContain('action = "relax"');
    expect(text).toContain('verdict = "confirm"');
  });

  test('emits a comment (no invalid TOML block) when no policy lever exists for a rule id', () => {
    const clusters = clusterEntries([
      entry({ ruleId: 'rm-rf-dangerous', verdict: 'block', target: 'rm -rf /some/dir' }),
    ]);
    const text = renderSuggestions(clusters, resolvable, { days: 30 });
    expect(text).not.toContain('[[relax]]');
    expect(text).not.toContain('[[override]]');
    expect(text).toContain('# rm-rf-dangerous');
  });

  test('dedupes repeated relax suggestions for the same subcommand across shapes', () => {
    const clusters = clusterEntries([
      entry({ target: 'git push origin main' }),
      entry({ target: 'git push origin main extra-token' }), // different shape, same sub
    ]);
    const text = renderSuggestions(clusters, resolvable, { days: 30 });
    expect(text.match(/\[\[relax\]\]/g)?.length).toBe(1);
  });

  test('the full suggest output is valid TOML that loadPolicyFromOverlayText accepts with zero warnings, '
    + 'and the commented git block stays inert alongside the active mcp/override ones', () => {
    const clusters = clusterEntries([
      entry({ target: 'git push origin main' }),
      entry({ ruleId: 'dotenv', family: 'secret', verdict: 'block', target: '/Users/jrobic/project/.env' }),
      entry({ ruleId: 'mcp-write', family: 'mcp-write', verdict: 'confirm', target: 'mcp__github__list_issues' }),
    ]);
    const text = renderSuggestions(clusters, resolvable, { days: 30 });
    const result = loadPolicyFromOverlayText(text);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    // The active levers (mcp read_prefixes, the dotenv override) actually
    // applied...
    expect(result.policy.mcp_write.read_prefixes).toContain('list_issues');
    expect(result.activeOverrides.some((o) => o.rule === 'dotenv')).toBe(true);
    // ...while the commented git one did not.
    expect(result.policy.command.git.safe_subcommands).not.toContain('push');
  });

  test('an empty-friction cluster set produces a TOML-safe "nothing to suggest" comment', () => {
    const text = renderSuggestions([], resolvable, { days: 30 });
    expect(text).toContain('#');
    const result = loadPolicyFromOverlayText(text);
    expect(result.warnings).toEqual([]);
  });
});

describe('RELAX_LEVERS: schema-drift guard (round-3 review item 8)', () => {
  test('every lever\'s `list` is a member of the runtime RELAXABLE_LISTS companion', () => {
    for (const lever of RELAX_LEVERS) {
      expect(RELAXABLE_LISTS).toContain(lever.list);
    }
  });
});

describe('MCP_TOOL_NAME: drift guard against mcp-write-rules.ts\'s own (private) regex (round-3 review item 10)', () => {
  // audit.ts deliberately duplicates the split rule rather than importing
  // the security module's private regex (see audit.ts's own comment on
  // MCP_TOOL_NAME). This proves the duplicate hasn't drifted: whatever
  // audit.ts thinks the "operation" substring is, mcp-write-rules.ts's REAL
  // checker — given a read-prefix list containing exactly that string —
  // must treat the same tool name as a read (return null), for every
  // vector below, real server-name shapes included.
  const TOOL_NAMES: readonly string[] = [
    'mcp__github__list_issues',
    'mcp__plugin_context-mode_context-mode__ctx_execute',
    'mcp__filesystem__read_file',
    'mcp__plugin__deploy__getStatus', // extra `__` in the operation segment
    'mcp__server__', // empty operation
    'not-an-mcp-tool',
    'Bash',
  ];

  test('audit.ts\'s extracted operation, fed back as the ONLY read prefix, is treated as a read by the real checker', () => {
    for (const toolName of TOOL_NAMES) {
      const operation = MCP_TOOL_NAME.exec(toolName)?.[1];
      const checkMcpWrite = createCheckMcpWrite(operation ? [operation] : []);
      const verdict = checkMcpWrite(toolName);
      if (operation) {
        expect(verdict).toBeNull();
      } else {
        // No operation extracted (out of scope, or an empty capture) —
        // the real checker must agree this name is out of its scope too.
        expect(verdict).toBeNull();
      }
    }
  });
});
