// Review round 2 on ticket 12, standards item 4: lintOverrides,
// lintGitConditionalRelaxation, and lintEffectiveDialect used to receive
// their entries with no filename attached, so a warning about (say) an
// [[override]] with no reason named the rule but never the file — a user
// with several policy.d/*.toml files had no way to know WHICH one to fix.
// Each now takes FileTagged entries (or, for lintEffectiveDialect, reads
// EffectiveRule.sourceFile, already present) and prefixes every message
// with `${filename}: `, mirroring src/policy/load.ts's own
// lintMergedDialect, which already did this.

import { describe, expect, test } from 'bun:test';
import type { EffectiveRule, FileTagged } from '../src/policy/load.ts';
import { lintEffectiveDialect, lintGitConditionalRelaxation, lintOverrides } from '../src/policy/lint.ts';
import type { OverrideEntry } from '../src/policy/schema.ts';

describe('lintOverrides: names the file an issue came from', () => {
  test('an override with no reason in policy.d/30-x.toml is prefixed with that filename', () => {
    const overrides: FileTagged<OverrideEntry>[] = [
      { filename: 'policy.d/30-x.toml', raw: { rule: 'curl-file-upload', action: 'disable', reason: '' } },
    ];
    const issues = lintOverrides(overrides, new Set(['curl-file-upload']));
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every((i) => i.message.startsWith('policy.d/30-x.toml: '))).toBe(true);
    expect(issues.map((i) => i.message).join(' ')).toContain('reason must not be empty');
  });

  test('two files each contributing an issue are prefixed with their OWN filename, not the other\'s', () => {
    const overrides: FileTagged<OverrideEntry>[] = [
      { filename: 'policy.toml', raw: { rule: 'unresolvable-in-policy-toml', action: 'disable', reason: 'ok' } },
      { filename: 'policy.d/10-a.toml', raw: { rule: 'unresolvable-in-policy-d', action: 'disable', reason: 'ok' } },
    ];
    const issues = lintOverrides(overrides, new Set());
    const forPolicyToml = issues.find((i) => i.message.includes('unresolvable-in-policy-toml'));
    const forPolicyD = issues.find((i) => i.message.includes('unresolvable-in-policy-d'));
    expect(forPolicyToml?.message.startsWith('policy.toml: ')).toBe(true);
    expect(forPolicyD?.message.startsWith('policy.d/10-a.toml: ')).toBe(true);
  });
});

describe('lintGitConditionalRelaxation: names the file an issue came from', () => {
  test('a reason-less substitution of a baseline-governed sub is prefixed with its file', () => {
    const entries: FileTagged<{ readonly sub: string; readonly reason?: string }>[] = [
      { filename: 'policy.d/30-x.toml', raw: { sub: 'branch' } },
    ];
    const issues = lintGitConditionalRelaxation(entries, 'ask_flags', new Set(['branch']));
    expect(issues).toHaveLength(1);
    expect(issues[0]?.message.startsWith('policy.d/30-x.toml: ')).toBe(true);
  });
});

describe('lintEffectiveDialect: names the file an issue came from, when known', () => {
  const dialectViolation: EffectiveRule = {
    family: 'command.bash',
    rule: { id: 'bad-lookahead', regex: 'foo(?=bar)', reason: 'test' },
    provenance: 'overlay',
    sourceFile: 'policy.d/30-x.toml',
  };

  test('an overlay-sourced rule violating the dialect is prefixed with sourceFile', () => {
    const issues = lintEffectiveDialect([dialectViolation]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.message.startsWith('policy.d/30-x.toml: ')).toBe(true);
  });

  test('a baseline rule (no sourceFile) is NOT prefixed with a stray "undefined: "', () => {
    const baselineViolation: EffectiveRule = {
      family: 'command.bash',
      rule: { id: 'bad-lookahead', regex: 'foo(?=bar)', reason: 'test' },
      provenance: 'baseline',
    };
    const issues = lintEffectiveDialect([baselineViolation]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.message.startsWith('undefined')).toBe(false);
    expect(issues[0]?.message.startsWith('command.bash rule')).toBe(true);
  });
});
