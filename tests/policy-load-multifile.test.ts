// The multi-file overlay seam (ticket 12): `policy.toml` plus a
// `policy.d/*.toml` directory, merged in file order — every behavioral
// case here names an observed property at src/policy/load.ts's
// loadPolicyFromOverlayFiles boundary, not internal structure. Written
// before that function exists (TDD). Complements tests/policy-load.test.ts
// (the pre-existing single-file seam, unchanged behavior via
// loadPolicyFromOverlayText, which this ticket keeps as a thin wrapper).

import { describe, expect, test } from 'bun:test';
import { loadPolicyFromOverlayFiles, type OverlayFile } from '../src/policy/load.ts';

function file(filename: string, text: string): OverlayFile {
  return { filename, text };
}

describe('loadPolicyFromOverlayFiles: no files', () => {
  test('an empty file list is the baseline alone, silently (no warnings)', () => {
    const result = loadPolicyFromOverlayFiles([]);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(false);
    expect(result.overlayFiles).toEqual([]);
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });
});

describe('loadPolicyFromOverlayFiles: multiple files merge additively', () => {
  test('a rule added in policy.toml and a rule added in a policy.d file are BOTH active', () => {
    const files = [
      file(
        'policy.toml',
        `
        [[rules.command.bash]]
        id = "from-policy-toml"
        regex = "\\\\bfrom-policy-toml\\\\b"
        reason = "test"
        `,
      ),
      file(
        'policy.d/10-extra.toml',
        `
        [[rules.command.bash]]
        id = "from-policy-d"
        regex = "\\\\bfrom-policy-d\\\\b"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    const ids = result.policy.command.bash.map((r) => r.id);
    expect(ids).toContain('from-policy-toml');
    expect(ids).toContain('from-policy-d');
    expect(result.overlayFiles).toEqual(['policy.toml', 'policy.d/10-extra.toml']);
  });

  test('policy.d files alone (no policy.toml in the set) still merge onto the baseline', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[rules.command.bash]]
        id = "only-in-policy-d"
        regex = "\\\\bonly-in-policy-d\\\\b"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.bash.map((r) => r.id)).toContain('only-in-policy-d');
  });
});

describe('loadPolicyFromOverlayFiles: lexicographic order — an order-dependent case', () => {
  test('two files each add a rule matching the SAME input; the earlier file in merge order wins '
    + '(first match wins, and files are appended in the given order — policy.toml, then policy.d '
    + 'lexicographically)', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[rules.command.bash]]
        id = "rule-from-10-a"
        regex = "shared-trigger"
        reason = "first file, should win"
        `,
      ),
      file(
        'policy.d/20-b.toml',
        `
        [[rules.command.bash]]
        id = "rule-from-20-b"
        regex = "shared-trigger"
        reason = "second file, should be shadowed"
        `,
      ),
    ];
    // Caller passes files in the order they should merge — src/adapter/policy.ts
    // is what actually sorts policy.d filenames lexicographically before
    // building this array; this test proves loadPolicyFromOverlayFiles
    // itself honors whatever order it's given (first match wins).
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    const hit = result.policy.command.bash.find((r) => r.regex === 'shared-trigger');
    expect(hit?.id).toBe('rule-from-10-a');

    // Reversed order flips which one is first — proving the outcome
    // genuinely depends on file order, not on some other tiebreak.
    const reversed = loadPolicyFromOverlayFiles([...files].reverse());
    const reversedHit = reversed.policy.command.bash.find((r) => r.regex === 'shared-trigger');
    expect(reversedHit?.id).toBe('rule-from-20-b');
  });
});

describe('loadPolicyFromOverlayFiles: one broken file rejects the WHOLE set', () => {
  test('a malformed policy.d file rejects policy.toml\'s otherwise-valid content too, naming the broken file', () => {
    const files = [
      file(
        'policy.toml',
        `
        [[rules.command.bash]]
        id = "would-have-worked"
        regex = "would-have-worked"
        reason = "test"
        `,
      ),
      file('policy.d/20-broken.toml', 'this is [not valid toml {{{'),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.overlayFiles).toEqual([]);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings.join(' ')).toContain('policy.d/20-broken.toml');
    // Baseline stays fully active — the "would-have-worked" rule does NOT
    // silently apply just because policy.toml itself was fine.
    expect(result.policy.command.bash.map((r) => r.id)).not.toContain('would-have-worked');
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });

  test('a lint-failing policy.d file (not just a parse error) also rejects the whole set, naming the file', () => {
    const files = [
      file('policy.toml', ''),
      file(
        'policy.d/10-bad-regex.toml',
        `
        [[rules.command.bash]]
        id = "lookahead-rule"
        regex = "foo(?=bar)"
        reason = "should never load"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('policy.d/10-bad-regex.toml');
  });

  test('a broken policy.toml rejects an otherwise-valid policy.d file too', () => {
    const files = [
      file('policy.toml', 'this is [not valid toml {{{'),
      file(
        'policy.d/10-fine.toml',
        `
        [[rules.command.bash]]
        id = "fine-rule"
        regex = "fine-rule"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('policy.toml');
    expect(result.policy.command.bash.map((r) => r.id)).not.toContain('fine-rule');
  });
});

describe('loadPolicyFromOverlayFiles: cross-file [[override]]/[[relax]] conflicts are explicit lint errors', () => {
  test('the SAME rule overridden in two DIFFERENT files is rejected, naming both files', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[override]]
        rule = "curl-file-upload"
        action = "disable"
        reason = "file A's reason"
        `,
      ),
      file(
        'policy.d/20-b.toml',
        `
        [[override]]
        rule = "curl-file-upload"
        action = "disable"
        reason = "file B's reason"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('curl-file-upload');
    expect(result.warnings.join(' ')).toContain('policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('policy.d/20-b.toml');
  });

  test('two DIFFERENT rules overridden across two files is NOT a conflict', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[override]]
        rule = "curl-file-upload"
        action = "disable"
        reason = "test"
        `,
      ),
      file(
        'policy.d/20-b.toml',
        `
        [[override]]
        rule = "mkfs"
        action = "disable"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
  });

  test('the SAME rule overridden TWICE within one file still works (existing chaining behavior, unaffected)', () => {
    const files = [
      file(
        'policy.toml',
        `
        [[override]]
        rule = "curl-file-upload"
        action = "replace"
        regex = "curl-file-upload-narrowed"
        reason = "narrow first"

        [[override]]
        rule = "curl-file-upload"
        action = "relax"
        verdict = "confirm"
        reason = "then relax"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    const rule = result.policy.command.bash.find((r) => r.id === 'curl-file-upload');
    expect(rule?.regex).toBe('curl-file-upload-narrowed');
  });

  test('the SAME [[relax]] list+value in two files is rejected, naming both files', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[relax]]
        list = "command.git.safe_subcommands"
        value = "push"
        reason = "file A"
        `,
      ),
      file(
        'policy.d/20-b.toml',
        `
        [[relax]]
        list = "command.git.safe_subcommands"
        value = "push"
        reason = "file B"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('command.git.safe_subcommands');
    expect(result.warnings.join(' ')).toContain('policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('policy.d/20-b.toml');
  });

  test('the SAME [[relax]] list+value in two files is still caught when value contains a space '
    + '(labelOf reads the raw entry directly — no lossy `${list} ${value}`.split(\' \') re-parse)', () => {
    const files = [
      file('policy.d/10-a.toml', '[[relax]]\nlist = "mcp_write.read_prefixes"\nvalue = "two words"\nreason = "file A"\n'),
      file('policy.d/20-b.toml', '[[relax]]\nlist = "mcp_write.read_prefixes"\nvalue = "two words"\nreason = "file B"\n'),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    // The full value, space included, must survive intact in the message —
    // the old split(' ')-based decode silently truncated it.
    expect(result.warnings.join(' ')).toContain('mcp_write.read_prefixes="two words"');
    expect(result.warnings.join(' ')).toContain('policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('policy.d/20-b.toml');
  });

  test('a [[relax]] on the same list but a DIFFERENT value across two files is not a conflict', () => {
    const files = [
      file('policy.d/10-a.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "test"\n'),
      file('policy.d/20-b.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "rebase"\nreason = "test"\n'),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.git.safe_subcommands).toContain('push');
    expect(result.policy.command.git.safe_subcommands).toContain('rebase');
  });

  test('the same governed `sub` substituted in two declarative-table files is rejected', () => {
    const files = [
      file(
        'policy.d/10-a.toml',
        `
        [[rules.command.git.ask_flags]]
        sub = "branch"
        flags = []
        reason = "file A"
        `,
      ),
      file(
        'policy.d/20-b.toml',
        `
        [[rules.command.git.ask_flags]]
        sub = "branch"
        flags = ["-f"]
        reason = "file B"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('branch');
    expect(result.warnings.join(' ')).toContain('policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('policy.d/20-b.toml');
  });
});

describe('loadPolicyFromOverlayFiles: provenance names the source file', () => {
  test('an overlay-added rule\'s effectiveRules entry carries its sourceFile', () => {
    const files = [
      file(
        'policy.d/10-npm.toml',
        `
        [[rules.command.bash]]
        id = "block-npm-publish"
        regex = "npm publish"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    const entry = result.effectiveRules.find((r) => r.rule.id === 'block-npm-publish');
    expect(entry?.provenance).toBe('overlay');
    expect(entry?.sourceFile).toBe('policy.d/10-npm.toml');
  });

  test('a baseline rule\'s effectiveRules entry has no sourceFile', () => {
    const result = loadPolicyFromOverlayFiles([file('policy.toml', '')]);
    const entry = result.effectiveRules.find((r) => r.rule.id === 'mkfs');
    expect(entry?.provenance).toBe('baseline');
    expect(entry?.sourceFile).toBeUndefined();
  });

  test('an active override carries the file it came from', () => {
    const files = [
      file(
        'policy.d/10-relax.toml',
        `
        [[override]]
        rule = "curl-file-upload"
        action = "disable"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.activeOverrides).toHaveLength(1);
    expect(result.activeOverrides[0]?.sourceFile).toBe('policy.d/10-relax.toml');
    const entry = result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload');
    expect(entry).toBeUndefined(); // disabled — expect no override entry, no rule entry
  });

  test('an active relaxation carries the file it came from', () => {
    const files = [
      file(
        'policy.d/10-relax.toml',
        `
        [[relax]]
        list = "command.git.safe_subcommands"
        value = "push"
        reason = "test"
        `,
      ),
    ];
    const result = loadPolicyFromOverlayFiles(files);
    expect(result.activeRelaxations).toHaveLength(1);
    expect(result.activeRelaxations[0]?.sourceFile).toBe('policy.d/10-relax.toml');
  });
});
