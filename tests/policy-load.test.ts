// The policy-loading seam: baseline + overlay merge, override application
// (and its lint failures), fail-closed fallback on a malformed overlay, and
// RE2-dialect rejection. Written before src/policy/load.ts (TDD) — every
// case here names an observed behavior at the load boundary, not internal
// structure.

import { describe, expect, test } from 'bun:test';
import { loadPolicyFromOverlayText } from '../src/policy/load.ts';

describe('loadPolicyFromOverlayText: no overlay', () => {
  test('null overlay text is the baseline alone, silently (no warnings)', () => {
    const result = loadPolicyFromOverlayText(null);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(false);
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });
});

describe('loadPolicyFromOverlayText: additive merge', () => {
  test('a valid overlay adds a new command.bash rule alongside the baseline', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "custom-block"
      regex = "\\\\bforbidden-tool\\\\b"
      reason = "blocked by local policy"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    const ids = result.policy.command.bash.map((r) => r.id);
    expect(ids).toContain('custom-block');
    // Additive, not replacing: the baseline's own rules are still present.
    expect(ids).toContain('mkfs');
  });

  test('a direct rules.command.git.safe_subcommands addition is rejected (must go through [[relax]])', () => {
    // Round-3 review, blocking item 4: a plain overlay addition to a pure
    // allowlist can ONLY relax security, so it must carry a reason —
    // which the [rules] table form has nowhere to put. Probed exploit
    // this closes: a 2-line overlay silently allowlisting `git push`.
    const overlay = `
      [rules.command.git]
      safe_subcommands = ["my-custom-readonly-subcommand"]
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('[[relax]]');
    expect(result.policy.command.git.safe_subcommands).not.toContain('my-custom-readonly-subcommand');
  });
});

describe('loadPolicyFromOverlayText: [[relax]] — the only sanctioned way to widen an allowlist', () => {
  test('a [[relax]] entry with a reason extends safe_subcommands and is reported as an active relaxation', () => {
    const overlay = `
      [[relax]]
      list = "command.git.safe_subcommands"
      value = "my-custom-readonly-subcommand"
      reason = "our CI treats this alias as read-only"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    expect(result.policy.command.git.safe_subcommands).toContain('status'); // baseline
    expect(result.policy.command.git.safe_subcommands).toContain('my-custom-readonly-subcommand');
    expect(result.activeRelaxations).toHaveLength(1);
    expect(result.activeRelaxations[0]).toEqual({
      list: 'command.git.safe_subcommands',
      value: 'my-custom-readonly-subcommand',
      reason: 'our CI treats this alias as read-only',
      sourceFile: 'policy.toml',
    });
  });

  test('a [[relax]] entry with an empty reason fails lint — baseline stays active', () => {
    const overlay = `
      [[relax]]
      list = "command.git.safe_subcommands"
      value = "push"
      reason = ""
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('reason');
    expect(result.policy.command.git.safe_subcommands).not.toContain('push');
  });

  test('a [[relax]] entry naming an unknown list fails lint', () => {
    const overlay = `
      [[relax]]
      list = "command.git.something_else"
      value = "push"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
  });

  test('a direct rules.mcp_write.read_prefixes addition is rejected the same way', () => {
    const overlay = `
      [rules.mcp_write]
      read_prefixes = ["create"]
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('[[relax]]');
  });

  test('a [[relax]] entry widens mcp_write.read_prefixes with a reason', () => {
    const overlay = `
      [[relax]]
      list = "mcp_write.read_prefixes"
      value = "create"
      reason = "our internal MCP server's createFoo is idempotent and read-like"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.policy.mcp_write.read_prefixes).toContain('create');
  });
});

describe('loadPolicyFromOverlayText: a git-conditional entry substituting an already-governed subcommand', () => {
  test('overriding baseline-governed "branch" ask_flags without a reason fails lint', () => {
    // "branch" already has a baseline ask_flags entry — an overlay entry
    // for the same `sub` wins the merge (overlay searched first) and is
    // therefore a substitution, not a fresh addition: it can only relax
    // branch's behavior, so it needs a reason the same way [[relax]] does.
    const overlay = `
      [[rules.command.git.ask_flags]]
      sub = "branch"
      flags = []
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('reason');
  });

  test('overriding baseline-governed "branch" ask_flags WITH a reason succeeds and is an active relaxation', () => {
    const overlay = `
      [[rules.command.git.ask_flags]]
      sub = "branch"
      flags = []
      reason = "our workflow never deletes/renames branches from an agent session"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    expect(result.activeRelaxations).toContainEqual({
      list: 'command.git.ask_flags',
      value: 'branch',
      reason: 'our workflow never deletes/renames branches from an agent session',
      sourceFile: 'policy.toml',
    });
  });

  test('a declarative entry for a genuinely NEW subcommand needs no reason', () => {
    // Nested array literal spaced out ([ [...] ], not [[...]]) — Bun's TOML
    // parser mis-parses a bare leading "[[" as an array-of-tables header
    // even mid-value; policy/command.toml's own safe_grammar entries hit
    // the same constraint and avoid it by putting the outer bracket on its
    // own line (see command.toml's pull/merge/apply entries).
    const overlay = `
      [[rules.command.git.safe_grammar]]
      sub = "rebase"
      sequences = [ ["--continue"] ]
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    expect(result.activeRelaxations).toEqual([]);
  });
});

describe('loadPolicyFromOverlayText: the declarative overlay forms are shape-validated (round-3 review, blocking item 1)', () => {
  test('an ask_flags entry missing "flags" fails lint instead of throwing at match time', () => {
    const overlay = `
      [[rules.command.git.ask_flags]]
      sub = "push"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('flags');
  });

  test('a safe_first_arg entry missing "safe_when_absent" fails lint', () => {
    const overlay = `
      [[rules.command.git.safe_first_arg]]
      sub = "worktree"
      values = ["list"]
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('safe_when_absent');
  });

  test('a safe_grammar entry whose sequences are not arrays of strings fails lint', () => {
    const overlay = `
      [[rules.command.git.safe_grammar]]
      sub = "worktree"
      sequences = [ [1, 2] ]
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
  });
});

describe('loadPolicyFromOverlayText: the lint pass actually compiles every regex (round-3 review, blocking item 1)', () => {
  test('an overlay rule with an unclosed group is rejected — baseline stays active, the hook still responds', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "bad-regex"
      regex = "([a-z"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    // Never fail-open: the baseline's own rules are still fully active.
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });

  test('an overlay rule with flags="g" is rejected (mutable lastIndex on a reused RegExp)', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "global-flag-rule"
      regex = "forbidden"
      flags = "g"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('flag');
  });

  test('an overlay rule with flags="y" (sticky) is rejected the same way', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "sticky-flag-rule"
      regex = "forbidden"
      flags = "y"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
  });

  test('i/m/s flags are still accepted', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "case-insensitive-rule"
      regex = "forbidden-tool"
      flags = "ims"
      reason = "test"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
  });
});

describe('loadPolicyFromOverlayText: [[override]] application', () => {
  test('action "disable" removes the rule from the effective set', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
      reason = "our CI legitimately uploads via curl in every build"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    const ids = result.policy.command.bash.map((r) => r.id);
    expect(ids).not.toContain('curl-file-upload');
  });

  test('action "replace" swaps the rule\'s regex', () => {
    const overlay = `
      [[override]]
      rule = "mkfs"
      action = "replace"
      regex = "\\\\bmkfs\\\\.ext4\\\\b"
      reason = "narrowed to ext4 only — other filesystems are fine in our sandbox"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    const rule = result.policy.command.bash.find((r) => r.id === 'mkfs');
    expect(rule?.regex).toBe('\\bmkfs\\.ext4\\b');
  });

  test('action "relax" changes the rule\'s verdict kind', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "relax"
      verdict = "confirm"
      reason = "we want a prompt, not a hard stop, for this one"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    // `verdict_override` lives on the compiled/effective layer
    // (src/policy/match.ts's CompiledRule), not on RulesPolicy's
    // RegexRule[] — the relaxation is asserted through effectiveRules,
    // where the properly-typed provenance/overrideAction/overrideReason
    // fields already say the same thing.
    const effective = result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload');
    expect(effective?.provenance).toBe('override');
    expect(effective?.overrideAction).toBe('relax');
  });

  test('an active override is reported with its provenance and reason', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
      reason = "our CI legitimately uploads via curl in every build"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.activeOverrides).toHaveLength(1);
    expect(result.activeOverrides[0]).toMatchObject({
      rule: 'curl-file-upload',
      action: 'disable',
      reason: 'our CI legitimately uploads via curl in every build',
    });
  });

  test('secret.bash\'s two former same-id entries now disable independently (round-3 review, standards item 7)', () => {
    // Before the id-suffixing fix, both secret.bash entries shared the id
    // "bash-git-leak" — a `disable` override on that id silently took out
    // BOTH, including the one marked `special = "git_remote_url"`. They
    // are now bash-git-leak-credential / bash-git-leak-remote-url: this
    // proves disabling one leaves the other fully active.
    const overlay = `
      [[override]]
      rule = "bash-git-leak-credential"
      action = "disable"
      reason = "test: only the credential entry should go"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    const ids = result.policy.secret.bash.map((r) => r.id);
    expect(ids).not.toContain('bash-git-leak-credential');
    expect(ids).toContain('bash-git-leak-remote-url');
  });
});

describe('loadPolicyFromOverlayText: [[override]] action is a closed enum (round-3 review, blocking item 2)', () => {
  test('an unknown action fails lint instead of silently behaving like "relax"', () => {
    const overlay = `
      [[override]]
      rule = "mkfs"
      action = "nuke"
      reason = "typo for disable"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('nuke');
    // Not silently disabled either — the rejected overlay means baseline,
    // untouched, is what is actually active.
    expect(result.policy.command.bash.map((r) => r.id)).toContain('mkfs');
  });

  test('action "relax" with an unknown verdict fails lint', () => {
    const overlay = `
      [[override]]
      rule = "mkfs"
      action = "relax"
      verdict = "explode"
      reason = "typo"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
  });
});

describe('loadPolicyFromOverlayText: an override-injected regex passes the same RE2 dialect (round-3 review, blocking item 2)', () => {
  test('action "replace" with a lookahead regex is rejected — baseline stays active', () => {
    const overlay = `
      [[override]]
      rule = "mkfs"
      action = "replace"
      regex = "mkfs(?=\\\\.ext4)"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    // Never fail-open: baseline's own (unreplaced) mkfs rule still active.
    const rule = result.policy.command.bash.find((r) => r.id === 'mkfs');
    expect(rule?.regex).toBe('\\bmkfs(\\.\\w+)?\\b');
  });

  test('action "replace" with an unclosed group is rejected', () => {
    const overlay = `
      [[override]]
      rule = "mkfs"
      action = "replace"
      regex = "([a-z"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
  });
});

describe('loadPolicyFromOverlayText: override lint failures fall back to baseline', () => {
  test('an override with an empty reason fails lint — baseline stays active, loud warning', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
      reason = ""
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings.join(' ')).toContain('reason');
    // The baseline rule the (rejected) override tried to disable is still active.
    expect(result.policy.command.bash.map((r) => r.id)).toContain('curl-file-upload');
  });

  test('an override with no reason field at all fails lint the same way', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  test('an override whose rule id does not resolve fails lint — baseline stays active', () => {
    const overlay = `
      [[override]]
      rule = "this-rule-id-does-not-exist-anywhere"
      action = "disable"
      reason = "a perfectly good reason"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('this-rule-id-does-not-exist-anywhere');
  });
});

describe('loadPolicyFromOverlayText: RE2 dialect rejection', () => {
  test('an overlay rule using a lookahead assertion fails lint — baseline stays active', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "lookahead-rule"
      regex = "foo(?=bar)"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.policy.command.bash.map((r) => r.id)).not.toContain('lookahead-rule');
  });

  test('an overlay rule using a backreference fails lint — baseline stays active', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "backref-rule"
      regex = "(foo)\\\\1"
      reason = "should never load"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
  });
});

describe('loadPolicyFromOverlayText: fail-closed fallback on a malformed overlay', () => {
  test('invalid TOML syntax falls back to the embedded baseline with a loud warning', () => {
    const result = loadPolicyFromOverlayText('this is [not valid toml {{{');
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    // Never fail-open: the baseline's own rules are still fully active.
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
    expect(result.policy.command.bash.map((r) => r.id)).toContain('mkfs');
  });

  test('a rule table with the wrong shape (a string instead of an array) falls back to baseline', () => {
    const result = loadPolicyFromOverlayText('[rules.command]\nbash = "not an array"\n');
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });
});

describe('loadPolicyFromOverlayText: an overlay with no [rules] table is a valid, override-only overlay', () => {
  test('an overlay with only [[override]] and no [rules] table applies the override', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
      reason = "our CI legitimately uploads via curl in every build"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.bash.map((r) => r.id)).not.toContain('curl-file-upload');
  });

  test('a genuinely empty overlay (comments only) is a silent no-op, same as no overlay', () => {
    const result = loadPolicyFromOverlayText('# nothing to see here\n');
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.bash.length).toBeGreaterThan(0);
  });
});

describe('loadPolicyFromOverlayText: effectiveRules carries provenance for `rules list`', () => {
  test('every baseline rule is listed with provenance "baseline"', () => {
    const result = loadPolicyFromOverlayText(null);
    const curl = result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload');
    expect(curl?.provenance).toBe('baseline');
  });

  test('an overlay-added rule is listed with provenance "overlay"', () => {
    const overlay = `
      [[rules.command.bash]]
      id = "custom-block"
      regex = "\\\\bforbidden-tool\\\\b"
      reason = "blocked by local policy"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    const custom = result.effectiveRules.find((r) => r.rule.id === 'custom-block');
    expect(custom?.provenance).toBe('overlay');
  });

  test('an overridden (relaxed) rule is listed with provenance "override" and its reason', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "relax"
      verdict = "confirm"
      reason = "we want a prompt, not a hard stop, for this one"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    const curl = result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload');
    expect(curl?.provenance).toBe('override');
    expect(curl?.overrideReason).toBe('we want a prompt, not a hard stop, for this one');
  });

  test('a disabled rule does not appear in effectiveRules at all', () => {
    const overlay = `
      [[override]]
      rule = "curl-file-upload"
      action = "disable"
      reason = "our CI legitimately uploads via curl in every build"
    `;
    const result = loadPolicyFromOverlayText(overlay);
    expect(result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload')).toBeUndefined();
  });
});
