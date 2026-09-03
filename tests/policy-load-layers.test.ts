// The named-layers engine seam (ticket 20, ADR-0001): loadPolicyFromLayers
// receives layers in PRECEDENCE order (later wins) and owns cross-layer
// precedence, provenance, and (still collective — ticket 21 makes it
// per-layer) rejection. Every case here names an observed property at
// that boundary, not internal structure — complements
// tests/policy-load-multifile.test.ts (the single, unnamed-layer seam,
// unchanged by this ticket).

import { describe, expect, test } from 'bun:test';
import { loadPolicyFromLayers, type NamedLayer, type OverlayFile } from '../src/policy/load.ts';

function file(filename: string, text: string): OverlayFile {
  return { filename, text };
}

function layer(name: string, files: readonly OverlayFile[]): NamedLayer {
  return { name, files };
}

describe('loadPolicyFromLayers: no files anywhere', () => {
  test('every layer empty is the baseline alone, silently, with per-layer zero counts', () => {
    const result = loadPolicyFromLayers([layer('common', []), layer('profile', [])]);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(false);
    expect(result.layers).toEqual([{ name: 'common', files: [] }, { name: 'profile', files: [] }]);
  });
});

describe('loadPolicyFromLayers: mono-layer case matches loadPolicyFromOverlayFiles additive behavior', () => {
  test('a single named layer merges additively onto the baseline, filenames qualified by layer', () => {
    const result = loadPolicyFromLayers([
      layer('profile', [
        file('policy.toml', '[[rules.command.bash]]\nid = "solo"\nregex = "solo-trigger"\nreason = "test"\n'),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    const entry = result.effectiveRules.find((r) => r.rule.id === 'solo');
    expect(entry?.sourceFile).toBe('profile:policy.toml');
    expect(entry?.shadows).toBeUndefined();
  });
});

describe('loadPolicyFromLayers: common-only — the profile layer empty runs on the common layer alone', () => {
  test('a relax in the common layer is active even though the profile layer contributes nothing', () => {
    const result = loadPolicyFromLayers([
      layer('common', [file('policy.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "common-wide"\n')]),
      layer('profile', []),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.git.safe_subcommands).toContain('push');
    expect(result.activeRelaxations).toHaveLength(1);
    expect(result.activeRelaxations[0]?.sourceFile).toBe('common:policy.toml');
    expect(result.layers).toEqual([{ name: 'common', files: ['policy.toml'] }, { name: 'profile', files: [] }]);
  });
});

describe('loadPolicyFromLayers: common absent is a normal, passing state', () => {
  test('an absent common layer (zero files) with an active profile is a pass, common file count is 0', () => {
    const result = loadPolicyFromLayers([
      layer('common', []),
      layer('profile', [file('policy.toml', '[[rules.command.bash]]\nid = "profile-only"\nregex = "x"\nreason = "test"\n')]),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    expect(result.layers).toEqual([{ name: 'common', files: [] }, { name: 'profile', files: ['policy.toml'] }]);
  });
});

describe('loadPolicyFromLayers: precedence — the profile wins on all four target kinds', () => {
  test('regex row id: profile shadows the common row, common one is dropped, profile keeps its own position', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file('policy.d/100-common.toml', '[[rules.command.bash]]\nid = "shared-id"\nregex = "common-pattern"\nreason = "common"\n'),
      ]),
      layer('profile', [file('policy.toml', '[[rules.command.bash]]\nid = "shared-id"\nregex = "profile-pattern"\nreason = "profile"\n')]),
    ]);
    expect(result.warnings).toEqual([]);
    const matches = result.effectiveRules.filter((r) => r.rule.id === 'shared-id');
    expect(matches).toHaveLength(1);
    expect(matches[0]?.rule.regex).toBe('profile-pattern');
    expect(matches[0]?.sourceFile).toBe('profile:policy.toml');
    expect(matches[0]?.shadows).toBe('common:policy.d/100-common.toml');
  });

  test('[[override]] rule: the profile override replaces the common one outright, not chained', () => {
    const result = loadPolicyFromLayers([
      layer('common', [file('policy.toml', '[[override]]\nrule = "curl-file-upload"\naction = "disable"\nreason = "common disables"\n')]),
      layer('profile', [
        file(
          'policy.toml',
          '[[override]]\nrule = "curl-file-upload"\naction = "relax"\nverdict = "confirm"\nreason = "profile relaxes instead"\n',
        ),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.activeOverrides).toHaveLength(1);
    expect(result.activeOverrides[0]).toMatchObject({
      rule: 'curl-file-upload',
      action: 'relax',
      sourceFile: 'profile:policy.toml',
      shadows: 'common:policy.toml',
    });
    const rule = result.effectiveRules.find((r) => r.rule.id === 'curl-file-upload');
    expect(rule?.overrideAction).toBe('relax');
  });

  test('[[relax]] list+value: the profile relax shadows the common one, value present exactly once', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file('policy.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "common reason"\n'),
      ]),
      layer('profile', [
        file('policy.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "profile reason"\n'),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.policy.command.git.safe_subcommands.filter((v) => v === 'push')).toHaveLength(1);
    expect(result.activeRelaxations).toHaveLength(1);
    expect(result.activeRelaxations[0]).toMatchObject({
      reason: 'profile reason',
      sourceFile: 'profile:policy.toml',
      shadows: 'common:policy.toml',
    });
  });

  test('git-conditional sub (ask_flags): the profile entry wins the lookup, common entry is gone', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file(
          'policy.toml',
          '[[rules.command.git.ask_flags]]\nsub = "branch"\nflags = ["-f"]\nreason = "common substitution"\n',
        ),
      ]),
      layer('profile', [
        file(
          'policy.toml',
          '[[rules.command.git.ask_flags]]\nsub = "branch"\nflags = ["-D"]\nreason = "profile substitution"\n',
        ),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    const branchRule = result.policy.command.git.ask_flags.find((r) => r.sub === 'branch');
    expect(branchRule?.flags).toEqual(['-D']);
    const relax = result.activeRelaxations.find((r) => r.list === 'command.git.ask_flags');
    expect(relax).toMatchObject({ value: 'branch', reason: 'profile substitution', sourceFile: 'profile:policy.toml' });
    expect(relax?.shadows).toBe('common:policy.toml');
  });

  test('positional: the shadowing profile row sits AFTER every surviving common row, not spliced into the dropped row\'s old slot', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file(
          'policy.toml',
          '[[rules.command.bash]]\nid = "common-only"\nregex = "common-only-trigger"\nreason = "test"\n\n'
            + '[[rules.command.bash]]\nid = "shared-id"\nregex = "common-pattern"\nreason = "common"\n',
        ),
      ]),
      layer('profile', [file('policy.toml', '[[rules.command.bash]]\nid = "shared-id"\nregex = "profile-pattern"\nreason = "profile"\n')]),
    ]);
    expect(result.warnings).toEqual([]);
    const ids = result.policy.command.bash.map((r) => r.id);
    const commonOnlyIndex = ids.indexOf('common-only');
    const sharedIndex = ids.indexOf('shared-id');
    expect(commonOnlyIndex).toBeGreaterThanOrEqual(0);
    // "at its own position (after every common row)" — the profile's
    // winning row is NOT spliced back into common-only's neighboring
    // slot; it sits at the position a normal profile addition would take
    // (after every surviving common row), the same append order every
    // other overlay row uses.
    expect(sharedIndex).toBeGreaterThan(commonOnlyIndex);
  });

  test('mixed kept/shadowed/dropped: precedence survives a family+layer set carrying all three at once (key-based, not object-identity-based)', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file(
          'policy.toml',
          '[[rules.command.bash]]\nid = "common-unique"\nregex = "common-unique-trigger"\nreason = "test"\n\n'
            + '[[rules.command.bash]]\nid = "shadowed-id"\nregex = "common-pattern"\nreason = "common"\n',
        ),
      ]),
      layer('profile', [
        file(
          'policy.toml',
          '[[rules.command.bash]]\nid = "shadowed-id"\nregex = "profile-pattern"\nreason = "profile"\n\n'
            + '[[rules.command.bash]]\nid = "profile-unique"\nregex = "profile-unique-trigger"\nreason = "test"\n',
        ),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    const ids = result.policy.command.bash.map((r) => r.id);
    expect(ids).toContain('common-unique'); // survives untouched (no shared key)
    expect(ids).toContain('profile-unique'); // survives untouched (no shared key)
    expect(ids.filter((id) => id === 'shadowed-id')).toHaveLength(1); // common's dropped, profile's kept
    const shadowed = result.effectiveRules.find((r) => r.rule.id === 'shadowed-id');
    expect(shadowed?.rule.regex).toBe('profile-pattern');
    expect(shadowed?.shadows).toBe('common:policy.toml');
  });
});

describe('loadPolicyFromLayers: two files of the SAME layer sharing a target still reject that layer\'s set', () => {
  test('two profile files overriding the same rule is rejected, common is unaffected by the check', () => {
    const result = loadPolicyFromLayers([
      layer('common', []),
      layer('profile', [
        file('policy.d/10-a.toml', '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = "file A"\n'),
        file('policy.d/20-b.toml', '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = "file B"\n'),
      ]),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('profile:policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('profile:policy.d/20-b.toml');
  });

  test('two common files sharing a regex id is rejected even though the profile layer is clean', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file('policy.d/10-a.toml', '[[rules.command.bash]]\nid = "dup"\nregex = "a"\nreason = "test"\n'),
        file('policy.d/20-b.toml', '[[rules.command.bash]]\nid = "dup"\nregex = "b"\nreason = "test"\n'),
      ]),
      layer('profile', [file('policy.toml', '[[rules.command.bash]]\nid = "fine"\nregex = "fine"\nreason = "test"\n')]),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('common:policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('common:policy.d/20-b.toml');
  });

  test('two profile files [[relax]]ing the same list+value is rejected, common is unaffected by the check', () => {
    const result = loadPolicyFromLayers([
      layer('common', []),
      layer('profile', [
        file('policy.d/10-a.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "file A"\n'),
        file('policy.d/20-b.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "file B"\n'),
      ]),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('command.git.safe_subcommands');
    expect(result.warnings.join(' ')).toContain('profile:policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('profile:policy.d/20-b.toml');
  });

  test('two common files substituting the same governed ask_flags sub is rejected, profile is unaffected', () => {
    const result = loadPolicyFromLayers([
      layer('common', [
        file('policy.d/10-a.toml', '[[rules.command.git.ask_flags]]\nsub = "branch"\nflags = ["-f"]\nreason = "file A"\n'),
        file('policy.d/20-b.toml', '[[rules.command.git.ask_flags]]\nsub = "branch"\nflags = ["-D"]\nreason = "file B"\n'),
      ]),
      layer('profile', []),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('branch');
    expect(result.warnings.join(' ')).toContain('common:policy.d/10-a.toml');
    expect(result.warnings.join(' ')).toContain('common:policy.d/20-b.toml');
  });
});

describe('loadPolicyFromLayers: rejection stays collective across layers (ticket 21 makes it per-layer)', () => {
  test('a broken file in the COMMON layer rejects the profile layer too, baseline alone stays active', () => {
    const result = loadPolicyFromLayers([
      layer('common', [file('policy.toml', 'this is [not valid toml {{{')]),
      layer('profile', [file('policy.toml', '[[rules.command.bash]]\nid = "would-have-worked"\nregex = "x"\nreason = "test"\n')]),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('common:policy.toml');
    expect(result.policy.command.bash.map((r) => r.id)).not.toContain('would-have-worked');
    expect(result.layers).toEqual([{ name: 'common', files: ['policy.toml'] }, { name: 'profile', files: ['policy.toml'] }]);
  });

  test('a broken file in the PROFILE layer rejects the common layer\'s otherwise-valid relax too', () => {
    const result = loadPolicyFromLayers([
      layer('common', [file('policy.toml', '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "test"\n')]),
      layer('profile', [file('policy.toml', 'this is [not valid toml {{{')]),
    ]);
    expect(result.overlayApplied).toBe(false);
    expect(result.warnings.join(' ')).toContain('profile:policy.toml');
    expect(result.policy.command.git.safe_subcommands).not.toContain('push');
  });
});

describe('loadPolicyFromLayers: ticket-19 regression — same target repeated within one file, unaffected', () => {
  test('the same regex id twice within one profile file still chains (existing single-file semantics)', () => {
    const result = loadPolicyFromLayers([
      layer('common', []),
      layer('profile', [
        file(
          'policy.toml',
          '[[rules.command.bash]]\nid = "dup-in-file"\nregex = "first"\nreason = "one"\n\n'
            + '[[rules.command.bash]]\nid = "dup-in-file"\nregex = "second"\nreason = "two"\n',
        ),
      ]),
    ]);
    expect(result.warnings).toEqual([]);
    expect(result.overlayApplied).toBe(true);
    expect(result.effectiveRules.filter((r) => r.rule.id === 'dup-in-file')).toHaveLength(2);
  });
});
