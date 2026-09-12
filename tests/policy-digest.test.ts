import { describe, expect, test } from 'bun:test';
import { BASELINE } from '../src/policy/baseline.ts';
import { policyDigest } from '../src/policy/digest.ts';
import type { ActiveOverride, ActiveRelaxation } from '../src/policy/load.ts';

const ACTIVE_OVERRIDE: ActiveOverride = {
  rule: 'curl-file-upload',
  action: 'disable',
  reason: 'Allowed in the deployment pipeline',
  sourceFile: 'profile:policy.toml',
};
const ACTIVE_RELAXATION: ActiveRelaxation = {
  list: 'command.git.safe_subcommands',
  value: 'push',
  reason: 'Allow the release branch',
  sourceFile: 'profile:policy.toml',
};

describe('policyDigest', () => {
  test('ignores a rule reason but changes when the rule regex changes', () => {
    const baseline = policyDigest(BASELINE.rules, [], []);
    const firstRule = BASELINE.rules.command.bash[0]!;

    const withChangedReason = {
      ...BASELINE.rules,
      command: {
        ...BASELINE.rules.command,
        bash: [{ ...firstRule, reason: 'A different explanation for the same behavior' }, ...BASELINE.rules.command.bash.slice(1)],
      },
    };
    const withChangedRegex = {
      ...BASELINE.rules,
      command: {
        ...BASELINE.rules.command,
        bash: [{ ...firstRule, regex: `${firstRule.regex}(?:)` }, ...BASELINE.rules.command.bash.slice(1)],
      },
    };

    expect(policyDigest(withChangedReason, [], [])).toBe(baseline);
    expect(policyDigest(withChangedRegex, [], [])).not.toBe(baseline);
  });

  test('hashes active override, relaxation, and harness behavior but not their prose or provenance', () => {
    const baseline = policyDigest(BASELINE.rules, [], []);
    const firstHarness = BASELINE.rules.harness[0]!;
    const withChangedWitness = {
      ...BASELINE.rules,
      harness: [{ ...firstHarness, witness: '~/.another-config' }, ...BASELINE.rules.harness.slice(1)],
    };

    expect(policyDigest(BASELINE.rules, [ACTIVE_OVERRIDE], [])).not.toBe(baseline);
    expect(policyDigest(BASELINE.rules, [], [ACTIVE_RELAXATION])).not.toBe(baseline);
    expect(policyDigest(withChangedWitness, [], [])).not.toBe(baseline);
    expect(policyDigest(BASELINE.rules, [{ ...ACTIVE_OVERRIDE, reason: 'Different prose' }], [])).toBe(
      policyDigest(BASELINE.rules, [ACTIVE_OVERRIDE], []),
    );
    expect(policyDigest(BASELINE.rules, [{ ...ACTIVE_OVERRIDE, sourceFile: 'common:policy.toml' }], [])).toBe(
      policyDigest(BASELINE.rules, [ACTIVE_OVERRIDE], []),
    );
  });
});
