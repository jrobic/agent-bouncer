// src/policy/baseline.ts
// merges six family files by shallow spread — a family file contributing a
// STRAY extra key (or the WRONG key entirely) under [rules] would silently
// spread into the merged RulesPolicy with no compile-time signal (the
// Pick<RulesPolicy, 'command'> casts only catch a
// MISSING family — an extra/wrong key sails through the `as unknown as`
// cast unexamined). assertExactlyOneFamily is the runtime guard: each
// family file must contribute EXACTLY its one expected key under [rules],
// or the baseline module throws at import time — the earliest and loudest
// possible failure, since a bad baseline can never be caught by "fall back
// to baseline" the way a bad overlay can.

import { describe, expect, test } from 'bun:test';
import { assertExactlyOneFamily, assertNoUnfilledPlaceholders, assertUniqueRuleIds, BASELINE } from '../src/policy/baseline.ts';
import { lintRegexSource } from '../src/policy/lint.ts';
import type { RulesPolicy } from '../src/policy/schema.ts';

describe('assertExactlyOneFamily', () => {
  test('a family file contributing exactly its one expected key passes through unchanged', () => {
    const data = { rules: { command: { some: 'shape' } } };
    const result = assertExactlyOneFamily(data, 'command', 'policy/command.toml');
    expect(result.rules).toEqual(data.rules as unknown as Pick<RulesPolicy, 'command'>);
  });

  test('a family file with an extra stray key alongside the expected one throws, naming the file', () => {
    const data = { rules: { command: { some: 'shape' }, secret: { leaked: 'in' } } };
    expect(() => assertExactlyOneFamily(data, 'command', 'policy/command.toml')).toThrow(/policy\/command\.toml/);
  });

  test('a family file contributing the WRONG key entirely throws, naming the file', () => {
    const data = { rules: { secret: { wrong: 'family' } } };
    expect(() => assertExactlyOneFamily(data, 'command', 'policy/command.toml')).toThrow(/policy\/command\.toml/);
  });

  test('a family file with no [rules] table at all throws, naming the file', () => {
    expect(() => assertExactlyOneFamily({}, 'command', 'policy/command.toml')).toThrow(/policy\/command\.toml/);
  });

  test('a family file whose [rules] table is empty throws, naming the file', () => {
    expect(() => assertExactlyOneFamily({ rules: {} }, 'command', 'policy/command.toml')).toThrow(/policy\/command\.toml/);
  });
});

describe('assertUniqueRuleIds', () => {
  test('rejects a manual baseline collision with harness-global-config', () => {
    const rules = {
      ...BASELINE.rules,
      protected_write: [
        ...BASELINE.rules.protected_write,
        {
          id: 'harness-global-config',
          regex: 'manual-baseline-collision$',
          reason: 'Manual duplicate for the import-time validation test',
        },
      ],
    };
    expect(() => assertUniqueRuleIds(rules)).toThrow(/harness-global-config.*globally unique/);
  });
});

describe('the real baseline module (six actual TOML files) satisfies the assertion', () => {
  test('BASELINE still loads — importing this module proves every family file passed', () => {
    // If any real policy/*.toml family file contributed a stray or wrong key,
    // importing baseline.ts (which every other test file also
    // does, transitively) would already have thrown before this test ever
    // ran. This assertion is a documented tripwire, not the real check.
    expect(BASELINE.rules.command.bash.length).toBeGreaterThan(0);
    expect(BASELINE.rules.secret.path.length).toBeGreaterThan(0);
    expect(BASELINE.rules.mcp_write.read_prefixes.length).toBeGreaterThan(0);
    expect(BASELINE.rules.write_secret.length).toBeGreaterThan(0);
    expect(BASELINE.rules.prompt.length).toBeGreaterThan(0);
    expect(BASELINE.rules.protected_write.length).toBeGreaterThan(0);
  });
});

// Shared regex fragments (src/policy/fragments.ts): a baseline row may spell
// `{{name}}`, filled in once at load. A placeholder that survives the fill is
// a typo that would silently disable its rule, so the baseline module refuses
// to load; and an overlay row — which is never filled — is rejected by lint.
describe('assertNoUnfilledPlaceholders', () => {
  const withSecretBash = (regex: string, except?: string): RulesPolicy => ({
    ...BASELINE.rules,
    secret: { ...BASELINE.rules.secret, bash: [{ id: 'probe', regex, reason: 'probe', ...(except === undefined ? {} : { except }) }] },
  });

  test('the effective baseline carries no {{…}} in any regex or except of any table', () => {
    expect(() => assertNoUnfilledPlaceholders(BASELINE.rules)).not.toThrow();
  });

  test('a regex that still spells a {{name}} throws, naming the rule', () => {
    expect(() => assertNoUnfilledPlaceholders(withSecretBash('a{{not-a-fragment}}b'))).toThrow(/probe.*placeholder/);
  });

  test('an except that still spells a {{name}} throws too', () => {
    expect(() => assertNoUnfilledPlaceholders(withSecretBash('a', '{{protected_name}}'))).toThrow(/probe.*placeholder/);
  });

  test('a placeholder in another table is caught as well', () => {
    const rules = {
      ...BASELINE.rules,
      command: {
        ...BASELINE.rules.command,
        bash: [{ id: 'probe-command', regex: 'x{{oops}}', reason: 'probe' }],
      },
    };
    expect(() => assertNoUnfilledPlaceholders(rules)).toThrow(/probe-command.*placeholder/);
  });
});

describe('lintRegexSource: placeholders belong to the baseline', () => {
  test('{{protected-name}} in an overlay regex is rejected with a message that says why', () => {
    const issues = lintRegexSource('\\$\\{?{{protected-name}}\\b');
    expect(issues).toHaveLength(1);
    expect(issues[0]?.message).toContain('placeholder');
    expect(issues[0]?.message).toContain('baseline');
  });

  test('any {{…}} is refused, known fragment or not', () => {
    expect(lintRegexSource('a{{whatever}}b')).toHaveLength(1);
  });

  test('escaped braces are literal text, not a placeholder', () => {
    expect(lintRegexSource('\\{\\{.Config\\}\\}')).toEqual([]);
  });
});
