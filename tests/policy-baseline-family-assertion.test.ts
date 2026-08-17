// Ticket 13, decision carried from ticket 12's review: src/policy/baseline.ts
// merges five family files by shallow spread — until now, a family file
// contributing a STRAY extra key (or the WRONG key entirely) under [rules]
// would silently spread into the merged RulesPolicy with no compile-time
// signal (the Pick<RulesPolicy, 'command'> casts, ticket 12, only catch a
// MISSING family — an extra/wrong key sails through the `as unknown as`
// cast unexamined). assertExactlyOneFamily is the runtime guard: each
// family file must contribute EXACTLY its one expected key under [rules],
// or the baseline module throws at import time — the earliest and loudest
// possible failure, since a bad baseline can never be caught by "fall back
// to baseline" the way a bad overlay can.

import { describe, expect, test } from 'bun:test';
import { assertExactlyOneFamily, BASELINE } from '../src/policy/baseline.ts';
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

describe('the real baseline module (five actual TOML files) satisfies the assertion', () => {
  test('BASELINE still loads — importing this module at all proves every real family file passed', () => {
    // If any of the five real policy/*.toml files contributed a stray or
    // wrong key, importing baseline.ts (which every other test file also
    // does, transitively) would already have thrown before this test ever
    // ran. This assertion is a documented tripwire, not the real check.
    expect(BASELINE.rules.command.bash.length).toBeGreaterThan(0);
    expect(BASELINE.rules.secret.path.length).toBeGreaterThan(0);
    expect(BASELINE.rules.mcp_write.read_prefixes.length).toBeGreaterThan(0);
    expect(BASELINE.rules.write_secret.length).toBeGreaterThan(0);
    expect(BASELINE.rules.prompt.length).toBeGreaterThan(0);
  });
});
