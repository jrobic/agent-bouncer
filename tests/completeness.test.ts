import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, test } from 'bun:test';

import { BASELINE } from '../src/policy/baseline.ts';
import type { RegexRule } from '../src/policy/schema.ts';

// The exhaustiveness lock: for each table, the SET of ruleIds carrying a
// behavioural case must EQUAL the set of effective ruleIds. A rule added
// without a case fails here; a case surviving the rule it exercised fails
// here too, and each is named on the correct side of the diff.
//
// Where the covered ids come from, and what that costs. The tests on this
// side are one `test()` per ruleId, with the id in the title:
// `test("ruleId rm-rf-dangerous: rm -rf / is denied")`. Coverage is read out
// of the titles rather than out of an exported array, which avoids
// restructuring the suite and keeps the convention the files already
// follow.
//
// The cost is stated rather than hidden: a title can lie. A test announcing
// a ruleId it does not exercise counts as covered here. The stronger form
// is to record which rules actually fire during the suite, and it needs a
// collector this file does not have.
//
// `mcp-write-rules` is deliberately absent: its test file does not use the
// title convention (it is coverage-diffed independently, against its own
// READ_VECTORS/WRITE_NEIGHBOURS tables).

const RULES_TESTS = join(import.meta.dirname);

/** The ruleIds a file claims a behavioural case for, read from its test titles. */
function coveredRuleIds(filename: string): Set<string> {
  const source = readFileSync(join(RULES_TESTS, filename), 'utf8');
  // Quote-agnostic on purpose: the suites ported into this repo were
  // rewritten to use single quotes throughout, while the source
  // generation's own tests used double quotes — the convention this lock
  // reads is the "ruleId <id>:" title prefix, not a specific quote char.
  const ids = [...source.matchAll(/\btest\(\s*['"]ruleId ([a-zA-Z0-9._-]+)\s*:/g)].map((m) =>
    m[1]!
  );

  if (ids.length === 0) {
    throw new Error(
      `${filename} yielded no "ruleId <id>:" test title. Either the file stopped using the `
        + `convention this lock reads, or the lock is now measuring nothing — both are defects.`,
    );
  }
  return new Set(ids);
}

function expectRuleIdsToMatch(
  table: string,
  ruleIds: Iterable<string>,
  covered: Set<string>,
): void {
  const rules = new Set(ruleIds);
  const diff = {
    rulesWithoutCases: [...rules].filter((id) => !covered.has(id)).sort(),
    casesWithoutRules: [...covered].filter((id) => !rules.has(id)).sort(),
  };

  expect(diff, `${table}: ruleId mismatch`).toEqual({
    rulesWithoutCases: [],
    casesWithoutRules: [],
  });
}

const ids = (rules: readonly RegexRule[]) => rules.map((r) => r.id);

describe('completeness: every effective rule carries a behavioural case', () => {
  test('command rules', () => {
    // Three ids are decided in code rather than by a table row:
    // `rm-rf-dangerous`, `sudo` (privilege escalation), and `git-protected`
    // (the git policy).
    expectRuleIdsToMatch(
      'command',
      [
        ...ids(BASELINE.rules.command.bash),
        'rm-rf-dangerous',
        'sudo',
        'git-protected',
      ],
      coveredRuleIds('command-rules.test.ts'),
    );
  });

  test('secret rules', () => {
    // secret.path rules carry their bare id here (exercised as path rules
    // directly), not the `bash-` prefix they get when reached through a
    // bash command.
    expectRuleIdsToMatch(
      'secret',
      [
        ...ids(BASELINE.rules.secret.bash),
        ...ids(BASELINE.rules.secret.path),
      ],
      coveredRuleIds('secret-rules.test.ts'),
    );
  });

  test('write-secret rules', () => {
    expectRuleIdsToMatch(
      'write-secret',
      ids(BASELINE.rules.write_secret),
      coveredRuleIds('write-secret-rules.test.ts'),
    );
  });

  test('prompt rules', () => {
    // base64-blob is a plain 7th entry of rules.prompt now (ticket 06 — it
    // used to be a module constant evaluated apart from the table), so no
    // extra id needs to be added on this side.
    expectRuleIdsToMatch(
      'prompt',
      ids(BASELINE.rules.prompt),
      coveredRuleIds('prompt-rules.test.ts'),
    );
  });
});
