// Executes every fixture in fixtures/*.json against the REAL adapter
// dispatch (src/adapter/dispatch.ts) — the same code path the compiled
// binary runs. This is the conformance contract's own proof of life: if
// this file is green, the fixtures describe the adapter's actual behavior,
// not aspirational behavior. tests/fixtures-mutation.test.ts proves the
// converse at the engine layer — that a broken rule makes the fixture
// tied to it red.

import { describe, expect, test } from 'bun:test';
import { evaluateCase, type FixtureFile, listFixtureFiles, loadFixtureFile } from './fixture-runner.ts';

const KNOWN_EVENTS = new Set(['PreToolUse', 'UserPromptSubmit']);

describe('fixtures: the adapter matches its conformance contract', () => {
  for (const filename of listFixtureFiles()) {
    const file: FixtureFile = loadFixtureFile(filename);

    describe(`${file.family} (${filename})`, () => {
      test('the file is non-empty', () => {
        expect(file.cases.length).toBeGreaterThan(0);
      });

      // The fixture tuple is "(event, tool name, tool input | prompt) ->
      // verdict" — `event` is part of the contract, not decoration: it is
      // what tells this runner (and any non-TS one) whether a case is
      // PreToolUse-shaped (toolName/toolInput) or UserPromptSubmit-shaped
      // (prompt).
      test('event names a known hook event', () => {
        expect(KNOWN_EVENTS.has(file.event)).toBe(true);
      });

      for (const fixtureCase of file.cases) {
        test(fixtureCase.id, async () => {
          const actual = await evaluateCase(file, fixtureCase);
          expect(actual).toEqual([...fixtureCase.expected]);
        });

        if (fixtureCase.knownLimit) {
          test(`${fixtureCase.id}: knownLimit carries a non-empty reason`, () => {
            expect(fixtureCase.knownLimitReason?.trim()).toBeTruthy();
          });
        }
      }
    });
  }
});
