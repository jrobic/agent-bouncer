// Executes every fixture in fixtures/*.json against the real engine. This
// is the conformance contract's own proof of life: if this file is green,
// the fixtures describe the engine's actual behavior, not aspirational
// behavior. fixtures-mutation.test.ts proves the converse — that a broken
// engine makes it red.

import { describe, expect, test } from 'bun:test';
import { evaluateCase, type FixtureFile, listFixtureFiles, loadFixtureFile } from './fixture-runner.ts';
import { REAL_ENGINE } from './real-engine.ts';

const KNOWN_EVENTS = new Set(['PreToolUse', 'UserPromptSubmit']);

describe('fixtures: the engine matches its conformance contract', () => {
  for (const filename of listFixtureFiles()) {
    const file: FixtureFile = loadFixtureFile(filename);

    describe(`${file.family} (${filename})`, () => {
      test('the file is non-empty', () => {
        expect(file.cases.length).toBeGreaterThan(0);
      });

      // The fixture tuple is "(event, tool name, tool input | command
      // string) -> verdict" — `event` is part of the contract, not decoration.
      // A future adapter needs it to know which hook this family binds to,
      // so it must actually be one of the harness event names, not an empty
      // or made-up string.
      test('event names a known hook event', () => {
        expect(KNOWN_EVENTS.has(file.event)).toBe(true);
      });

      for (const fixtureCase of file.cases) {
        test(fixtureCase.id, () => {
          const actual = evaluateCase(REAL_ENGINE, file, fixtureCase);
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
