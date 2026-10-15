// fixtures/command.json carries the shared list of command-start forms
// (tests/command-start-forms.ts) replayed on each family: the recorded cases
// must be exactly the ones the list produces, so a form or a family cannot
// change on one side only. tests/fixtures.test.ts judges each case.

import { expect, test } from 'bun:test';
import { COMMAND_START_CASE_PREFIX, commandStartCases } from './command-start-forms.ts';
import { loadFixtureFile } from './fixture-runner.ts';

test('fixtures/command.json records the command-start cases of the shared list, in order', () => {
  const recorded = loadFixtureFile('command.json').cases.filter((fixture) => fixture.id.startsWith(COMMAND_START_CASE_PREFIX));
  expect(recorded, 'rewrite them with `bun tests/command-start-forms.ts`').toEqual(commandStartCases());
});
