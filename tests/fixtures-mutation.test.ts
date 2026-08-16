// Mutation proof: the fixtures must measure behavior, not just replay it.
// This file injects a deliberately broken engine into the same runner
// fixtures.test.ts uses against the real one, and asserts that the SPECIFIC
// fixture id tied to the mutated rule goes red — not just "something" red,
// which would also be true of a runner bug unrelated to the rule itself.
//
// Never mutates the real modules (the guards-digest lock in tests/ watches
// those): each "broken engine" is a hand-rolled function substituted at the
// Engine-interface boundary the runner already accepts for exactly this
// purpose.

import { describe, expect, test } from 'bun:test';
import type { Deny } from '../src/types.ts';
import type { InjectionHit } from '../src/prompt-rules.ts';
import {
  type Engine,
  type FixtureFile,
  listFixtureFiles,
  loadFixtureFile,
  runFixtureFile,
} from './fixture-runner.ts';
import { REAL_ENGINE } from './real-engine.ts';

function brokenEngine(overrides: Partial<Engine>): Engine {
  return { ...REAL_ENGINE, ...overrides };
}

// The single implementation of "which fixtures failed" — reuses
// runFixtureFile's own pass/fail computation instead of re-deriving it, so
// there is exactly one place that decides what counts as a match.
function failingIds(engine: Engine, file: FixtureFile): string[] {
  return runFixtureFile(engine, file)
    .filter((result) => !result.pass)
    .map((result) => result.case.id);
}

// Every mutation below simulates a rule "silently deleted" or "silently
// narrowed" — always returning the all-clear for the one ruleId it targets,
// as if that rule had been dropped from its table or its predicate always
// answered false. Each is scoped to a single ruleId so the corresponding
// baseline-zero-failures assertion stays meaningful: a mutation broad enough
// to touch everything would prove nothing about THAT rule specifically.

const bashWithoutRmRfDangerous = (cmd: string): Deny | null => {
  const real = REAL_ENGINE.checkBash(cmd);
  return real?.ruleId === 'rm-rf-dangerous' ? null : real;
};

const bashWithoutGitPolicy = (cmd: string): Deny | null => {
  const real = REAL_ENGINE.checkBash(cmd);
  return real?.ruleId === 'git-protected' ? null : real;
};

const checkPathWithoutDotenv = (path: string): Deny | null => {
  const real = REAL_ENGINE.checkPath(path);
  return real?.ruleId === 'dotenv' ? null : real;
};

const checkMcpWriteAlwaysAllows = (_toolName: string): Deny | null => null;

const scanSecretsWithoutJwt = (text: string, target: string): Deny | null => {
  const real = REAL_ENGINE.scanSecrets(text, target);
  return real?.ruleId === 'jwt' ? null : real;
};

const scanPromptWithoutIgnorePrevious = (prompt: string): readonly InjectionHit[] =>
  REAL_ENGINE.scanPrompt(prompt).filter((hit) => hit.ruleId !== 'ignore-previous');

describe('fixtures-mutation: the real engine has zero failures on every family (baseline)', () => {
  for (const filename of listFixtureFiles()) {
    test(filename, () => {
      expect(failingIds(REAL_ENGINE, loadFixtureFile(filename))).toEqual([]);
    });
  }
});

describe('fixtures-mutation: a broken rule fails the fixture that names it', () => {
  test('command: deleting rm-rf-dangerous reddens rm-rf-dangerous-root', () => {
    const file = loadFixtureFile('command.json');
    const engine = brokenEngine({ checkBash: bashWithoutRmRfDangerous });
    expect(failingIds(engine, file)).toContain('rm-rf-dangerous-root');
  });

  test('command: deleting the git policy reddens git-push-asks', () => {
    const file = loadFixtureFile('command.json');
    const engine = brokenEngine({ checkBash: bashWithoutGitPolicy });
    expect(failingIds(engine, file)).toContain('git-push-asks');
  });

  test('secret: deleting the dotenv path rule reddens dotenv-blocked', () => {
    const file = loadFixtureFile('secret.json');
    const engine = brokenEngine({ checkPath: checkPathWithoutDotenv });
    expect(failingIds(engine, file)).toContain('dotenv-blocked');
  });

  test('mcp-write: a rule that always allows reddens write-asks-any-server', () => {
    const file = loadFixtureFile('mcp-write.json');
    const engine = brokenEngine({ checkMcpWrite: checkMcpWriteAlwaysAllows });
    expect(failingIds(engine, file)).toContain('write-asks-any-server');
  });

  test('write-secret: deleting the jwt signature reddens the jwt fixture', () => {
    const file = loadFixtureFile('write-secret.json');
    const engine = brokenEngine({ scanSecrets: scanSecretsWithoutJwt });
    expect(failingIds(engine, file)).toContain('jwt');
  });

  test('prompt: deleting the ignore-previous signature reddens the ignore-previous fixture', () => {
    const file = loadFixtureFile('prompt.json');
    const engine = brokenEngine({ scanPrompt: scanPromptWithoutIgnorePrevious });
    expect(failingIds(engine, file)).toContain('ignore-previous');
  });

  test('negative control: an unrelated mutation does not reintroduce failures the baseline did not have', () => {
    // A mutation to a rule the file happens not to exercise must not change
    // which fixtures fail — otherwise "reddens" would be trivially true for
    // any change, mutation-unrelated included.
    const file = loadFixtureFile('command.json');
    const engine = brokenEngine({ checkMcpWrite: checkMcpWriteAlwaysAllows });
    expect(failingIds(engine, file)).toEqual([]);
  });
});
