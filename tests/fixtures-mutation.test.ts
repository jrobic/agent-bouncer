// Mutation proof: the fixtures must measure behavior, not just replay it.
// This file calls the real rule functions directly (see tests/real-engine.ts
// for why this operates at the engine layer, not through the full adapter
// dispatch) with a deliberately broken override for one named rule, and
// asserts that the SPECIFIC fixture id tied to that rule goes red — not
// just "something" red, which would also be true of an unrelated bug.
//
// Never mutates the real modules (the guards-digest lock in tests/ watches
// those): each "broken engine" is a hand-rolled function wrapping the real
// one and special-casing exactly the ruleId under test.

import { describe, expect, test } from 'bun:test';
import type { Verdict } from '../src/types.ts';
import { type ExpectedVerdict, type FixtureCase, loadFixtureFile } from './fixture-runner.ts';
import { REAL } from './real-engine.ts';

function toExpected(verdict: Verdict | null): ExpectedVerdict[] {
  return verdict ? [{ verdict: verdict.verdict, ruleId: verdict.ruleId }] : [];
}

function matchesExpected(actual: ExpectedVerdict[], fixtureCase: FixtureCase): boolean {
  return JSON.stringify(actual) === JSON.stringify(fixtureCase.expected);
}

function findCase(filename: string, id: string): FixtureCase {
  const file = loadFixtureFile(filename);
  const found = file.cases.find((c) => c.id === id);
  if (!found) throw new Error(`fixture ${id} not found in ${filename}`);
  return found;
}

// Every mutation below simulates a rule "silently deleted" — always
// returning the all-clear for the one ruleId it targets, as if that rule
// had been dropped from its table or its predicate always answered false.
// Each is scoped to a single ruleId so the "still matches everything else"
// property (implicitly exercised by fixtures.test.ts's own green run)
// stays meaningful.

const bashWithoutRmRfDangerous = (cmd: string): Verdict | null => {
  const real = REAL.checkBash(cmd);
  return real?.ruleId === 'rm-rf-dangerous' ? null : real;
};

const bashWithoutGitPolicy = (cmd: string): Verdict | null => {
  const real = REAL.checkBash(cmd);
  return real?.ruleId === 'git-protected' ? null : real;
};

const checkPathWithoutDotenv = (path: string): Verdict | null => {
  const real = REAL.checkPath(path);
  return real?.ruleId === 'dotenv' ? null : real;
};

const checkMcpWriteAlwaysAllows = (_toolName: string): Verdict | null => null;

const scanSecretsWithoutJwt = (text: string, target: string): Verdict | null => {
  const real = REAL.scanSecrets(text, target);
  return real?.ruleId === 'jwt' ? null : real;
};

const scanPromptWithoutIgnorePrevious = (prompt: string): Verdict[] =>
  REAL.scanPrompt(prompt).filter((hit) => hit.ruleId !== 'ignore-previous');

describe('fixtures-mutation: the real engine matches the fixture before it is mutated', () => {
  test('command: rm-rf-dangerous-root', () => {
    const kase = findCase('command.json', 'rm-rf-dangerous-root');
    const command = (kase.toolInput as { command: string; }).command;
    expect(matchesExpected(toExpected(REAL.checkBash(command)), kase)).toBe(true);
  });

  test('command: git-push-asks', () => {
    const kase = findCase('command.json', 'git-push-asks');
    const command = (kase.toolInput as { command: string; }).command;
    expect(matchesExpected(toExpected(REAL.checkBash(command)), kase)).toBe(true);
  });

  test('secret: dotenv-blocked', () => {
    const kase = findCase('secret.json', 'dotenv-blocked');
    const path = (kase.toolInput as { file_path: string; }).file_path;
    expect(matchesExpected(toExpected(REAL.checkPath(path)), kase)).toBe(true);
  });

  test('mcp-write: write-asks-any-server', () => {
    const kase = findCase('mcp-write.json', 'write-asks-any-server');
    expect(matchesExpected(toExpected(REAL.checkMcpWrite(kase.toolName!)), kase)).toBe(true);
  });

  test('write-secret: jwt', () => {
    const kase = findCase('write-secret.json', 'jwt');
    const content = (kase.toolInput as { content: string; }).content;
    expect(matchesExpected(toExpected(REAL.scanSecrets(content, 'target')), kase)).toBe(true);
  });

  test('prompt: ignore-previous', () => {
    const kase = findCase('prompt.json', 'ignore-previous');
    const actual = REAL.scanPrompt(kase.prompt!).map((v) => ({ verdict: v.verdict, ruleId: v.ruleId }));
    expect(matchesExpected(actual, kase)).toBe(true);
  });
});

describe('fixtures-mutation: a broken rule fails the fixture that names it', () => {
  test('command: deleting rm-rf-dangerous reddens rm-rf-dangerous-root', () => {
    const kase = findCase('command.json', 'rm-rf-dangerous-root');
    const command = (kase.toolInput as { command: string; }).command;
    const actual = toExpected(bashWithoutRmRfDangerous(command));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('command: deleting the git policy reddens git-push-asks', () => {
    const kase = findCase('command.json', 'git-push-asks');
    const command = (kase.toolInput as { command: string; }).command;
    const actual = toExpected(bashWithoutGitPolicy(command));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('secret: deleting the dotenv path rule reddens dotenv-blocked', () => {
    const kase = findCase('secret.json', 'dotenv-blocked');
    const path = (kase.toolInput as { file_path: string; }).file_path;
    const actual = toExpected(checkPathWithoutDotenv(path));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('mcp-write: a rule that always allows reddens write-asks-any-server', () => {
    const kase = findCase('mcp-write.json', 'write-asks-any-server');
    const actual = toExpected(checkMcpWriteAlwaysAllows(kase.toolName!));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('write-secret: deleting the jwt signature reddens the jwt fixture', () => {
    const kase = findCase('write-secret.json', 'jwt');
    const content = (kase.toolInput as { content: string; }).content;
    const actual = toExpected(scanSecretsWithoutJwt(content, 'target'));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('prompt: deleting the ignore-previous signature reddens the ignore-previous fixture', () => {
    const kase = findCase('prompt.json', 'ignore-previous');
    const actual = scanPromptWithoutIgnorePrevious(kase.prompt!).map((v) => ({
      verdict: v.verdict,
      ruleId: v.ruleId,
    }));
    expect(matchesExpected(actual, kase)).toBe(false);
  });

  test('negative control: an unrelated mutation does not reintroduce a failure on rm-rf-dangerous-root', () => {
    const kase = findCase('command.json', 'rm-rf-dangerous-root');
    const command = (kase.toolInput as { command: string; }).command;
    // checkMcpWriteAlwaysAllows is irrelevant to a Bash rm -rf command — the
    // real checkBash must still match, proving "reddens" is not trivially
    // true for any change, mutation-unrelated included.
    void checkMcpWriteAlwaysAllows;
    const actual = toExpected(REAL.checkBash(command));
    expect(matchesExpected(actual, kase)).toBe(true);
  });
});
