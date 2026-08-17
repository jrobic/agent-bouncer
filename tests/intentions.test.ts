import { describe, expect, test } from 'bun:test';
import { checkGit } from '../src/command-rules.ts';
import { checkPath, checkSecretBash } from '../src/secret-rules.ts';

// Three deliberate absences, grouped outside their rule modules. Each vector
// names the decision that makes silence intentional, so deleting it as a
// stale test for a vanished rule would erase a documented security boundary.
describe('rule intentions: deliberate absences', () => {
  test('deliberate carve-out: git remote -v passes the secret guard', () => {
    expect(checkSecretBash('git remote -v')).toBeNull();
  });

  test('radical non-dot: hidden .secret.pem passes checkPath', () => {
    expect(checkPath('/home/u/.secret.pem')).toBeNull();
  });

  test('rtk proxy fix: rtk proxy git push still asks via git-protected', () => {
    expect(checkGit('rtk proxy git push')?.ruleId).toBe('git-protected');
  });
});
