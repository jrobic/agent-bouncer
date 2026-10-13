import { describe, expect, test } from 'bun:test';
import { createEnvValueGuard } from '../src/env-value-rules.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import { scanSecrets } from '../src/write-secret-rules.ts';

describe('write-secret-rules: SECRET_RULES', () => {
  test('ruleId private-key: PEM private key block is denied', () => {
    const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('private-key');
  });

  test('ruleId aws-access-key-id: AKIA... is denied', () => {
    const text = 'const key = "AKIAABCDEFGHIJKLMNOP";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('aws-access-key-id');
  });

  test('ruleId github-pat: ghp_ token is denied', () => {
    const text = 'const t = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('github-pat');
  });

  test('ruleId github-pat: github_pat_ token is denied', () => {
    const text = 'const t = "github_pat_abcdefghijklmnopqrstuv";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('github-pat');
  });

  test('ruleId github-token: ghu_ OAuth token is denied', () => {
    const text = `const t = "ghu_${'a'.repeat(36)}";`;
    expect(scanSecrets(text, 'target')?.ruleId).toBe('github-token');
  });

  test('ruleId slack-token: xoxb- token is denied', () => {
    const text = 'const t = "xoxb-1234567890-abcdefghij";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('slack-token');
  });

  test('ruleId google-api-key: AIza... key is denied', () => {
    const text = `const k = "AIza${'B'.repeat(35)}";`;
    expect(scanSecrets(text, 'target')?.ruleId).toBe('google-api-key');
  });

  test('ruleId stripe-secret-key: sk_live_ key is denied', () => {
    const text = 'const k = "sk_live_abcdefghijklmnopqrstuvwx";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('stripe-secret-key');
  });

  test('ruleId jwt: a JSON Web Token is denied', () => {
    const text = 'const j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrs";';
    expect(scanSecrets(text, 'target')?.ruleId).toBe('jwt');
  });

  test('benign: ordinary source text passes', () => {
    expect(scanSecrets('const safe = "hello world";', 'target')).toBeNull();
  });

  test('benign: empty text passes', () => {
    expect(scanSecrets('', 'target')).toBeNull();
  });
});

describe('write-secret-rules: the env-value row', () => {
  const env = { FAKE_API_TOKEN: 'Zq7-made-up-0042' };

  test('ruleId env-value: the value of a protected environment variable is blocked, naming the variable', () => {
    const verdict = createEnvValueGuard(BASELINE.rules.write_secret, env).check('const t = "Zq7-made-up-0042";', '/tmp/out.ts');
    expect(verdict).toMatchObject({ verdict: 'block', ruleId: 'env-value', target: '/tmp/out.ts', envVars: ['FAKE_API_TOKEN'] });
    expect(verdict?.reason).toContain('FAKE_API_TOKEN');
  });

  test('the regex scan never fires that row: its recognition is the engine\'s, bound to an environment', () => {
    expect(scanSecrets('const t = "Zq7-made-up-0042";', 'target')).toBeNull();
  });
});
