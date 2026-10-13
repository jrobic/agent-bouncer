// The env-value detector (ticket 58): a fake environment in, names and forms
// out. Every name and value below is made up; nothing reads the machine's own
// environment (tests/setup.ts drops the protected names from this process, and
// createEnvValueScanner takes the record as an argument).

import { describe, expect, test } from 'bun:test';
import { createCheckEnvValue, createEnvValueScanner, ENV_VALUE_SPECIAL, MIN_ENV_VALUE_LENGTH } from '../src/env-value-rules.ts';
import type { RegexRule } from '../src/policy/schema.ts';
import { checkSecretBash } from '../src/secret-rules.ts';
import { PROTECTED_NAMES, UNPROTECTED_NAMES } from './protected-name-examples.ts';

const VALUE = 'Zq7-made-up-0042'; // 16 characters, never a real credential
const hex = (value: string): string => Buffer.from(value).toString('hex');
const b64 = (value: string): string => Buffer.from(value).toString('base64');
const urlSafe = (encoded: string): string => encoded.replaceAll('+', '-').replaceAll('/', '_');
const unpadded = (encoded: string): string => encoded.replaceAll('=', '');

function scan(text: string, env: Record<string, string | undefined> = { FAKE_API_TOKEN: VALUE }) {
  return createEnvValueScanner(env)(text);
}

describe('env-value scanner: the three forms', () => {
  test('plain: the value in clear is found, whatever surrounds it', () => {
    expect(scan(`const token = "${VALUE}";`)).toEqual([{ name: 'FAKE_API_TOKEN', form: 'plain' }]);
    expect(scan(VALUE)).toEqual([{ name: 'FAKE_API_TOKEN', form: 'plain' }]);
  });

  test('base64: the encoded value alone, padded and unpadded', () => {
    const encoded = b64(VALUE);
    expect(scan(encoded)).toEqual([{ name: 'FAKE_API_TOKEN', form: 'base64' }]);
    expect(scan(unpadded(encoded))).toEqual([{ name: 'FAKE_API_TOKEN', form: 'base64' }]);
  });

  test('hex: lowercase and uppercase', () => {
    expect(scan(hex(VALUE))).toEqual([{ name: 'FAKE_API_TOKEN', form: 'hex' }]);
    expect(scan(hex(VALUE).toUpperCase())).toEqual([{ name: 'FAKE_API_TOKEN', form: 'hex' }]);
  });

  test('hex: a mixed-case string is not covered (documented)', () => {
    const lower = hex(VALUE);
    const mixed = `${lower.slice(0, 10).toUpperCase()}${lower.slice(10)}`;
    expect(scan(mixed)).toEqual([]);
  });

  test('base64: the value inside a longer stream, at all three alignments, standard and URL-safe, padded and not', () => {
    // A value with `+` and `/` in its encoding, so the two alphabets differ.
    const value = '>>>>>>????????>>>>';
    expect(b64(value)).toMatch(/[+/]/);
    const env = { ANOTHER_SECRET: value };
    for (let before = 0; before < 6; before += 1) {
      for (let after = 0; after < 6; after += 1) {
        const stream = Buffer.from(`${'a'.repeat(before)}${value}${'z'.repeat(after)}`).toString('base64');
        for (const text of [stream, unpadded(stream), urlSafe(stream), urlSafe(unpadded(stream))]) {
          expect(scan(`data:${text};`, env), `before=${before} after=${after} text=${text}`).toEqual([
            { name: 'ANOTHER_SECRET', form: 'base64' },
          ]);
        }
      }
    }
  });

  test('base64: every value length from the floor up, over arbitrary neighbouring bytes', () => {
    // A deterministic stream of bytes stands in for "whatever surrounds the value".
    let seed = 0x2545f491;
    const next = (): number => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed & 0xff;
    };
    for (let length = MIN_ENV_VALUE_LENGTH; length <= 40; length += 1) {
      const value = Array.from({ length }, () => String.fromCharCode(0x21 + (next() % 0x5e))).join('');
      for (let before = 0; before < 3; before += 1) {
        for (let after = 0; after < 3; after += 1) {
          const bytes = Buffer.concat([
            Buffer.from(Array.from({ length: before }, next)),
            Buffer.from(value),
            Buffer.from(Array.from({ length: after }, next)),
          ]);
          for (const encoded of [bytes.toString('base64'), bytes.toString('base64url')]) {
            expect(scan(encoded, { RANDOM_SECRET: value }), `length=${length} before=${before} after=${after}`).toEqual([
              { name: 'RANDOM_SECRET', form: 'base64' },
            ]);
          }
        }
      }
    }
  });

  test('a value that is not UTF-8-simple is encoded as UTF-8 (base64 and hex)', () => {
    const value = 'pässwörd-é-12';
    const env = { DB_PASSWORD: value };
    expect(scan(b64(value), env)).toEqual([{ name: 'DB_PASSWORD', form: 'base64' }]);
    expect(scan(hex(value), env)).toEqual([{ name: 'DB_PASSWORD', form: 'hex' }]);
    expect(scan(value, env)).toEqual([{ name: 'DB_PASSWORD', form: 'plain' }]);
  });

  test('the base64 of the text around the value, but not the value itself, is not a hit', () => {
    expect(scan(b64(`prefix-${VALUE.slice(0, 7)}-other`))).toEqual([]);
  });
});

describe('env-value scanner: what is not scanned', () => {
  test('a value one character under the floor is skipped, in every form', () => {
    const short = 'abcdefg';
    expect(short).toHaveLength(MIN_ENV_VALUE_LENGTH - 1);
    const env = { FAKE_API_TOKEN: short };
    expect(scan(`${short} ${b64(short)} ${hex(short)}`, env)).toEqual([]);
  });

  test('a value exactly at the floor is scanned', () => {
    const edge = 'abcdefgh';
    expect(edge).toHaveLength(MIN_ENV_VALUE_LENGTH);
    expect(scan(edge, { FAKE_API_TOKEN: edge })).toEqual([{ name: 'FAKE_API_TOKEN', form: 'plain' }]);
  });

  test.each([['HOME'], ['NODE_ENV'], ['PATH']])('%s: a long value of an unprotected name is not scanned', (name) => {
    expect(scan(VALUE, { [name]: VALUE })).toEqual([]);
  });

  test('a lowercase name is not scanned', () => {
    expect(scan(VALUE, { github_token: VALUE })).toEqual([]);
  });

  test('text that only names the variable is not a hit', () => {
    expect(scan('export FAKE_API_TOKEN=$FAKE_API_TOKEN # uses process.env.FAKE_API_TOKEN')).toEqual([]);
  });

  test('empty text, and an environment with no usable entry, find nothing', () => {
    expect(scan('')).toEqual([]);
    expect(scan(VALUE, {})).toEqual([]);
    expect(scan(VALUE, { FAKE_API_TOKEN: undefined })).toEqual([]);
    expect(scan(VALUE, { FAKE_API_TOKEN: '' })).toEqual([]);
  });
});

describe('env-value scanner: several variables, several forms', () => {
  test('two variables holding the same value are both reported', () => {
    const env = { FAKE_API_TOKEN: VALUE, FAKE_BACKUP_TOKEN: VALUE, HOME: VALUE };
    expect(scan(VALUE, env)).toEqual([
      { name: 'FAKE_API_TOKEN', form: 'plain' },
      { name: 'FAKE_BACKUP_TOKEN', form: 'plain' },
    ]);
  });

  test('one variable written in two forms is reported once per form', () => {
    expect(scan(`${VALUE}\n${hex(VALUE)}`)).toEqual([
      { name: 'FAKE_API_TOKEN', form: 'plain' },
      { name: 'FAKE_API_TOKEN', form: 'hex' },
    ]);
  });

  test('a value with regex metacharacters is matched as plain text and never compiled', () => {
    const value = '(((([[[**++??^$\\';
    const env = { FAKE_CLIENT_SECRET: value };
    expect(() => scan(`x ${value} y`, env)).not.toThrow();
    expect(scan(`x ${value} y`, env)).toEqual([{ name: 'FAKE_CLIENT_SECRET', form: 'plain' }]);
    expect(scan('x (((([[[ y', env)).toEqual([]);
  });

  test('the result carries names and forms only — no value, no encoding of it', () => {
    const found = JSON.stringify(scan(`${VALUE} ${b64(VALUE)} ${hex(VALUE)}`));
    for (const secret of [VALUE, b64(VALUE), hex(VALUE), unpadded(b64(VALUE))]) {
      expect(found).not.toContain(secret);
    }
    expect(found).toContain('FAKE_API_TOKEN');
  });
});

describe('env-value scanner: one definition of a protected name', () => {
  // The baseline reference rows (policy/secret.toml, filled from the shared
  // fragment) and the detector run over ticket 57's own examples: a name is
  // either protected by both or by neither.
  test.each(PROTECTED_NAMES)('protected name %s: the detector and the reference rows agree', (name) => {
    expect(scan(VALUE, { [name]: VALUE })).toEqual([{ name, form: 'plain' }]);
    expect(checkSecretBash(`echo $${name}`)).not.toBeNull();
  });

  test.each(UNPROTECTED_NAMES)('unprotected name %s: the detector and the reference rows agree', (name) => {
    expect(scan(VALUE, { [name]: VALUE })).toEqual([]);
    expect(checkSecretBash(`echo $${name}`)).toBeNull();
  });
});

describe('env-value check: the row-consulting verdict', () => {
  const ROW: RegexRule = {
    id: 'env-value',
    regex: '[\\s\\S]',
    special: ENV_VALUE_SPECIAL,
    reason: 'the text contains a protected value',
  };
  const env = { FAKE_API_TOKEN: VALUE };

  test('a hit is a block that names the variable in the reason and in envVars, never the value', () => {
    const verdict = createCheckEnvValue([ROW], env)(`x = "${VALUE}"`, '/tmp/out.ts');
    expect(verdict).toEqual({
      verdict: 'block',
      ruleId: 'env-value',
      reason: 'the text contains a protected value — variable: FAKE_API_TOKEN',
      target: '/tmp/out.ts',
      envVars: ['FAKE_API_TOKEN'],
    });
  });

  test('several variables are listed once each, in the reason and in envVars', () => {
    const verdict = createCheckEnvValue([ROW], { ...env, FAKE_BACKUP_TOKEN: VALUE })(`${VALUE} ${hex(VALUE)}`, 't');
    expect(verdict?.envVars).toEqual(['FAKE_API_TOKEN', 'FAKE_BACKUP_TOKEN']);
    expect(verdict?.reason).toBe('the text contains a protected value — variables: FAKE_API_TOKEN, FAKE_BACKUP_TOKEN');
  });

  test('nothing in the verdict carries the value, in clear, base64 or hex', () => {
    const verdict = createCheckEnvValue([ROW], env)(`${VALUE} ${b64(VALUE)} ${hex(VALUE)}`, '/tmp/out.ts');
    const serialized = JSON.stringify(verdict);
    for (const secret of [VALUE, b64(VALUE), unpadded(b64(VALUE)), hex(VALUE)]) {
      expect(serialized).not.toContain(secret);
    }
  });

  test('a path that itself carries the value is withheld from the verdict target', () => {
    for (const path of [`/tmp/${VALUE}.txt`, `/tmp/${b64(VALUE)}.txt`, `/tmp/${hex(VALUE)}.txt`]) {
      const verdict = createCheckEnvValue([ROW], env)(VALUE, path);
      expect(verdict?.target).toStartWith('(path withheld');
      expect(JSON.stringify(verdict)).not.toContain(VALUE);
      expect(JSON.stringify(verdict)).not.toContain(b64(VALUE));
      expect(JSON.stringify(verdict)).not.toContain(hex(VALUE));
    }
  });

  test('no env-value row left (a consumer disabled it): the guard is off', () => {
    expect(createCheckEnvValue([], env)(VALUE, 't')).toBeNull();
    expect(createCheckEnvValue([{ id: ROW.id, regex: ROW.regex, reason: ROW.reason }], env)(VALUE, 't')).toBeNull();
  });

  test('a relax override (verdict_override) softens the verdict kind', () => {
    const relaxed = { ...ROW, verdict_override: 'confirm' } as RegexRule;
    expect(createCheckEnvValue([relaxed], env)(VALUE, 't')?.verdict).toBe('confirm');
  });

  test('the row\'s own `verdict` is honoured, and an override beats it', () => {
    const observed = { ...ROW, verdict: 'observe' } as const;
    expect(createCheckEnvValue([observed], env)(VALUE, 't')?.verdict).toBe('observe');
    expect(createCheckEnvValue([{ ...observed, verdict_override: 'block' } as RegexRule], env)(VALUE, 't')?.verdict).toBe(
      'block',
    );
  });

  test('a replaced regex narrows which texts the guard looks at; except exempts one', () => {
    const narrowed = { ...ROW, regex: '^only-this$' };
    expect(createCheckEnvValue([narrowed], env)(VALUE, 't')).toBeNull();
    expect(createCheckEnvValue([{ ...ROW, except: 'allowed-file' }], env)(`allowed-file ${VALUE}`, 't')).toBeNull();
  });

  test('no protected variable in the environment: silent', () => {
    expect(createCheckEnvValue([ROW], { HOME: VALUE })(VALUE, 't')).toBeNull();
    expect(createCheckEnvValue([ROW], env)('no secret here', 't')).toBeNull();
    expect(createCheckEnvValue([ROW], env)('', 't')).toBeNull();
  });
});
