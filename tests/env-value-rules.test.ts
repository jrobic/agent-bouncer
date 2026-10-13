// The env-value detector (ticket 58) and its redactor (ticket 59): a fake
// environment in, names and forms — or the redacted text — out. Every name and
// value below is made up; nothing reads the machine's own environment
// (tests/setup.ts drops the protected names from this process, and every
// constructor takes the record as an argument).

import { describe, expect, test } from 'bun:test';
import { createEnvValueGuard, createEnvValueScanner, ENV_VALUE_SPECIAL, MIN_ENV_VALUE_LENGTH } from '../src/env-value-rules.ts';
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
    const verdict = createEnvValueGuard([ROW], env).check(`x = "${VALUE}"`, '/tmp/out.ts');
    expect(verdict).toEqual({
      verdict: 'block',
      ruleId: 'env-value',
      reason: 'the text contains a protected value — variable: FAKE_API_TOKEN',
      target: '/tmp/out.ts',
      envVars: ['FAKE_API_TOKEN'],
    });
  });

  test('several variables are listed once each, in the reason and in envVars', () => {
    const verdict = createEnvValueGuard([ROW], { ...env, FAKE_BACKUP_TOKEN: VALUE }).check(`${VALUE} ${hex(VALUE)}`, 't');
    expect(verdict?.envVars).toEqual(['FAKE_API_TOKEN', 'FAKE_BACKUP_TOKEN']);
    expect(verdict?.reason).toBe('the text contains a protected value — variables: FAKE_API_TOKEN, FAKE_BACKUP_TOKEN');
  });

  test('nothing in the verdict carries the value, in clear, base64 or hex', () => {
    const verdict = createEnvValueGuard([ROW], env).check(`${VALUE} ${b64(VALUE)} ${hex(VALUE)}`, '/tmp/out.ts');
    const serialized = JSON.stringify(verdict);
    for (const secret of [VALUE, b64(VALUE), unpadded(b64(VALUE)), hex(VALUE)]) {
      expect(serialized).not.toContain(secret);
    }
  });

  test('a path that itself carries the value is withheld from the verdict target', () => {
    for (const path of [`/tmp/${VALUE}.txt`, `/tmp/${b64(VALUE)}.txt`, `/tmp/${hex(VALUE)}.txt`]) {
      const verdict = createEnvValueGuard([ROW], env).check(VALUE, path);
      expect(verdict?.target).toStartWith('(path withheld');
      expect(JSON.stringify(verdict)).not.toContain(VALUE);
      expect(JSON.stringify(verdict)).not.toContain(b64(VALUE));
      expect(JSON.stringify(verdict)).not.toContain(hex(VALUE));
    }
  });

  test('no env-value row left (a consumer disabled it): the guard is off', () => {
    expect(createEnvValueGuard([], env).check(VALUE, 't')).toBeNull();
    expect(createEnvValueGuard([{ id: ROW.id, regex: ROW.regex, reason: ROW.reason }], env).check(VALUE, 't')).toBeNull();
  });

  test('a relax override (verdict_override) softens the verdict kind', () => {
    const relaxed = { ...ROW, verdict_override: 'confirm' } as RegexRule;
    expect(createEnvValueGuard([relaxed], env).check(VALUE, 't')?.verdict).toBe('confirm');
  });

  test('the row\'s own `verdict` is honoured, and an override beats it', () => {
    const observed = { ...ROW, verdict: 'observe' } as const;
    expect(createEnvValueGuard([observed], env).check(VALUE, 't')?.verdict).toBe('observe');
    expect(createEnvValueGuard([{ ...observed, verdict_override: 'block' } as RegexRule], env).check(VALUE, 't')?.verdict).toBe(
      'block',
    );
  });

  test('a replaced regex narrows which texts the guard looks at; except exempts one', () => {
    const narrowed = { ...ROW, regex: '^only-this$' };
    expect(createEnvValueGuard([narrowed], env).check(VALUE, 't')).toBeNull();
    expect(createEnvValueGuard([{ ...ROW, except: 'allowed-file' }], env).check(`allowed-file ${VALUE}`, 't')).toBeNull();
  });

  test('no protected variable in the environment: silent', () => {
    expect(createEnvValueGuard([ROW], { HOME: VALUE }).check(VALUE, 't')).toBeNull();
    expect(createEnvValueGuard([ROW], env).check('no secret here', 't')).toBeNull();
    expect(createEnvValueGuard([ROW], env).check('', 't')).toBeNull();
  });
});

// Ticket 59 (ADR-0008 § 4): the same row, used to replace instead of refuse.
describe('env-value redactor: what replaces what', () => {
  const ROW: RegexRule = { id: 'env-value', regex: '[\\s\\S]', special: ENV_VALUE_SPECIAL, reason: 'r' };
  const redact = (text: string, env: Record<string, string | undefined> = { FAKE_API_TOKEN: VALUE }) =>
    createEnvValueGuard([ROW], env).redact(text);
  const MARKER = '[redacted: FAKE_API_TOKEN]';
  const FOUND = { names: ['FAKE_API_TOKEN'], ruleId: 'env-value' };

  test.each([
    ['plain', VALUE],
    ['base64, padded', b64(VALUE)],
    ['base64, unpadded', unpadded(b64(VALUE))],
    ['base64, URL-safe', urlSafe(b64('?>?>made-up-0042'))],
    ['hex, lowercase', hex(VALUE)],
    ['hex, uppercase', hex(VALUE).toUpperCase()],
  ])('%s: a standalone spelling is replaced whole, the text around it kept', (_form, spelling) => {
    const env = { FAKE_API_TOKEN: spelling === urlSafe(b64('?>?>made-up-0042')) ? '?>?>made-up-0042' : VALUE };
    expect(redact(`key=${spelling}\nnext line`, env)).toEqual({ text: `key=${MARKER}\nnext line`, found: FOUND });
  });

  test('every occurrence is replaced', () => {
    expect(redact(`${VALUE}|${VALUE}|${hex(VALUE)}`).text).toBe(`${MARKER}|${MARKER}|${MARKER}`);
  });

  describe('base64: exactly the characters that carry the value go, never a neighbour', () => {
    // 15, 16 and 17 bytes: a complete last group, then one and two bytes
    // over (a partial last character, then `==` / `=` padding). `?>` puts
    // `/` in the standard encoding, so the URL-safe spelling differs.
    const VALUES = ['?>?>made-up-004', '?>?>made-up-0042', '?>?>made-up-00420'];
    const spellings = (encoded: string): readonly string[] => [
      encoded,
      unpadded(encoded),
      urlSafe(encoded),
      urlSafe(unpadded(encoded)),
    ];
    // Each pair surrounds the encoding with characters of the base64 alphabets.
    const NEIGHBOURS: ReadonlyArray<readonly [string, string]> = [
      ['https://h/x/', '/next'],
      ['id_', '_v2'],
      ['a-', '-b'],
      ['abc', 'xyz'],
    ];

    test.each(VALUES)('%p encoded alone, between alphabet neighbours: the neighbours stay', (value) => {
      for (const spelling of spellings(b64(value))) {
        for (const [before, after] of NEIGHBOURS) {
          expect(redact(`${before}${spelling}${after}`, { FAKE_API_TOKEN: value }), `${before}|${spelling}|${after}`).toEqual({
            text: `${before}${MARKER}${after}`,
            found: FOUND,
          });
        }
      }
    });

    test.each(VALUES)('%p inside a longer stream, at every alignment: the stream outside the value\'s bits stays', (value) => {
      const length = Buffer.byteLength(value);
      for (let before = 0; before < 6; before += 1) {
        for (let after = 0; after < 6; after += 1) {
          const stream = b64(`${'a'.repeat(before)}${value}${'z'.repeat(after)}`);
          // Characters wholly inside the bytes before / after the value.
          const keptBefore = Math.floor((8 * before) / 6);
          const resumeAt = Math.ceil((8 * (before + length)) / 6);
          for (const spelling of spellings(stream)) {
            // With nothing after the value, what follows its last character is padding, part of the encoding.
            const keptAfter = after === 0 ? '' : spelling.slice(resumeAt);
            expect(redact(`https://h/x/${spelling}/next`, { FAKE_API_TOKEN: value }).text, `before=${before} after=${after} ${spelling}`)
              .toBe(`https://h/x/${spelling.slice(0, keptBefore)}${MARKER}${keptAfter}/next`);
          }
        }
      }
    });
  });

  test('a marker is never scanned again: a value that spells part of another variable\'s marker stays a marker', () => {
    const env = { ALPHA_TOKEN: 'made-up-alpha-0042', BETA_TOKEN: 'ted: ALPHA_TOKEN]' };
    expect(redact('made-up-alpha-0042', env)).toEqual({
      text: '[redacted: ALPHA_TOKEN]',
      found: { names: ['ALPHA_TOKEN'], ruleId: 'env-value' },
    });
  });

  test('one value under two names: named once, by the name that sorts first, whatever the environment order', () => {
    const env = { ZULU_TOKEN: VALUE, ALPHA_TOKEN: VALUE };
    expect(redact(VALUE, env)).toEqual({ text: '[redacted: ALPHA_TOKEN]', found: { names: ['ALPHA_TOKEN'], ruleId: 'env-value' } });
  });

  test('nothing to replace, an unprotected name, a value under the floor: the text comes back unchanged, nothing found', () => {
    expect(redact('no secret here')).toEqual({ text: 'no secret here' });
    expect(redact(VALUE, { HOME: VALUE })).toEqual({ text: VALUE });
    const short = 'x'.repeat(MIN_ENV_VALUE_LENGTH - 1);
    expect(redact(`${short} ${hex(short)}`, { FAKE_API_TOKEN: short })).toEqual({ text: `${short} ${hex(short)}` });
  });

  test('a value that is `__proto__` is a needle like any other', () => {
    expect(redact('a __proto__ b', { WEIRD_TOKEN: '__proto__' }).text).toBe('a [redacted: WEIRD_TOKEN] b');
  });
});

describe('env-value redactor: the row is the switch (decision H3)', () => {
  const ROW: RegexRule = { id: 'env-value', regex: '[\\s\\S]', special: ENV_VALUE_SPECIAL, reason: 'r' };
  const env = { FAKE_API_TOKEN: VALUE };

  test('no env-value row (disabled): off', () => {
    expect(createEnvValueGuard([], env).redact(VALUE)).toEqual({ text: VALUE });
  });

  test('a relaxed row (any verdict_override): redaction off, not softer — the same guard\'s write check is only softened', () => {
    for (const verdict of ['confirm', 'observe'] as const) {
      const guard = createEnvValueGuard([{ ...ROW, verdict_override: verdict } as RegexRule], env);
      expect(guard.redact(VALUE)).toEqual({ text: VALUE });
      expect(guard.check(VALUE, 't')?.verdict).toBe(verdict);
    }
  });

  test('the row\'s regex / except gate writes only: the redaction scans every text (decision H6); its id names it', () => {
    const marker = '[redacted: FAKE_API_TOKEN]';
    const narrowed = createEnvValueGuard([{ ...ROW, regex: '^only-this$' }], env);
    expect(narrowed.check(VALUE, 't')).toBeNull();
    expect(narrowed.redact(VALUE)).toEqual({ text: marker, found: { names: ['FAKE_API_TOKEN'], ruleId: 'env-value' } });
    const excepted = createEnvValueGuard([{ ...ROW, except: 'allowed-file' }], env);
    expect(excepted.check(`allowed-file ${VALUE}`, 't')).toBeNull();
    expect(excepted.redact(`allowed-file ${VALUE}`).text).toBe(`allowed-file ${marker}`);
    expect(createEnvValueGuard([{ ...ROW, id: 'overlay-env-value' }], env).redact(VALUE).found?.ruleId).toBe('overlay-env-value');
  });
});
