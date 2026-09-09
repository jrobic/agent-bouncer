// The `hashline` input codec (src/adapter/codecs/input/hashline.ts,
// ADR-0006 § 6, ticket 15c) — pi-agent/omp's `edit` tool's own
// `[PATH#TAG]` + `+`-row patch grammar to `{paths, text}`. Each test names
// exactly which parsing contract it proves; `parseHashline` is exercised
// directly (raw patch text in, no `tool_input` wrapper) so a grammar bug
// can't hide behind the field-reading contract `hashlineCodec` layers on
// top of it (covered separately, § "the non-string field contract"
// below) — same discipline as tests/adapter-codecs-apply-patch.test.ts.

import { describe, expect, test } from 'bun:test';
import { hashlineCodec, parseHashline } from '../src/adapter/codecs/input/hashline.ts';

function withStderr(fn: () => void): string[] {
  const logs: string[] = [];
  const original = console.error;
  console.error = (msg: string) => logs.push(msg);
  try {
    fn();
  } finally {
    console.error = original;
  }
  return logs;
}

describe('parseHashline: one section', () => {
  test('a single [PATH#TAG] section with "+" rows only: the path is written, its rows join into text', () => {
    const patch = ['[greet.py#A1B2]', 'PUT 1.=3:', '+def greet(name):', '+    print(f"Hi, {name}")'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py']);
    expect(result.text).toBe('def greet(name):\n    print(f"Hi, {name}")');
  });

  test('an operation line with no body rows (CUT) is legal and contributes no text', () => {
    const patch = ['[greet.py#A1B2]', 'CUT 4.=4'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py']);
    expect(result.text).toBeNull();
  });
});

describe('parseHashline: several sections', () => {
  test('two [PATH#TAG] sections in one payload: both paths are written, text is joined across sections', () => {
    const patch = [
      '[greet.py#A1B2]',
      'PUT 1*:',
      '+def greet(name):',
      '+    print(f"Hello, {name}")',
      '[other.py#3C4D]',
      'PUT <1:',
      '+import greet',
    ].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py', 'other.py']);
    expect(result.text).toBe('def greet(name):\n    print(f"Hello, {name}")\nimport greet');
  });

  test('a move via CUT + PUT across two sections collects both paths (mirrors apply-patch\'s own move-writes-two-paths reasoning)', () => {
    const patch = ['[greet.py#A1B2]', 'CUT 1* @fn', '[other.py#5E6F]', 'PUT <1 @fn'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py', 'other.py']);
    expect(result.text).toBeNull();
  });
});

describe('parseHashline: relative path, resolved against cwd by buildNeutralCall (not by this codec)', () => {
  test('a relative PATH in the header is returned verbatim — cwd-joining is the caller\'s job, same contract as apply-patch', () => {
    const patch = ['[src/config.toml#1122]', 'PUT >5:', '+new_setting = true'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['src/config.toml']);
    expect(result.text).toBe('new_setting = true');
  });
});

describe('parseHashline: "+" rows only — never "-"/context/CUT rows', () => {
  test('a bare context-shaped line and a leading "-" never leak into text, only "+" rows do', () => {
    const patch = [
      '[greet.py#A1B2]',
      'PUT 2.=3:',
      '-   msg = "old"',
      '    unchanged_context_line',
      '+   msg = "new"',
      '+   return msg',
    ].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.text).toBe('   msg = "new"\n   return msg');
  });

  test('a CUT operation line (no colon, no body) never contributes to text even when it names a range', () => {
    const patch = ['[greet.py#A1B2]', 'CUT 4.=9', 'PUT >40:', '+moved_here()'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.text).toBe('moved_here()');
  });
});

describe('parseHashline: the optional *** Begin Patch / *** End Patch envelope', () => {
  test('enveloped in *** Begin Patch / *** End Patch markers: accepted, markers themselves contribute nothing', () => {
    const patch = ['*** Begin Patch', '[greet.py#A1B2]', 'PUT 1.=1:', '+def greet(name):', '*** End Patch'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py']);
    expect(result.text).toBe('def greet(name):');
  });

  test('NOT enveloped at all: accepted identically — the envelope is optional, never required', () => {
    const patch = ['[greet.py#A1B2]', 'PUT 1.=1:', '+def greet(name):'].join('\n');
    const result = parseHashline(patch, 'test');
    expect(result.paths).toEqual(['greet.py']);
    expect(result.text).toBe('def greet(name):');
  });
});

describe('parseHashline: an unparseable payload — not judged, one stderr line', () => {
  test('no [PATH#TAG] header anywhere: not judged at all, logs one stderr line', () => {
    const logs = withStderr(() => {
      const result = parseHashline('PUT 1.=1:\n+def greet(name):\n', 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('hashline payload has no [PATH#TAG] section header — not judged');
  });

  test('an empty payload: not judged, logs one stderr line', () => {
    const logs = withStderr(() => {
      const result = parseHashline('', 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
  });

  test('a malformed tag (not 4 hex chars) never matches the header — the whole line is inert, not a path', () => {
    const logs = withStderr(() => {
      const result = parseHashline('[greet.py#ZZZZ]\nPUT 1.=1:\n+x = 1', 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
  });
});

describe('parseHashline: CRLF line endings', () => {
  test('CRLF parses identically to LF', () => {
    const lf = ['[src/crlf.ts#AB12]', 'PUT 1.=1:', '+export const crlf = true;'].join('\n');
    const crlf = lf.replace(/\n/g, '\r\n');
    const lfResult = parseHashline(lf, 'test');
    const crlfResult = parseHashline(crlf, 'test');
    expect(crlfResult).toEqual(lfResult);
    expect(crlfResult.paths).toEqual(['src/crlf.ts']);
    expect(crlfResult.text).toBe('export const crlf = true;');
  });
});

describe('hashlineCodec: the non-string field contract (mirrors a plain selector, same as applyPatchCodec)', () => {
  test('neither tool_input.input nor {path, edits[]} present: NOT_JUDGED WITH a stderr line (review round 1 P-1)', () => {
    const logs = withStderr(() => {
      const result = hashlineCodec({}, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('edit payload matches neither the omp hashline (`input`) nor the pi (`path`+`edits[]`) shape — not judged');
  });

  test('a non-string tool_input.input logs the same diagnostic every selector uses and resolves to no value', () => {
    const logs = withStderr(() => {
      const result = hashlineCodec({ input: 42 }, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('expected string for tool_input.input, got number — allowing');
  });

  test('a real string tool_input.input is parsed as a hashline patch', () => {
    const input = ['[src/x.ts#9988]', 'PUT 1.=1:', '+content'].join('\n');
    const result = hashlineCodec({ input }, 'test');
    expect(result.paths).toEqual(['src/x.ts']);
    expect(result.text).toBe('content');
  });
});

describe('hashlineCodec: pi\'s own {path, edits[]} shape (review round 1 P-1, edit.d.ts:10-16)', () => {
  test('path + edits[].newText: paths = [path], text = every newText joined by "\\n"', () => {
    const logs = withStderr(() => {
      const result = hashlineCodec({
        path: 'src/new-secret.ts',
        edits: [
          { oldText: 'old one', newText: 'export const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";' },
          { oldText: 'old two', newText: 'export const other = 1;' },
        ],
      }, 'test');
      expect(result.paths).toEqual(['src/new-secret.ts']);
      expect(result.text).toBe('export const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\nexport const other = 1;');
    });
    expect(logs).toEqual([]);
  });

  test('oldText is never part of the scanned text — only newText, the content actually written', () => {
    const result = hashlineCodec({
      path: 'src/x.ts',
      edits: [{ oldText: 'AKIAIOSFODNN7EXAMPLE', newText: 'redacted' }],
    }, 'test');
    expect(result.text).toBe('redacted');
    expect(result.text).not.toContain('AKIA');
  });

  test('edits: [] (no edits) still names the path, with null text', () => {
    const result = hashlineCodec({ path: 'src/x.ts', edits: [] }, 'test');
    expect(result.paths).toEqual(['src/x.ts']);
    expect(result.text).toBeNull();
  });

  test('path present but edits missing/not an array: neither shape recognized, NOT_JUDGED with a stderr line', () => {
    const logs = withStderr(() => {
      const result = hashlineCodec({ path: 'src/x.ts' }, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('not judged');
  });

  test('edits present but path missing/not a string: neither shape recognized, NOT_JUDGED with a stderr line', () => {
    const logs = withStderr(() => {
      const result = hashlineCodec({ edits: [{ oldText: 'a', newText: 'b' }] }, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('not judged');
  });
});
