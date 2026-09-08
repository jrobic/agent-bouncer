// The `apply-patch` input codec (src/adapter/codecs/input/apply-patch.ts,
// ADR-0006 § 6, ticket 15b) — Codex's `*** Begin Patch` … `*** End Patch`
// grammar to `{paths, text}`. Each test names exactly which parsing
// contract it proves; `parseApplyPatch` is exercised directly (raw patch
// text in, no `tool_input` wrapper) so a grammar bug can't hide behind
// the field-reading contract `applyPatchCodec` layers on top of it
// (covered separately, § "the non-string field contract" below).

import { describe, expect, test } from 'bun:test';
import { applyPatchCodec, parseApplyPatch } from '../src/adapter/codecs/input/apply-patch.ts';

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

describe('parseApplyPatch: the four directives', () => {
  test('Add File: the path is written, its "+" lines become text', () => {
    const patch = ['*** Begin Patch', '*** Add File: src/new.ts', '+export const x = 1;', '+export const y = 2;', '*** End Patch']
      .join('\n');
    const result = parseApplyPatch(patch, 'test');
    expect(result.paths).toEqual(['src/new.ts']);
    expect(result.text).toBe('export const x = 1;\nexport const y = 2;');
  });

  test('Update File: the path is written, its "+" lines become text, "-" lines never do', () => {
    const patch = [
      '*** Begin Patch',
      '*** Update File: src/existing.ts',
      '@@',
      '-export const old = 1;',
      '+export const updated = 2;',
      '*** End Patch',
    ].join('\n');
    const result = parseApplyPatch(patch, 'test');
    expect(result.paths).toEqual(['src/existing.ts']);
    expect(result.text).toBe('export const updated = 2;');
  });

  test('Delete File: the path is written, no text (a delete carries no content)', () => {
    const patch = ['*** Begin Patch', '*** Delete File: src/obsolete.ts', '*** End Patch'].join('\n');
    const result = parseApplyPatch(patch, 'test');
    expect(result.paths).toEqual(['src/obsolete.ts']);
    expect(result.text).toBeNull();
  });

  test('Move to (as a sub-directive of Update File): both the source and destination are written', () => {
    const patch = [
      '*** Begin Patch',
      '*** Update File: src/old-name.ts',
      '*** Move to: src/new-name.ts',
      '@@',
      '+export const moved = true;',
      '*** End Patch',
    ].join('\n');
    const result = parseApplyPatch(patch, 'test');
    expect(result.paths).toEqual(['src/old-name.ts', 'src/new-name.ts']);
    expect(result.text).toBe('export const moved = true;');
  });
});

test('a move writes two paths and one Add File in the same patch writes a third — every touched path is collected', () => {
  const patch = [
    '*** Begin Patch',
    '*** Add File: src/brand-new.ts',
    '+export const brand = true;',
    '*** Update File: src/old.ts',
    '*** Move to: src/new.ts',
    '@@',
    '+export const renamed = true;',
    '*** End Patch',
  ].join('\n');
  const result = parseApplyPatch(patch, 'test');
  expect(result.paths).toEqual(['src/brand-new.ts', 'src/old.ts', 'src/new.ts']);
  expect(result.text).toBe('export const brand = true;\nexport const renamed = true;');
});

test('mixed hunks: context and removed lines inside one Update File section never leak into text, only "+" lines do', () => {
  const patch = [
    '*** Begin Patch',
    '*** Update File: src/mixed.ts',
    '@@ function example() {',
    ' const kept = 1;',
    '-const removed = 2;',
    '+const added = 3;',
    ' const alsoKept = 4;',
    '+const alsoAdded = 5;',
    '*** End Patch',
  ].join('\n');
  const result = parseApplyPatch(patch, 'test');
  expect(result.paths).toEqual(['src/mixed.ts']);
  expect(result.text).toBe('const added = 3;\nconst alsoAdded = 5;');
});

test('CRLF line endings parse identically to LF', () => {
  const lf = ['*** Begin Patch', '*** Add File: src/crlf.ts', '+export const crlf = true;', '*** End Patch'].join('\n');
  const crlf = lf.replace(/\n/g, '\r\n');
  const lfResult = parseApplyPatch(lf, 'test');
  const crlfResult = parseApplyPatch(crlf, 'test');
  expect(crlfResult).toEqual(lfResult);
  expect(crlfResult.paths).toEqual(['src/crlf.ts']);
  expect(crlfResult.text).toBe('export const crlf = true;');
});

test('an empty patch (Begin/End Patch, no directives) yields no paths and no text — legal, silent, no diagnostic', () => {
  const logs = withStderr(() => {
    const result = parseApplyPatch('*** Begin Patch\n*** End Patch', 'test');
    expect(result.paths).toEqual([]);
    expect(result.text).toBeNull();
  });
  expect(logs).toEqual([]);
});

test('a patch missing "*** End Patch" is not judged and logs one stderr line naming the failure', () => {
  const logs = withStderr(() => {
    const result = parseApplyPatch('*** Begin Patch\n*** Add File: src/x.ts\n+x', 'test');
    expect(result.paths).toEqual([]);
    expect(result.text).toBeNull();
  });
  expect(logs).toHaveLength(1);
  expect(logs[0]).toContain('missing "*** End Patch"');
  expect(logs[0]).toContain('not judged');
});

test('a patch missing "*** Begin Patch" is not judged and logs one stderr line naming the failure', () => {
  const logs = withStderr(() => {
    const result = parseApplyPatch('*** Add File: src/x.ts\n+x\n*** End Patch', 'test');
    expect(result.paths).toEqual([]);
    expect(result.text).toBeNull();
  });
  expect(logs).toHaveLength(1);
  expect(logs[0]).toContain('missing "*** Begin Patch"');
});

test('an unrecognized directive line with nothing parsed before it is not judged at all', () => {
  const logs = withStderr(() => {
    const result = parseApplyPatch('*** Begin Patch\n*** Rename File: src/x.ts\n*** End Patch', 'test');
    expect(result.paths).toEqual([]);
    expect(result.text).toBeNull();
  });
  expect(logs).toHaveLength(1);
  expect(logs[0]).toContain('unrecognized line');
  expect(logs[0]).toContain('Rename File');
});

// Review round 1 S-9: an otherwise-valid patch whose body goes off the
// rails PARTWAY THROUGH keeps everything parsed before the offending
// line — judge what was seen, say what was not — rather than discarding
// a real Add File path and its text over one bad trailing line.
test('an unrecognized directive line AFTER a valid section keeps that section judged, logs the offending line', () => {
  const logs = withStderr(() => {
    const patch = [
      '*** Begin Patch',
      '*** Add File: src/a.ts',
      '+content-a',
      '*** Rename File: src/b.ts',
      '*** End Patch',
    ].join('\n');
    const result = parseApplyPatch(patch, 'test');
    expect(result.paths).toEqual(['src/a.ts']);
    expect(result.text).toBe('content-a');
  });
  expect(logs).toHaveLength(1);
  expect(logs[0]).toContain('unrecognized line');
  expect(logs[0]).toContain('Rename File');
  expect(logs[0]).toContain('body line 4');
  expect(logs[0]).toContain('parsed prefix judged, rest skipped');
});

describe('applyPatchCodec: the non-string field contract (mirrors a plain selector)', () => {
  test('tool_input.command absent is silently "no value" — no diagnostic', () => {
    const logs = withStderr(() => {
      const result = applyPatchCodec({}, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toEqual([]);
  });

  test('a non-string tool_input.command logs the same diagnostic every selector uses and resolves to no value', () => {
    const logs = withStderr(() => {
      const result = applyPatchCodec({ command: 42 }, 'test');
      expect(result.paths).toEqual([]);
      expect(result.text).toBeNull();
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('expected string for tool_input.command, got number — allowing');
  });

  test('a real string tool_input.command is parsed as a patch', () => {
    const command = ['*** Begin Patch', '*** Add File: src/x.ts', '+content', '*** End Patch'].join('\n');
    const result = applyPatchCodec({ command }, 'test');
    expect(result.paths).toEqual(['src/x.ts']);
    expect(result.text).toBe('content');
  });
});
