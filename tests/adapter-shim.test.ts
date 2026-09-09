// src/adapter/shim.ts's own renderShim/hasShim — the embedded pi-agent
// shim source with `BOUNCER` substituted, byte for byte otherwise.

import { describe, expect, test } from 'bun:test';
import { hasShim, renderShim } from '../src/adapter/shim.ts';

describe('hasShim', () => {
  test('true for a harness with an embedded shim, false for one without and an undeclared id', () => {
    expect(hasShim('pi-agent')).toBe(true);
    expect(hasShim('codex')).toBe(false);
    expect(hasShim('nope')).toBe(false);
  });
});

describe('renderShim', () => {
  test('undefined for a harness with no printable shim', () => {
    expect(renderShim('codex', '/usr/local/bin/bouncer')).toBeUndefined();
    expect(renderShim('nope', '/usr/local/bin/bouncer')).toBeUndefined();
  });

  test('substitutes BOUNCER to the given path, JSON-encoded, exactly once', () => {
    const rendered = renderShim('pi-agent', '/opt/dist/bouncer')!;
    expect(rendered).toContain('const BOUNCER = process.env.BOUNCER_BIN ?? "/opt/dist/bouncer";');
    // The placeholder token itself never survives rendering.
    expect(rendered).not.toContain('__BOUNCER_BIN__');
  });

  // Review round 1 S-1: String.replace's second argument, given a
  // string, interprets `$&`/`$'`/`` $` ``/`$n` as replacement patterns —
  // a bouncerPath containing one would have silently corrupted the
  // printed shim under the old `source.replace(PLACEHOLDER,
  // JSON.stringify(bouncerPath))` call. A path most operators would
  // never type by hand, but a real absolute path all the same.
  test('a path containing "$&" is substituted literally, not interpreted as a replacement pattern', () => {
    const dollarPath = '/tmp/weird-$&-path/bouncer';
    const rendered = renderShim('pi-agent', dollarPath)!;
    expect(rendered).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(dollarPath)};`);
  });

  test('a path containing "$$" (the "$" replacement pattern) is substituted literally', () => {
    const dollarPath = '/tmp/weird-$$-path/bouncer';
    const rendered = renderShim('pi-agent', dollarPath)!;
    expect(rendered).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(dollarPath)};`);
  });

  test('two renders of the same harness with different paths differ only in the baked BOUNCER line', () => {
    const a = renderShim('pi-agent', '/a/bouncer')!;
    const b = renderShim('pi-agent', '/b/bouncer')!;
    const aLines = a.split('\n');
    const bLines = b.split('\n');
    expect(aLines.length).toBe(bLines.length);
    const diffLines = aLines.filter((line, i) => line !== bLines[i]);
    expect(diffLines).toEqual(['const BOUNCER = process.env.BOUNCER_BIN ?? "/a/bouncer";']);
  });
});
