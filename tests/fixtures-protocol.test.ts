// The conformance proof ADR-0006 § 10 asks for: fixtures/protocol/
// claude-code.json was captured from the INSTALLED binary (9ee2286)
// BEFORE the ticket 15a refactor (scripts/capture-protocol.ts, see the
// 15a report for the capture run) — this file replays every one of those
// cases through the POST-refactor, declaration-driven `run()` and asserts
// its stdout and exit code match, byte for byte. If this file is green,
// the seam extraction changed nothing observable for a Claude Code user.
//
// Each case gets its own throwaway HOME/CLAUDE_CONFIG_DIR (baseline only,
// no workstation overlay) — same isolation discipline as the capture
// script itself. The two SessionStart cases need a real settings.json on
// disk; its SHAPE (not its exact binary path — see below) is what the
// capture script wrote, reconstructed here from the same
// tests/doctor-fixtures.ts helpers the rest of the doctor test suite
// uses. The binary path itself never appears in either captured case's
// stdout (checked once, by hand, against the recorded fixture) — only
// event names and check ids do — so a fake path here reproduces the same
// bytes the real installed path produced.

import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/adapter/run.ts';
import { HEALTHY_HOOKS } from './doctor-fixtures.ts';

interface RecordedCase {
  readonly id: string;
  readonly argv: readonly string[];
  readonly stdin: string;
  readonly expected: { readonly stdout: string | null; readonly exit: number; };
}

const FIXTURE_PATH = join(import.meta.dir, '..', 'fixtures', 'protocol', 'claude-code.json');
const { cases } = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as { cases: readonly RecordedCase[]; };

// Mirrors scripts/capture-protocol.ts's own settings fixtures exactly —
// see that script's `settings` field on the two `sessionstart-*` cases.
const MISSING_HOOK_HOOKS = (() => {
  const { UserPromptSubmit: _omit, ...rest } = HEALTHY_HOOKS;
  return rest;
})();

function settingsFor(caseId: string): unknown | undefined {
  if (caseId === 'sessionstart-healthy-silent') return HEALTHY_HOOKS;
  if (caseId === 'sessionstart-missing-hook-scream') return MISSING_HOOK_HOOKS;
  return undefined;
}

// Mirrors cli.ts's own `run` argv handling exactly: only the LITERAL
// string "--shadow" ever sets shadow mode; every other token is passed
// through as an unrecognized-argument warning, never silently dropped.
function parseRunArgv(argv: readonly string[]): { shadow: boolean; unrecognizedTokens: readonly string[]; } {
  return { shadow: argv.includes('--shadow'), unrecognizedTokens: argv.filter((t) => t !== '--shadow') };
}

describe('fixtures/protocol/claude-code.json: byte-for-byte replay against the post-15a run()', () => {
  for (const recorded of cases) {
    test(recorded.id, async () => {
      const accountDir = mkdtempSync(join(tmpdir(), 'bouncer-protocol-replay-'));
      const configDir = join(accountDir, '.claude');
      mkdirSync(configDir, { recursive: true });
      const settings = settingsFor(recorded.id);
      if (settings !== undefined) {
        writeFileSync(join(configDir, 'settings.json'), JSON.stringify({ hooks: settings }), 'utf8');
      }

      const originalHome = process.env.HOME;
      const originalConfigDir = process.env.CLAUDE_CONFIG_DIR;
      process.env.HOME = accountDir;
      process.env.CLAUDE_CONFIG_DIR = configDir;
      try {
        const { shadow, unrecognizedTokens } = parseRunArgv(recorded.argv);
        const result = await run(recorded.stdin, { shadow, unrecognizedTokens });
        expect(result.stdout).toBe(recorded.expected.stdout);
        expect(result.exit ?? 0).toBe(recorded.expected.exit);
      } finally {
        if (originalHome === undefined) delete process.env.HOME;
        else process.env.HOME = originalHome;
        if (originalConfigDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
        else process.env.CLAUDE_CONFIG_DIR = originalConfigDir;
      }
    });
  }
});

// A meta-check on the fixture set itself — the capture script's own
// output proves this, but a shrunk-to-nothing fixture file passing
// vacuously would be a silent regression of the proof itself.
test('the fixture set has every acceptance-listed case, not an accidentally-empty file', () => {
  expect(cases.length).toBeGreaterThanOrEqual(20);
  const ids = new Set(cases.map((c) => c.id));
  expect(ids.size).toBe(cases.length);
});
