// readAndRun is cli.ts's testable core: main() wraps it with process.exit()
// side effects that would kill the test runner itself if exercised
// in-process, so this file tests readAndRun directly with an injected
// stdin reader instead of spawning a real subprocess.

import { describe, expect, test } from 'bun:test';
import { readAndRun } from '../src/cli.ts';

describe('readAndRun: an unreadable stdin fails open (by contract)', () => {
  test('a throwing reader produces no verdict, not a thrown error', async () => {
    const throwingReader = async (): Promise<string> => {
      throw new Error('EIO: simulated stdin read failure');
    };
    const result = await readAndRun(throwingReader);
    expect(result.stdout).toBeNull();
  });

  test('a normal reader still runs the envelope through as usual', async () => {
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    const result = await readAndRun(async () => envelope);
    expect(result.stdout).not.toBeNull();
    const parsed = JSON.parse(result.stdout!);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('deny');
  });
});

describe('readAndRun: ticket 08 — the { shadow: true } option main() builds from --shadow', () => {
  test('the same deny-worthy envelope produces no stdout when shadow is threaded through', async () => {
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    const result = await readAndRun(async () => envelope, { shadow: true });
    expect(result.stdout).toBeNull();
  });
});

describe('readAndRun: ticket 08 review — { unrecognizedTokens } main() builds from a typo\'d flag', () => {
  test('with a typo\'d token and shadow left false, the deny-worthy envelope still denies on stdout', async () => {
    // Mirrors main()'s own split: `rest.includes('--shadow')` stays false
    // for "--shadwo", so `shadow` is false and `unrecognizedTokens` carries
    // the typo — enforcement is never disarmed by an unrecognized token.
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    const result = await readAndRun(async () => envelope, { shadow: false, unrecognizedTokens: ['--shadwo'] });
    expect(result.stdout).not.toBeNull();
    expect(JSON.parse(result.stdout!).hookSpecificOutput.permissionDecision).toBe('deny');
  });
});
