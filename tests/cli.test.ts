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
