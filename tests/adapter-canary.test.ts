import { describe, expect, test } from 'bun:test';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { buildCanaryCommand, CANARY_REASON } from '../src/adapter/canary.ts';
import { tmpDir } from './tmp.ts';

const PROJECT_ROOT = join(import.meta.dir, '..');

describe('canonical canary command', () => {
  test('a missing binary emits a parseable deny and exits successfully', async () => {
    const home = tmpDir('bouncer-canary-home-');
    const configDir = join(home, 'config');
    await mkdir(configDir);
    const command = buildCanaryCommand(join(home, 'bin', 'bouncer'));
    const canary = Bun.spawn(['/bin/sh', '-c', command], {
      env: { ...process.env, HOME: home, CLAUDE_CONFIG_DIR: configDir },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const stdout = await new Response(canary.stdout).text();

    expect(await canary.exited).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: CANARY_REASON,
      },
    });
  });

  test('a freshly built binary leaves the canary silent', async () => {
    const build = Bun.spawn(['bun', 'run', 'build'], {
      cwd: PROJECT_ROOT,
      stdout: 'ignore',
      stderr: 'ignore',
    });
    expect(await build.exited).toBe(0);

    const home = tmpDir('bouncer-canary-home-');
    const configDir = join(home, 'config');
    await mkdir(configDir);
    const command = buildCanaryCommand(join(PROJECT_ROOT, 'dist', 'bouncer'));
    const canary = Bun.spawn(['/bin/sh', '-c', command], {
      env: { ...process.env, HOME: home, CLAUDE_CONFIG_DIR: configDir },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const stdout = await new Response(canary.stdout).text();

    expect(await canary.exited).toBe(0);
    expect(stdout).toBe('');
  });
});
