// Path canonicalization: closes the workstation's documented symlink bypass
// (secret-guard.ts resolved realpath() before checkPath; the ported engine
// had it nowhere — src, tests, or ticket 03/04). Both the unit-level
// canonicalizePath() behavior and the end-to-end run() bypass-closure are
// covered with a real symlink in a tmpdir, not a mocked fs.

import { describe, expect, test } from 'bun:test';
import { realpath, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalizePath } from '../src/adapter/paths.ts';
import { run } from '../src/adapter/run.ts';
import { tmpDir } from './tmp.ts';

// macOS's own tmpdir() is itself behind a symlink (/tmp -> /private/tmp), so
// the raw tmpDir() result is NOT canonical — realpath()ing it here once
// keeps every "expected" value in this file honest, independent of that
// platform quirk. canonicalizePath() itself is what is under test; this is
// test scaffolding, not a workaround for it.
async function freshDir(): Promise<string> {
  return await realpath(tmpDir('bouncer-paths-test-'));
}

describe('canonicalizePath: unit behavior', () => {
  test('resolves a symlink to its real target', async () => {
    const dir = await freshDir();
    const envPath = join(dir, '.env');
    const linkPath = join(dir, 'innocent-name.txt');
    await writeFile(envPath, 'SECRET=x');
    await symlink(envPath, linkPath);

    const resolved = await canonicalizePath(linkPath);
    expect(resolved).toBe(envPath);
  });

  test('falls back to lexical parent resolution when the target does not exist yet', async () => {
    const dir = await freshDir();
    const newFilePath = join(dir, 'not-created-yet.txt');

    const resolved = await canonicalizePath(newFilePath);
    expect(resolved).toBe(newFilePath);
  });

  test('resolves a symlinked PARENT directory even when the file itself is new', async () => {
    const dir = await freshDir();
    const realParent = join(dir, 'real-parent');
    const { mkdir } = await import('node:fs/promises');
    await mkdir(realParent);
    const linkedParent = join(dir, 'linked-parent');
    await symlink(realParent, linkedParent);

    // The file through the symlinked parent does not exist yet — only the
    // parent does. canonicalizePath must still resolve to the REAL parent.
    const resolved = await canonicalizePath(join(linkedParent, 'new-file.txt'));
    expect(resolved).toBe(join(realParent, 'new-file.txt'));
  });

  test('falls back to the lexical path when nothing on the chain exists', async () => {
    const resolved = await canonicalizePath('/definitely/does/not/exist/anywhere/x.txt');
    expect(resolved).toBe('/definitely/does/not/exist/anywhere/x.txt');
  });
});

describe('run(): the symlink bypass is closed end to end', () => {
  test('reading a symlink to .env through Read is denied', async () => {
    const dir = await freshDir();
    const envPath = join(dir, '.env');
    const linkPath = join(dir, 'safe-looking-name.txt');
    await writeFile(envPath, 'SECRET=x');
    await symlink(envPath, linkPath);

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: linkPath },
    });
    const { stdout } = await run(envelope);
    expect(stdout).not.toBeNull();
    const parsed = JSON.parse(stdout!);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain('dotenv');
  });

  test('a symlink to an ordinary, non-sensitive file is silent', async () => {
    const dir = await freshDir();
    const realPath = join(dir, 'notes.txt');
    const linkPath = join(dir, 'link-to-notes.txt');
    await writeFile(realPath, 'nothing sensitive here');
    await symlink(realPath, linkPath);

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: linkPath },
    });
    expect((await run(envelope)).stdout).toBeNull();
  });
});
