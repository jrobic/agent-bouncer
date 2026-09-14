import { describe, expect, test } from 'bun:test';
import { chmod, copyFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpDir } from './tmp.ts';

const SCRIPT = join(import.meta.dir, '..', 'scripts', 'changelog-section.sh');

const CHANGELOG = `# Changelog

## [Unreleased]

## [1.2.0] - 2026-09-14

### Added

- A thing.

- Another thing after a blank line.


## [1.1.0] - 2026-09-01

### Fixed

- Something.

[Unreleased]: https://example.test/compare/v1.2.0...HEAD
`;

async function runSection(version?: string): Promise<{ exitCode: number; stdout: string; stderr: string; }> {
  const root = tmpDir('bouncer-changelog-section-');
  await mkdir(join(root, 'scripts'), { recursive: true });
  await copyFile(SCRIPT, join(root, 'scripts', 'changelog-section.sh'));
  await chmod(join(root, 'scripts', 'changelog-section.sh'), 0o755);
  await writeFile(join(root, 'CHANGELOG.md'), CHANGELOG);
  const child = Bun.spawn(['/bin/bash', join(root, 'scripts', 'changelog-section.sh'), ...(version === undefined ? [] : [version])], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe('scripts/changelog-section.sh', () => {
  test('prints exactly one version section, trimmed, stopping before the next heading', async () => {
    const result = await runSection('1.2.0');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('### Added\n\n- A thing.\n\n- Another thing after a blank line.\n');
  });

  test('refuses a version without a section so no empty release body is published', async () => {
    const result = await runSection('9.9.9');
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('no section for version 9.9.9');
  });

  test('refuses an empty section (an Unreleased heading with nothing under it)', async () => {
    const result = await runSection('Unreleased');
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
  });
});
