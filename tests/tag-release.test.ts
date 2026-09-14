import { describe, expect, test } from 'bun:test';
import { chmod, copyFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpDir } from './tmp.ts';

const TAG_RELEASE_SCRIPT = join(import.meta.dir, '..', 'scripts', 'tag-release.sh');

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };

type CommandResult = {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
};

type ArtifactOptions = {
  readonly checksum?: 'invalid';
  readonly dirty?: boolean;
  readonly manifestPath?: string;
  readonly sha: string;
  readonly version?: string;
};

async function run(
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Record<string, string | undefined>; } = {},
): Promise<CommandResult> {
  const child = Bun.spawn([...args], {
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    ...(options.env === undefined ? {} : { env: options.env }),
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

async function git(repo: string, ...args: string[]): Promise<string> {
  const result = await run(['git', '-C', repo, ...args], { env: GIT_ENV });
  if (result.exitCode !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout.trim();
}

async function createRepository(): Promise<{ readonly head: string; readonly repo: string; }> {
  const repo = tmpDir('bouncer-tag-release-repo-');
  await git(repo, 'init', '-q');
  await git(repo, 'config', 'user.name', 'Tag Release Test');
  await git(repo, 'config', 'user.email', 'tag-release-script@example.test');
  await mkdir(join(repo, 'scripts'), { recursive: true });
  await copyFile(TAG_RELEASE_SCRIPT, join(repo, 'scripts', 'tag-release.sh'));
  await chmod(join(repo, 'scripts', 'tag-release.sh'), 0o755);
  await git(repo, 'add', 'scripts/tag-release.sh');
  await git(repo, 'commit', '-qm', 'add tag release fixture');
  return { head: await git(repo, 'rev-parse', '--short', 'HEAD'), repo };
}

async function writeArtifact(options: ArtifactOptions): Promise<string> {
  const artifactDir = tmpDir('bouncer-tag-release-artifact-');
  const binary = join(artifactDir, 'bouncer');
  const version = options.version ?? '9.9.9';
  const versionJson = JSON.stringify({
    name: 'bouncer',
    version,
    build: { sha: options.sha, dirty: options.dirty ?? false, date: '2026-09-14T00:00Z' },
    policy: { baseline: 'fixture' },
  });

  await writeFile(
    binary,
    `#!/usr/bin/env bash
if [ "${'$'}{1:-}" = "--version" ]; then
  if [ "${'$'}{2:-}" = "--json" ]; then
    printf '%s\\n' '${versionJson}'
    exit 0
  fi
  printf '%s\\n' 'bouncer ${version} (fixture, built 2026-09-14T00:00Z) baseline fixture'
  exit 0
fi
exit 64
`,
    'utf8',
  );
  await chmod(binary, 0o755);

  const checksum = await run(['shasum', '-a', '256', binary]);
  if (checksum.exitCode !== 0) throw new Error(`shasum failed: ${checksum.stderr}`);
  const expectedDigest = checksum.stdout.split(/\s+/)[0];
  const manifestPath = options.manifestPath ?? binary;
  const manifest = options.checksum === 'invalid'
    ? `${'0'.repeat(64)}  ${manifestPath}\n`
    : `${expectedDigest}  ${manifestPath}\n`;
  await writeFile(join(artifactDir, 'bouncer.sha256'), manifest, 'utf8');
  return artifactDir;
}

function runTagRelease(repo: string, artifactDir: string, args: readonly string[] = []): Promise<CommandResult> {
  return run(['/bin/bash', 'scripts/tag-release.sh', ...args], {
    cwd: repo,
    env: { ...GIT_ENV, BOUNCER_ARTIFACT_DIR: artifactDir },
  });
}

async function expectNoTag(repo: string, version = '9.9.9'): Promise<void> {
  expect(await git(repo, 'tag', '--list', `v${version}`)).toBe('');
}

describe('scripts/tag-release.sh', () => {
  test('creates an annotated release tag on HEAD and prints the release identity', async () => {
    const { head, repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: head });

    const result = await runTagRelease(repo, artifactDir);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('v9.9.9\nbouncer 9.9.9 (fixture, built 2026-09-14T00:00Z) baseline fixture\n');
    expect(await git(repo, 'cat-file', '-t', 'v9.9.9')).toBe('tag');
    expect(await git(repo, 'rev-parse', 'v9.9.9^{}')).toBe(await git(repo, 'rev-parse', 'HEAD'));
  });

  test('refuses a dirty artifact without creating a tag', async () => {
    const { head, repo } = await createRepository();
    const artifactDir = await writeArtifact({ dirty: true, sha: head });

    const result = await runTagRelease(repo, artifactDir);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('a release tag never comes from a dirty tree');
    await expectNoTag(repo);
  });

  test('refuses an artifact that was not built from HEAD without creating a tag', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'wronghead' });

    const result = await runTagRelease(repo, artifactDir);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('does not match HEAD');
    await expectNoTag(repo);
  });

  test('refuses an existing release tag without replacing it', async () => {
    const { head, repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: head });
    await git(repo, 'tag', '-a', 'v9.9.9', '-m', 'existing release tag');
    const existingTag = await git(repo, 'rev-parse', 'v9.9.9^{}');

    const result = await runTagRelease(repo, artifactDir);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('tag v9.9.9 already exists');
    expect(await git(repo, 'rev-parse', 'v9.9.9^{}')).toBe(existingTag);
  });

  test('refuses a checksum mismatch before creating a tag', async () => {
    const { head, repo } = await createRepository();
    const artifactDir = await writeArtifact({ checksum: 'invalid', sha: head });

    const result = await runTagRelease(repo, artifactDir);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('artifact checksum verification failed');
    await expectNoTag(repo);
  });

  test('shows usage and exits 0 for both help flags', async () => {
    const { repo } = await createRepository();

    const results = await Promise.all(
      ['-h', '--help'].map((flag) => run(['/bin/bash', 'scripts/tag-release.sh', flag], { cwd: repo, env: GIT_ENV })),
    );

    for (const result of results) {
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toContain('Usage: scripts/tag-release.sh');
    }
  });

  test('reports usage and exits 2 for an unknown option', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'unused' });

    const result = await runTagRelease(repo, artifactDir, ['--unknown']);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Usage: scripts/tag-release.sh');
  });
});
