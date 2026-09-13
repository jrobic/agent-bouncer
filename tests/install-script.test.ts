import { describe, expect, test } from 'bun:test';
import { chmod, copyFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpDir } from './tmp.ts';

const INSTALL_SCRIPT = join(import.meta.dir, '..', 'scripts', 'install.sh');

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };

type CommandResult = {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
};

type ArtifactOptions = {
  readonly checksum?: 'invalid' | 'valid';
  readonly doctorExit?: number;
  readonly dirty?: boolean;
  readonly manifestPath?: 'bouncer' | 'dist/bouncer';
  readonly sha: string;
  readonly version?: string;
  readonly versionAvailable?: boolean;
  readonly versionJson?: string;
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
  const repo = tmpDir('bouncer-install-script-repo-');
  await git(repo, 'init', '-q');
  await git(repo, 'config', 'user.name', 'Install Script Test');
  await git(repo, 'config', 'user.email', 'install-script@example.test');
  await mkdir(join(repo, 'scripts'), { recursive: true });
  await copyFile(INSTALL_SCRIPT, join(repo, 'scripts', 'install.sh'));
  await chmod(join(repo, 'scripts', 'install.sh'), 0o755);
  await git(repo, 'add', 'scripts/install.sh');
  await git(repo, 'commit', '-qm', 'add installer fixture');
  return { head: await git(repo, 'rev-parse', '--short', 'HEAD'), repo };
}

async function writeArtifact(options: ArtifactOptions): Promise<string> {
  const artifactDir = tmpDir('bouncer-install-script-artifact-');
  const binary = join(artifactDir, 'bouncer');
  const version = options.version ?? '2.3.4';
  const doctorExit = options.doctorExit ?? 0;
  const versionAvailable = options.versionAvailable ?? true;
  const versionJson = options.versionJson ?? JSON.stringify({
    name: 'bouncer',
    version,
    build: { sha: options.sha, dirty: options.dirty ?? false, date: '2026-09-12T00:00Z' },
    policy: { baseline: 'fixture' },
  });
  const versionHandler = versionAvailable
    ? `printf '%s\\n' '${versionJson}'\n  exit 0`
    : 'exit 64';

  await writeFile(
    binary,
    `#!/usr/bin/env bash
if [ "${'$'}{1:-}" = "--version" ] && [ "${'$'}{2:-}" = "--json" ]; then
  ${versionHandler}
fi
if [ "${'$'}{1:-}" = "doctor" ]; then
  exit ${doctorExit}
fi
exit 64
`,
    'utf8',
  );
  await chmod(binary, 0o755);

  const checksum = await run(['shasum', '-a', '256', 'bouncer'], { cwd: artifactDir });
  if (checksum.exitCode !== 0) throw new Error(`shasum failed: ${checksum.stderr}`);
  const expectedDigest = checksum.stdout.split(/\s+/)[0];
  const manifest = options.checksum === 'invalid'
    ? `${'0'.repeat(64)}  bouncer\n`
    : `${expectedDigest}  ${options.manifestPath ?? 'bouncer'}\n`;
  await writeFile(join(artifactDir, 'bouncer.sha256'), manifest, 'utf8');
  return artifactDir;
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function runInstaller(
  repo: string,
  artifactDir: string,
  destination: string,
  extraArgs: readonly string[] = [],
): Promise<CommandResult> {
  const home = tmpDir('bouncer-install-script-home-');
  return run(['/bin/bash', 'scripts/install.sh', '--from', artifactDir, '--dest', destination, ...extraArgs], {
    cwd: repo,
    env: { ...GIT_ENV, CLAUDE_CONFIG_DIR: join(home, 'claude'), HOME: home },
  });
}

describe('scripts/install.sh', () => {
  test('installs a fresh verified artifact at --dest with mode 0755', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'newbuild' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bin', 'bouncer');

    const result = await runInstaller(repo, artifactDir, destination);

    expect(result.exitCode).toBe(0);
    expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
    expect((await stat(destination)).mode & 0o777).toBe(0o755);
    expect(await exists(`${destination}.new`)).toBe(false);
  });

  test('installs a build-format manifest through --from', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ manifestPath: 'dist/bouncer', sha: 'buildformat' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');

    const result = await runInstaller(repo, artifactDir, destination);

    expect(result.exitCode).toBe(0);
    expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
  });

  test('uses --dest when HOME is unset', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'explicitdestination' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    const env: Record<string, string | undefined> = { ...GIT_ENV, CLAUDE_CONFIG_DIR: tmpDir('bouncer-install-script-config-') };
    delete env.HOME;

    const result = await run(['/bin/bash', 'scripts/install.sh', '--from', artifactDir, '--dest', destination], {
      cwd: repo,
      env,
    });

    expect(result.exitCode).toBe(0);
    expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
  });

  test('requires --dest when HOME is unset', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'missinghome' });
    const env: Record<string, string | undefined> = { ...GIT_ENV, CLAUDE_CONFIG_DIR: tmpDir('bouncer-install-script-config-') };
    delete env.HOME;

    const result = await run(['/bin/bash', 'scripts/install.sh', '--from', artifactDir], {
      cwd: repo,
      env,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('HOME is unset; pass --dest <path>');
  });

  test('installs at HOME default destination', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ sha: 'homedestination' });
    const home = tmpDir('bouncer-install-script-home-');
    const destination = join(home, '.local', 'bin', 'bouncer');

    const result = await run(['/bin/bash', 'scripts/install.sh', '--from', artifactDir], {
      cwd: repo,
      env: { ...GIT_ENV, CLAUDE_CONFIG_DIR: join(home, 'claude'), HOME: home },
    });

    expect(result.exitCode).toBe(0);
    expect((await stat(destination)).mode & 0o777).toBe(0o755);
  });

  test('backs up the installed build and retains only that backup generation', async () => {
    const { repo } = await createRepository();
    const installedArtifact = await writeArtifact({ sha: 'installed' });
    const newArtifact = await writeArtifact({ sha: 'replacement' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    await copyFile(join(installedArtifact, 'bouncer'), destination);
    await writeFile(`${destination}.older.bak`, 'older backup', 'utf8');

    const result = await runInstaller(repo, newArtifact, destination);

    expect(result.exitCode).toBe(0);
    expect(await readFile(`${destination}.installed.bak`)).toEqual(await readFile(join(installedArtifact, 'bouncer')));
    expect(await exists(`${destination}.older.bak`)).toBe(false);
    expect(await readFile(destination)).toEqual(await readFile(join(newArtifact, 'bouncer')));
  });

  test('adds -dirty to the backup name for a dirty installed build', async () => {
    const { repo } = await createRepository();
    const installedArtifact = await writeArtifact({ dirty: true, sha: 'installed' });
    const newArtifact = await writeArtifact({ sha: 'replacement' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    await copyFile(join(installedArtifact, 'bouncer'), destination);

    const result = await runInstaller(repo, newArtifact, destination);

    expect(result.exitCode).toBe(0);
    expect(await exists(`${destination}.installed-dirty.bak`)).toBe(true);
  });

  test('backs up a legacy installed binary as unknown', async () => {
    const { repo } = await createRepository();
    const legacyArtifact = await writeArtifact({ sha: 'legacy', versionAvailable: false });
    const newArtifact = await writeArtifact({ sha: 'replacement' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    await copyFile(join(legacyArtifact, 'bouncer'), destination);

    const result = await runInstaller(repo, newArtifact, destination);

    expect(result.exitCode).toBe(0);
    expect(await exists(`${destination}.unknown.bak`)).toBe(true);
  });

  test('backs up malformed installed metadata as unknown without parser output', async () => {
    const { repo } = await createRepository();
    const legacyArtifact = await writeArtifact({ sha: 'legacy', versionJson: 'not valid JSON' });
    const newArtifact = await writeArtifact({ sha: 'replacement' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    await copyFile(join(legacyArtifact, 'bouncer'), destination);

    const result = await runInstaller(repo, newArtifact, destination);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).not.toContain('SyntaxError');
    expect(await exists(`${destination}.unknown.bak`)).toBe(true);
  });

  test('refuses a dirty artifact until --allow-dirty is explicit', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ dirty: true, sha: 'dirtybuild' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
    await writeFile(destination, 'installed sentinel', 'utf8');

    const rejected = await runInstaller(repo, artifactDir, destination);

    expect(rejected.exitCode).toBe(1);
    expect(rejected.stderr).toContain('--allow-dirty');
    expect(await readFile(destination, 'utf8')).toBe('installed sentinel');

    const accepted = await runInstaller(repo, artifactDir, destination, ['--allow-dirty']);

    expect(accepted.exitCode).toBe(0);
    expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
  });

  test('aborts a checksum mismatch before creating the destination', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ checksum: 'invalid', sha: 'badchecksum' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');

    const result = await runInstaller(repo, artifactDir, destination);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('artifact checksum verification failed');
    expect(await exists(destination)).toBe(false);
  });

  test('returns doctor\'s exit code after installing the artifact', async () => {
    const { repo } = await createRepository();
    const artifactDir = await writeArtifact({ doctorExit: 3, sha: 'doctorfailure' });
    const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');

    const result = await runInstaller(repo, artifactDir, destination);

    expect(result.exitCode).toBe(3);
    expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
  });

  describe('--tag', () => {
    test('creates the artifact version tag on HEAD after installing', async () => {
      const { head, repo } = await createRepository();
      const artifactDir = await writeArtifact({ sha: head });
      const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');

      const result = await runInstaller(repo, artifactDir, destination, ['--tag']);

      expect(result.exitCode).toBe(0);
      expect(await git(repo, 'tag', '--list', 'v2.3.4')).toBe('v2.3.4');
      expect(await git(repo, 'cat-file', '-t', 'v2.3.4')).toBe('tag');
      expect(await git(repo, 'rev-parse', 'v2.3.4^{}')).toBe(await git(repo, 'rev-parse', 'HEAD'));
      expect(await readFile(destination)).toEqual(await readFile(join(artifactDir, 'bouncer')));
    });

    test('refuses an existing tag before copying', async () => {
      const { head, repo } = await createRepository();
      const artifactDir = await writeArtifact({ sha: head });
      const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
      await git(repo, 'tag', '-a', 'v2.3.4', '-m', 'existing tag');

      const result = await runInstaller(repo, artifactDir, destination, ['--tag']);

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('already exists');
      expect(await exists(destination)).toBe(false);
    });

    test('refuses a dirty repository before copying', async () => {
      const { head, repo } = await createRepository();
      const artifactDir = await writeArtifact({ sha: head });
      const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');
      await writeFile(join(repo, 'uncommitted.txt'), 'dirty tree', 'utf8');

      const result = await runInstaller(repo, artifactDir, destination, ['--tag']);

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('clean git tree');
      expect(await exists(destination)).toBe(false);
    });

    test('refuses an artifact that was not built from HEAD before copying', async () => {
      const { repo } = await createRepository();
      const artifactDir = await writeArtifact({ sha: 'wronghead' });
      const destination = join(tmpDir('bouncer-install-script-dest-'), 'bouncer');

      const result = await runInstaller(repo, artifactDir, destination, ['--tag']);

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('does not match HEAD');
      expect(await exists(destination)).toBe(false);
    });
  });

  test('shows usage and exits 0 for both help flags', async () => {
    const { repo } = await createRepository();
    const home = tmpDir('bouncer-install-script-home-');

    const results = await Promise.all(
      ['-h', '--help'].map((flag) =>
        run(['/bin/bash', 'scripts/install.sh', flag], {
          cwd: repo,
          env: { ...GIT_ENV, HOME: home },
        })
      ),
    );

    for (const result of results) {
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toContain('Usage:');
    }
  });

  test('reports usage and exits 2 for an unknown flag', async () => {
    const { repo } = await createRepository();
    const home = tmpDir('bouncer-install-script-home-');

    const result = await run(['/bin/bash', 'scripts/install.sh', '--unknown'], {
      cwd: repo,
      env: { ...GIT_ENV, HOME: home },
    });

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Usage:');
  });
});
