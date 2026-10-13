import { describe, expect, test } from 'bun:test';
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpDir } from './tmp.ts';

const PROJECT_ROOT = new URL('..', import.meta.url).pathname;
const BUILT_BINARY = join(PROJECT_ROOT, 'dist', 'bouncer');

type SourceCliResult = {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
};

async function runSourceCli(args: readonly string[]): Promise<SourceCliResult> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', ...args], { cwd: PROJECT_ROOT, stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe('bouncer harness shim', () => {
  describe('without --bin, on the compiled binary run through a symlink', () => {
    let builtOnce: Promise<void> | undefined;
    async function ensureBuilt(): Promise<void> {
      builtOnce ??= (async () => {
        const build = Bun.spawn(['bun', 'run', 'build'], { cwd: PROJECT_ROOT, stdout: 'ignore', stderr: 'ignore' });
        expect(await build.exited).toBe(0);
      })();
      return builtOnce;
    }

    async function printThrough(argv: readonly string[], env: Record<string, string>): Promise<SourceCliResult> {
      const child = Bun.spawn([...argv], { stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } });
      const [exitCode, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      return { exitCode, stdout, stderr };
    }

    function linkedBouncer(): { readonly binDir: string; readonly link: string; } {
      const binDir = join(tmpDir('bouncer-shim-invoked-'), 'bin');
      mkdirSync(binDir, { recursive: true });
      const link = join(binDir, 'bouncer');
      symlinkSync(BUILT_BINARY, link);
      return { binDir, link };
    }

    test('bakes the symlink path it was invoked through, absolute', async () => {
      await ensureBuilt();
      const { link } = linkedBouncer();

      const result = await printThrough([link, 'harness', 'shim', 'pi-agent'], {});

      expect(result).toMatchObject({ exitCode: 0, stderr: '' });
      expect(result.stdout).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(link)};`);
    });

    test('bakes the symlink path it was found at through PATH, by bare name', async () => {
      await ensureBuilt();
      const { binDir, link } = linkedBouncer();

      const result = await printThrough(['/bin/sh', '-c', 'bouncer harness shim pi-agent'], {
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
      });

      expect(result).toMatchObject({ exitCode: 0, stderr: '' });
      expect(result.stdout).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(link)};`);
    });
  });

  test('bakes the literal absolute path supplied with --bin', async () => {
    const result = await runSourceCli(['harness', 'shim', 'pi-agent', '--bin', '/x/bouncer']);

    expect(result).toMatchObject({ exitCode: 0, stderr: '' });
    expect(result.stdout).toContain('const BOUNCER = process.env.BOUNCER_BIN ?? "/x/bouncer";');
  });

  test.each([
    ['missing value', ['harness', 'shim', 'pi-agent', '--bin']],
    ['relative path', ['harness', 'shim', 'pi-agent', '--bin', 'bouncer']],
    ['repeated flag', ['harness', 'shim', 'pi-agent', '--bin', '/x/bouncer', '--bin', '/y/bouncer']],
  ])('rejects a %s --bin argument', async (_caseName, args) => {
    const result = await runSourceCli(args);

    expect(result).toMatchObject({ exitCode: 1, stdout: '' });
    expect(result.stderr).toMatch(/^bouncer: harness shim --bin /);
  });
});
