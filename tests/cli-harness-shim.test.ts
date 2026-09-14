import { describe, expect, test } from 'bun:test';

const PROJECT_ROOT = new URL('..', import.meta.url).pathname;

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
  test('bakes the source process path by default', async () => {
    const result = await runSourceCli(['harness', 'shim', 'pi-agent']);

    expect(result).toMatchObject({ exitCode: 0, stderr: '' });
    expect(result.stdout).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(process.execPath)};`);
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
