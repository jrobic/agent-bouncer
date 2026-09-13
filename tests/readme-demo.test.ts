import { expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { tmpDir } from './tmp.ts';

const DEMO_START = '<!-- demo:start -->';
const DEMO_END = '<!-- demo:end -->';
const TRUST_START = '<!-- trust:start -->';
const TRUST_END = '<!-- trust:end -->';
const DEMO_COMMANDS = [
  'rm -rf /',
  'git push --force origin main',
  'cat ~/.ssh/id_ed25519',
  'echo x > ~/.zshrc',
  'ls -la',
] as const;

interface SourceVersion {
  readonly version: string;
  readonly policy: {
    readonly baseline: string;
  };
}

async function runSourceCheck(command: string, env: Record<string, string>): Promise<string> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', 'check', command], {
    env: { ...process.env, ...env },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(exitCode).toBe(0);
  expect(stderr).toBe('');
  return stdout;
}

async function sourceVersionInfo(): Promise<SourceVersion> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', '--version', '--json'], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(exitCode).toBe(0);
  expect(stderr).toBe('');
  return JSON.parse(stdout) as SourceVersion;
}

test('README demo is byte-for-byte output from an empty-profile source CLI', async () => {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  expect(readme.split(DEMO_START)).toHaveLength(2);
  expect(readme.split(DEMO_END)).toHaveLength(2);
  const start = readme.indexOf(DEMO_START);
  const end = readme.indexOf(DEMO_END);

  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);

  if (start < 0 || end <= start) throw new Error('README demo markers are missing or out of order');

  const markedDemo = readme.slice(start + DEMO_START.length, end);
  const codeBlock = markedDemo.match(/^\n```console\n([\s\S]*?)```\n$/);

  expect(codeBlock).not.toBeNull();
  if (codeBlock === null) throw new Error('README demo must be a console fence');

  const home = tmpDir('bouncer-readme-demo-home-');
  const configDir = tmpDir('bouncer-readme-demo-config-');
  const env = { HOME: home, CLAUDE_CONFIG_DIR: configDir };
  const actual = (
    await Promise.all(
      DEMO_COMMANDS.map(async (command) => `$ bouncer check ${JSON.stringify(command)}\n${await runSourceCheck(command, env)}`),
    )
  ).join('');

  expect(codeBlock[1]).toBe(actual);
});

test('README trust sample names the current embedded baseline digest', async () => {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  expect(readme.split(TRUST_START)).toHaveLength(2);
  expect(readme.split(TRUST_END)).toHaveLength(2);
  const start = readme.indexOf(TRUST_START);
  const end = readme.indexOf(TRUST_END);

  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);

  if (start < 0 || end <= start) throw new Error('README trust markers are missing or out of order');

  const version = await sourceVersionInfo();
  const trustSample = readme.slice(start + TRUST_START.length, end);

  // Compiled SHA and date vary by build, so the README marks them as example values.
  expect(trustSample).toContain(
    `bouncer ${version.version} (example build SHA, built example UTC time) baseline ${version.policy.baseline}`,
  );
  expect(trustSample).toContain(`"version":"${version.version}"`);
  expect(trustSample).toContain(`"baseline":"${version.policy.baseline}"`);
});
