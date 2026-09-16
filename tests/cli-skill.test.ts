import { expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import packageJson from '../package.json';
import { renderSkill } from '../src/adapter/skill.ts';

const SOURCE_PATH = new URL('../skills/bouncer-policy/SKILL.md', import.meta.url);
const VERSION_PLACEHOLDER = 'bouncer_version: __BOUNCER_VERSION__';

type SourceCliResult = {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
};

async function runSourceCli(args: readonly string[]): Promise<SourceCliResult> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', ...args], {
    cwd: new URL('..', import.meta.url).pathname,
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

test('renders the policy skill byte-for-byte except for its literal version substitution', async () => {
  const source = await readFile(SOURCE_PATH, 'utf8');

  const rendered = renderSkill('policy', '$&');

  expect(rendered).toBe(source.replace(VERSION_PLACEHOLDER, () => 'bouncer_version: $&'));
  expect(rendered).toBeDefined();
  expect(rendered?.endsWith('\n')).toBe(true);
  expect(rendered?.endsWith('\n\n')).toBe(false);
});

test('prints the version-matched policy skill through the source CLI', async () => {
  const [source, result] = await Promise.all([readFile(SOURCE_PATH, 'utf8'), runSourceCli(['skill', 'policy'])]);

  expect(result).toEqual({
    exitCode: 0,
    stdout: source.replace(VERSION_PLACEHOLDER, () => `bouncer_version: ${packageJson.version}`),
    stderr: '',
  });
});

test.each([
  ['missing id', ['skill']],
  ['unknown id', ['skill', 'nope']],
  ['inherited object property', ['skill', 'constructor']],
  ['extra argument', ['skill', 'policy', '--json']],
])('rejects a %s skill invocation without writing stdout', async (_caseName, args) => {
  const result = await runSourceCli(args);

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toBe('');
  expect(result.stderr).toStartWith('bouncer: ');
  expect(result.stderr).toContain('policy');
});
