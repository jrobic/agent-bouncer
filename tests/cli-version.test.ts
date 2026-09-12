import { describe, expect, test } from 'bun:test';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { BOUNCER_VERSION } from '../src/build-info.ts';
import { tmpDir } from './tmp.ts';

interface SourceCliResult {
  readonly exitCode: number;
  readonly stdout: string;
}

async function runSourceCli(args: readonly string[], env?: Record<string, string>): Promise<SourceCliResult> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', ...args], { stdout: 'pipe', env: { ...process.env, ...env } });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  return { exitCode, stdout };
}

describe('bouncer --version', () => {
  test('source mode identifies itself honestly through both aliases', async () => {
    const version = await runSourceCli(['--version']);
    const alias = await runSourceCli(['-V']);

    expect(version.exitCode).toBe(0);
    expect(version.stdout).toMatch(
      new RegExp(`^bouncer ${BOUNCER_VERSION.replaceAll('.', '\\.')} \\(source, uncommitted build info\\) baseline [0-9a-f]{12}\\n$`),
    );
    expect(alias).toEqual(version);
  });

  test('--json exposes the documented source build schema', async () => {
    const result = await runSourceCli(['--version', '--json']);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      name: 'bouncer',
      version: BOUNCER_VERSION,
      build: { sha: 'source', dirty: null, date: null },
      policy: { baseline: expect.stringMatching(/^[0-9a-f]{12}$/) },
    });
  });

  test('--version keeps the embedded baseline digest when an account overlay exists', async () => {
    const configDir = tmpDir('bouncer-version-overlay-');
    await mkdir(join(configDir, 'bouncer'), { recursive: true });
    await writeFile(
      join(configDir, 'bouncer', 'policy.toml'),
      '[[override]]\nrule = "curl-file-upload"\naction = "disable"\nreason = "version command must not load this overlay"\n',
      'utf8',
    );

    const baseline = JSON.parse((await runSourceCli(['--version', '--json'])).stdout);
    const withOverlay = JSON.parse((await runSourceCli(['--version', '--json'], { CLAUDE_CONFIG_DIR: configDir })).stdout);
    expect(withOverlay.policy.baseline).toBe(baseline.policy.baseline);
  });
});
