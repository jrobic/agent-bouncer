import { describe, expect, test } from 'bun:test';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpDir } from './tmp.ts';

const SCRIPT = join(import.meta.dir, '..', 'scripts', 'brew-formula.sh');
const BOUNCER_CAVEATS = join(import.meta.dir, '..', 'scripts', 'homebrew-caveats.txt');
const DESCRIPTION = 'Guard coding-agent tool calls with declarative policy';
const DARWIN_SHA = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const LINUX_SHA = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

type FormulaOptions = {
  caveatsFile?: string | null;
  description?: string;
  homepage?: string;
  name?: string;
  omittedChecksumTarget?: string;
  repo?: string;
  targets?: readonly string[];
};

type ProcessResult = {
  exitCode: number;
  stderr: string;
  stdout: string;
};

async function runScript(args: readonly string[]): Promise<ProcessResult> {
  const child = Bun.spawn(['/bin/bash', SCRIPT, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

async function runFormula({
  caveatsFile = BOUNCER_CAVEATS,
  description = DESCRIPTION,
  homepage = 'https://github.com/jrobic/agent-bouncer',
  name = 'bouncer',
  omittedChecksumTarget,
  repo = 'jrobic/agent-bouncer',
  targets = ['darwin-arm64', 'linux-x64'],
}: FormulaOptions = {}): Promise<ProcessResult> {
  const assets = join(tmpDir('bouncer-brew-formula-'), 'assets');
  await mkdir(assets, { recursive: true });
  if (omittedChecksumTarget !== 'darwin-arm64') {
    await writeFile(join(assets, `${name}-1.1.0-darwin-arm64.tar.gz.sha256`), `${DARWIN_SHA}  ${name}-1.1.0-darwin-arm64.tar.gz\n`);
  }
  if (omittedChecksumTarget !== 'linux-x64') {
    await writeFile(join(assets, `${name}-1.1.0-linux-x64.tar.gz.sha256`), `${LINUX_SHA}  ${name}-1.1.0-linux-x64.tar.gz\n`);
  }

  const targetArgs: string[] = [];
  for (const target of targets) {
    targetArgs.push('--target', target);
  }
  const caveatArgs = caveatsFile === null ? [] : ['--caveats-file', caveatsFile];
  return runScript([
    '--name',
    name,
    '--repo',
    repo,
    '--version',
    '1.1.0',
    '--desc',
    description,
    '--homepage',
    homepage,
    '--license',
    'MIT',
    '--assets',
    assets,
    ...targetArgs,
    ...caveatArgs,
  ]);
}

async function rubySyntax(formula: string): Promise<ProcessResult> {
  const formulaPath = join(tmpDir('bouncer-brew-formula-ruby-'), 'bouncer.rb');
  await writeFile(formulaPath, formula);
  const child = Bun.spawn(['ruby', '-c', formulaPath], { stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

async function rubyStringValue(literal: string): Promise<ProcessResult> {
  const child = Bun.spawn(['ruby', '-e', `puts ${literal}`], { stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe('scripts/brew-formula.sh', () => {
  test('renders the bouncer formula byte-for-byte from target checksums', async () => {
    const result = await runFormula();

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe(`# Supported: macOS Apple Silicon, Linux x64 — other platforms: build from the checkout (README)
class Bouncer < Formula
  desc "${DESCRIPTION}"
  homepage "https://github.com/jrobic/agent-bouncer"
  version "1.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/jrobic/agent-bouncer/releases/download/v1.1.0/bouncer-1.1.0-darwin-arm64.tar.gz"
      sha256 "${DARWIN_SHA}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/jrobic/agent-bouncer/releases/download/v1.1.0/bouncer-1.1.0-linux-x64.tar.gz"
      sha256 "${LINUX_SHA}"
    end
  end

  def install
    bin.install "bouncer"
  end

  def caveats
    <<~EOS
      bouncer is installed at #{HOMEBREW_PREFIX}/bin/bouncer. Wire that path,
      never the Cellar path, into your harness (\`bouncer doctor\` checks it).
      pi/omp users: the printed extension bakes the absolute binary path; under
      Homebrew that path changes on upgrade. Export
      BOUNCER_BIN=#{HOMEBREW_PREFIX}/bin/bouncer in your shell, or reprint the
      extension after each upgrade (\`bouncer harness shim pi-agent\`).
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bouncer --version")
  end
end
`);

    const ruby = await rubySyntax(result.stdout);
    expect(ruby.exitCode).toBe(0);
    expect(ruby.stdout).toBe('Syntax OK\n');
    expect(ruby.stderr).toBe('');
  });

  test('rejects an option without a value before consuming it', async () => {
    const results = await Promise.all([
      runScript(['--name']),
      runScript(['--name', '--repo', 'x']),
    ]);

    for (const result of results) {
      expect(result.exitCode).toBe(2);
      expect(result.stdout).toBe('');
      expect(result.stderr).toStartWith('usage: ');
    }
  });

  test('escapes Ruby metadata without evaluating interpolation', async () => {
    const description = 'Guard "coding-agent" #{injected} C:\\tools';
    const result = await runFormula({ description });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('desc "Guard \\"coding-agent\\" \\#{injected} C:\\\\tools"');

    const ruby = await rubySyntax(result.stdout);
    expect(ruby.exitCode).toBe(0);
    const descriptionLine = result.stdout.split('\n').find((line) => line.startsWith('  desc '));
    if (descriptionLine === undefined) {
      throw new Error('rendered formula has no desc');
    }
    const evaluated = await rubyStringValue(descriptionLine.slice('  desc '.length));
    expect(evaluated.exitCode).toBe(0);
    expect(evaluated.stdout).toBe(`${description}\n`);
  });

  test('rejects an unsupported release target', async () => {
    const result = await runFormula({ targets: ['freebsd-x64'] });

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('error: unsupported target: freebsd-x64\n');
  });

  test('fails when a requested target has no checksum asset', async () => {
    const result = await runFormula({
      omittedChecksumTarget: 'linux-x64',
      targets: ['linux-x64'],
    });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('error: missing checksum:');
    expect(result.stderr).toContain('bouncer-1.1.0-linux-x64.tar.gz.sha256');
  });

  test('renders a hyphenated formula without bouncer caveats by default', async () => {
    const result = await runFormula({
      caveatsFile: null,
      name: 'my-cli',
      homepage: 'https://github.com/example/my-cli',
      repo: 'example/my-cli',
      targets: ['darwin-arm64'],
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toStartWith(
      '# Supported: macOS Apple Silicon — other platforms: build from the checkout (README)\nclass MyCli < Formula\n',
    );
    expect(result.stdout).toContain('bin.install "my-cli"');
    expect(result.stdout).not.toMatch(/bouncer/i);
  });
});
