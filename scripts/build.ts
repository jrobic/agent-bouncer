#!/usr/bin/env bun

interface PackageJson {
  readonly version?: unknown;
}

async function commandOutput(args: string[]): Promise<string> {
  const process = Bun.spawn(args, { stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(`${args.join(' ')} failed: ${stderr.trim()}`);
  return stdout.trim();
}

function utcBuildDate(): string {
  return `${new Date().toISOString().slice(0, 16)}Z`;
}

async function build(): Promise<void> {
  const [rawPackage, sha, status] = await Promise.all([
    Bun.file('package.json').json() as Promise<PackageJson>,
    commandOutput(['git', 'rev-parse', '--short', 'HEAD']),
    commandOutput(['git', 'status', '--porcelain']),
  ]);
  if (typeof rawPackage.version !== 'string') throw new Error('package.json has no string version');

  const result = await Bun.build({
    entrypoints: ['./src/cli.ts'],
    compile: { outfile: './dist/bouncer' },
    define: {
      BOUNCER_BUILD: JSON.stringify({
        sha,
        dirty: status !== '',
        date: utcBuildDate(),
        version: rawPackage.version,
      }),
    },
  });
  if (!result.success) throw new Error(result.logs.map((log) => log.message).join('\n'));

  const checksum = await commandOutput(['shasum', '-a', '256', 'dist/bouncer']);
  await Bun.write('dist/bouncer.sha256', `${checksum}\n`);
}

await build();
