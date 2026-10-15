// The `shim-file` wiring codec (src/adapter/codecs/wiring/shim-file.ts,
// ADR-0006 § 6/7) — exercised the same way tests/adapter-
// doctor.test.ts exercises hook-file and tests/adapter-codecs-codex-hooks.
// test.ts exercises codex-hooks: real scratch trees on disk, through
// runDoctorChecks (never the codec's own internals directly), so this is
// a proof of what `bouncer doctor --harness pi-agent` actually reports.

import { describe, expect, test } from 'bun:test';
import { chmod, lstat, mkdir, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { buildSessionStartContext, type DoctorReport, formatDoctorChecklist, runDoctorChecks } from '../src/adapter/doctor.ts';
import { renderShim } from '../src/adapter/shim.ts';
import { runPrintCanary } from '../src/cli-commands.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { LoadResult } from '../src/policy/load.ts';
import type { HarnessDeclaration } from '../src/policy/schema.ts';
import { tmpDir } from './tmp.ts';

const PI_AGENT_HARNESS: HarnessDeclaration = BASELINE.rules.harness.find((h) => h.id === 'pi-agent')!;

const PROJECT_ROOT = join(import.meta.dir, '..');

type SourceCliResult = {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
};

async function printShimWithBin(bouncerPath: string): Promise<SourceCliResult> {
  const child = Bun.spawn(['bun', 'run', 'src/cli.ts', 'harness', 'shim', 'pi-agent', '--bin', bouncerPath], {
    cwd: PROJECT_ROOT,
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

function cleanLoadResult(): LoadResult {
  return {
    policy: BASELINE.rules,
    effectiveRules: [],
    overlayApplied: false,
    overlayFiles: [],
    activeOverrides: [],
    activeRelaxations: [],
    overlayHarnessIds: [],
    layers: [],
    warnings: [],
  };
}

function scratchAgentDir(): string {
  return tmpDir('bouncer-shim-file-test-');
}

async function writeExecutableBouncer(dir: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  const path = join(dir, 'fake-bouncer');
  await writeFile(path, '#!/bin/sh\nexit 0\n', 'utf8');
  await chmod(path, 0o755);
  return path;
}

async function writeShimFile(agentDir: string, content: string): Promise<string> {
  const extensionsDir = join(agentDir, 'extensions');
  await mkdir(extensionsDir, { recursive: true });
  const path = join(extensionsDir, 'bouncer.ts');
  await writeFile(path, content, 'utf8');
  return path;
}

describe('shim-file wiring: identical to the printed shim', () => {
  test('wiring:shim and wiring:binary both pass', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({ ok: true, message: `${bouncerPath} is executable` });
      // shim-file carries no per-event settings shape — no top-level
      // "settings" check exists at all for this wiring codec.
      expect(report.checks.find((c) => c.id === 'settings')).toBeUndefined();
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: a stable symlink baked through --bin', () => {
  test('wiring:shim preserves the symlink spelling while wiring:binary follows its target', async () => {
    const agentDir = scratchAgentDir();
    try {
      const targetPath = await writeExecutableBouncer(agentDir);
      const stablePath = join(agentDir, 'bouncer');
      await symlink(targetPath, stablePath);
      const printed = await printShimWithBin(stablePath);
      expect(printed).toMatchObject({ exitCode: 0, stderr: '' });
      expect(printed.stdout).toContain(`const BOUNCER = process.env.BOUNCER_BIN ?? ${JSON.stringify(stablePath)};`);
      await writeShimFile(agentDir, printed.stdout);
      process.env.PI_CODING_AGENT_DIR = agentDir;

      const resolvedReport = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(resolvedReport.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(resolvedReport.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: true,
        message: `${stablePath} is executable`,
      });

      await unlink(targetPath);
      expect((await lstat(stablePath)).isSymbolicLink()).toBe(true);

      const brokenReport = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(brokenReport.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(brokenReport.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: `${stablePath} is not executable (or does not exist) — every tool call would fail closed`,
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: a versioned Homebrew Cellar path baked into the shim', () => {
  async function cellarBakedDoctor(prefixName: string): Promise<{ readonly prefix: string; readonly report: DoctorReport; }> {
    const agentDir = scratchAgentDir();
    const prefix = join(agentDir, prefixName);
    const cellarBin = await writeExecutableBouncer(join(prefix, 'Cellar', 'bouncer', '9.9.9', 'bin'));
    const printed = await printShimWithBin(cellarBin);
    expect(printed).toMatchObject({ exitCode: 0, stderr: '' });
    await writeShimFile(agentDir, printed.stdout);
    process.env.PI_CODING_AGENT_DIR = agentDir;
    try {
      return { prefix, report: await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS) };
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  }

  test('wiring:shim passes, wiring:binary fails naming the stable --bin to reprint with', async () => {
    const { prefix, report } = await cellarBakedDoctor('brew');

    expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
    const binary = report.checks.find((c) => c.id === 'wiring:binary')!;
    expect(binary.ok).toBe(false);
    expect(binary.message).toContain('brew upgrade');
    expect(binary.message).toContain(`bouncer harness shim pi-agent --bin ${prefix}/bin/fake-bouncer`);
  });

  test('a prefix that is not a plain path gets the instruction without a pasteable command', async () => {
    const { report } = await cellarBakedDoctor('my brew');

    const binary = report.checks.find((c) => c.id === 'wiring:binary')!;
    expect(binary.ok).toBe(false);
    expect(binary.message).toContain('brew upgrade');
    expect(binary.message).not.toContain('--bin /');
  });
});

describe('shim-file wiring: drifted (one byte edited)', () => {
  test('wiring:shim fails, names the reprint command; wiring:binary still passes (BOUNCER path untouched)', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      const source = renderShim('pi-agent', bouncerPath)!;
      await writeShimFile(agentDir, source.replace('failing closed', 'FAILING CLOSED'));
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('bouncer harness shim pi-agent'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({ ok: true });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: absent', () => {
  test('wiring:shim fails, names the print command; wiring:binary reports "cannot verify"', async () => {
    const agentDir = scratchAgentDir();
    try {
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('bouncer harness shim pi-agent'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify'),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: non-executable BOUNCER', () => {
  test('wiring:shim passes (the file matches byte for byte); wiring:binary fails', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = join(agentDir, 'not-executable-bouncer');
      await writeFile(bouncerPath, 'not a real binary', 'utf8');
      await chmod(bouncerPath, 0o644);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining(bouncerPath),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: a file that is not a printed shim at all', () => {
  test('no BOUNCER line found: wiring:shim fails naming the reprint, wiring:binary "cannot verify"', async () => {
    const agentDir = scratchAgentDir();
    try {
      await writeShimFile(agentDir, 'export default function (pi) { /* not a real shim */ }\n');
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('reprint it'),
      });
      expect(report.checks.find((c) => c.id === 'wiring:binary')).toMatchObject({
        ok: false,
        message: expect.stringContaining('cannot verify'),
      });
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: policy and log checks are unaffected (ADR-0006 § 6: "leaves policy/log unchanged")', () => {
  test('policy and log checks still run and pass alongside the two shim checks', async () => {
    const agentDir = scratchAgentDir();
    try {
      const bouncerPath = await writeExecutableBouncer(agentDir);
      await writeShimFile(agentDir, renderShim('pi-agent', bouncerPath)!);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const report = await runDoctorChecks(undefined, cleanLoadResult(), PI_AGENT_HARNESS);
      expect(report.checks.find((c) => c.id === 'policy')).toMatchObject({ ok: true });
      expect(report.checks.find((c) => c.id === 'log')).toMatchObject({ ok: true });
      expect(report.ok).toBe(true);
    } finally {
      delete process.env.PI_CODING_AGENT_DIR;
    }
  });
});

describe('shim-file wiring: doctor --print-canary', () => {
  test('the "no canary entry" error names the ACTUAL harness id, not a literal "<id>" placeholder', async () => {
    const printed = await runPrintCanary(undefined, 'pi-agent');
    expect(printed.ok).toBe(false);
    if (printed.ok) throw new Error('expected an error result');
    expect(printed.error).toContain('bouncer harness shim pi-agent');
    expect(printed.error).not.toContain('<id>');
  });
});

// omp resolves OMP_PROFILE / PI_PROFILE / `--profile` to
// `~/.omp/profiles/<name>/agent` and discovers extensions under THAT agent
// directory only — measured live on omp 18.9.1: the
// printed shim installed in `~/.omp/agent/extensions` never loads in a
// profiled session. A profile without its own copy is a session that runs
// without bouncer, so `doctor --harness pi-agent` reports each profile it
// can see. Same seam as above: real scratch trees through runDoctorChecks.
// `~` is the scratch tree: every `~` of a doctor run — the default account
// directory's, the profiles root's — goes through one processHome()
// (src/adapter/log-path.ts), the process's HOME, which the helper below
// reassigns. Nothing here ever reaches the workstation's own `~/.omp`.

/** A scratch HOME shaped like an omp install: its DEFAULT agent directory carries the current shim, so the default wiring passes. `currentShim` is what a profile needs to be current too. */
async function scratchOmpHome(): Promise<{ readonly home: string; readonly currentShim: string; }> {
  const home = tmpDir('bouncer-shim-profiles-test-');
  const bouncerPath = await writeExecutableBouncer(home);
  const currentShim = renderShim('pi-agent', bouncerPath)!;
  await writeShimFile(join(home, '.omp', 'agent'), currentShim);
  return { home, currentShim };
}

function profileAgentDir(home: string, name: string): string {
  return join(home, '.omp', 'profiles', name, 'agent');
}

interface DoctorOptions {
  /** PI_CODING_AGENT_DIR for the run — what a profiled omp session exports (the profile's agent directory); unset by default, so the default account directory is the scratch `~/.omp/agent`. */
  readonly accountDir?: string;
  /** `doctor --settings <path>`: the explicit shim path to check instead of `<accountDir>/extensions/bouncer.ts`. */
  readonly shimPath?: string;
  /** The harness declaration to check; pi-agent's own by default. */
  readonly harness?: HarnessDeclaration;
}

async function doctorUnder(home: string, { accountDir, shimPath, harness = PI_AGENT_HARNESS }: DoctorOptions = {}): Promise<DoctorReport> {
  const originalHome = process.env.HOME;
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.HOME = home;
  if (accountDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = accountDir;
  try {
    return await runDoctorChecks(shimPath, cleanLoadResult(), harness);
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
  }
}

const defaultWiringOf = (report: DoctorReport) => report.checks.filter((c) => c.id === 'wiring:shim' || c.id === 'wiring:binary');
const profileChecksOf = (report: DoctorReport) => report.checks.filter((c) => c.id.startsWith('wiring:shim (profile'));

/** What a profile's `[fail]` tells the operator to run — spelled the way the declaration spells `~`, never a scratch path. */
const installCommandFor = (name: string) =>
  `mkdir -p ~/.omp/profiles/${name}/agent/extensions && bouncer harness shim pi-agent > ~/.omp/profiles/${name}/agent/extensions/bouncer.ts`;

describe('shim-file wiring: omp profiles', () => {
  test('1 profile without the shim: [fail] naming the reprint command for that profile; the default directory result is unchanged', async () => {
    const { home } = await scratchOmpHome();
    const before = await doctorUnder(home);
    await mkdir(profileAgentDir(home, 'work'), { recursive: true });
    const after = await doctorUnder(home);

    expect(profileChecksOf(before)).toEqual([]);
    expect(defaultWiringOf(after)).toEqual(defaultWiringOf(before));
    expect(profileChecksOf(after)).toEqual([
      {
        id: 'wiring:shim (profile work)',
        ok: false,
        message: expect.stringContaining(installCommandFor('work')),
        otherSession: `another omp profile has no Bouncer shim: work — install it with \`${installCommandFor('work')}\``,
      },
    ]);
    expect(after.ok).toBe(false);
  });

  test('1 profile with the current shim: [pass]; the default directory result is unchanged', async () => {
    const { home, currentShim } = await scratchOmpHome();
    const before = await doctorUnder(home);
    const shimPath = await writeShimFile(profileAgentDir(home, 'work'), currentShim);
    const after = await doctorUnder(home);

    expect(defaultWiringOf(after)).toEqual(defaultWiringOf(before));
    // One `~` for the whole run: the default account directory and the profiles root sit under the same home.
    expect(after.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
      message: `${join(home, '.omp', 'agent', 'extensions', 'bouncer.ts')} matches the printed shim`,
    });
    expect(profileChecksOf(after)).toEqual([{
      id: 'wiring:shim (profile work)',
      ok: true,
      message: `${shimPath} matches the printed shim`,
    }]);
    expect(after.ok).toBe(true);
  });

  test('1 profile with a stale shim: [fail] with the drift message of the default directory; the default directory result is unchanged', async () => {
    const { home, currentShim } = await scratchOmpHome();
    const before = await doctorUnder(home);
    await writeShimFile(profileAgentDir(home, 'work'), currentShim.replace('failing closed', 'FAILING CLOSED'));
    const after = await doctorUnder(home);

    expect(defaultWiringOf(after)).toEqual(defaultWiringOf(before));
    expect(profileChecksOf(after)).toEqual([
      {
        id: 'wiring:shim (profile work)',
        ok: false,
        message: 'extensions/bouncer.ts differs from `bouncer harness shim pi-agent`; reprint it',
        otherSession: `another omp profile carries a stale Bouncer shim: work — reprint it with \`${installCommandFor('work')}\``,
      },
    ]);
    expect(after.ok).toBe(false);
  });

  test('0 profiles, a profiles directory that is absent and then one that is empty: no profile line, the report is the one before profile checks', async () => {
    const { home } = await scratchOmpHome();
    const absent = await doctorUnder(home);
    await mkdir(join(home, '.omp', 'profiles'), { recursive: true });
    const empty = await doctorUnder(home);

    expect(profileChecksOf(absent)).toEqual([]);
    expect(empty).toEqual(absent);
  });

  test('a profile with the shim and a profile without it are reported independently, in name order', async () => {
    const { home, currentShim } = await scratchOmpHome();
    const before = await doctorUnder(home);
    await writeShimFile(profileAgentDir(home, 'work'), currentShim);
    await mkdir(profileAgentDir(home, 'client'), { recursive: true });
    const after = await doctorUnder(home);

    expect(defaultWiringOf(after)).toEqual(defaultWiringOf(before));
    expect(profileChecksOf(after).map(({ id, ok }) => ({ id, ok }))).toEqual([
      { id: 'wiring:shim (profile client)', ok: false },
      { id: 'wiring:shim (profile work)', ok: true },
    ]);
  });

  test('only a directory holding an agent directory is a profile: a stray file, a folder never launched and a file named agent are not', async () => {
    const { home } = await scratchOmpHome();
    const before = await doctorUnder(home);
    const profiles = join(home, '.omp', 'profiles');
    await mkdir(join(profiles, 'draft'), { recursive: true });
    await mkdir(join(profiles, 'odd'), { recursive: true });
    await writeFile(join(profiles, 'odd', 'agent'), 'a file, not an agent directory', 'utf8');
    await writeFile(join(profiles, '.DS_Store'), '', 'utf8');
    const after = await doctorUnder(home);

    expect(after).toEqual(before);
  });

  test('a folder whose name omp refuses can never run, so it is not a profile: nothing is reported for it, nothing can be forged through it', async () => {
    const { home } = await scratchOmpHome();
    const baseline = await doctorUnder(home);
    // Measured on omp 18.9.1: `omp --profile=<name>` exits 1 ("Invalid OMP profile …") for every one of these.
    const refused = [
      'x\n[pass] wiring:shim (profile forged)\u001b[31m $(touch pwned)', // a newline, an ESC and `$(…)`
      'a b',
      '-dash',
      '_under',
      '.hidden',
      'work.',
      'a'.repeat(65), // outside ^[a-z0-9][a-z0-9._-]{0,63}$, or a trailing dot
      'con',
      'CON.txt',
      'aux.txt',
      'com1',
      'lpt9',
      'prn',
      'nul', // Windows reserved device names, with or without an extension
      'default', // omp reads it as "no profile": the default agent directory, never profiles/default
    ];
    await Promise.all(refused.map((name) => mkdir(profileAgentDir(home, name), { recursive: true })));

    expect(await doctorUnder(home)).toEqual(baseline);
  });

  test('the rule is omp\'s, no stricter: names one step inside it are profiles, in name order', async () => {
    const { home } = await scratchOmpHome();
    const accepted = ['0abc', 'a'.repeat(64), 'client', 'com10', 'con-x', 'console', 'w.o-r_k'];
    await Promise.all(accepted.map((name) => mkdir(profileAgentDir(home, name), { recursive: true })));

    expect(profileChecksOf(await doctorUnder(home)).map(({ id }) => id)).toEqual(accepted.map((name) => `wiring:shim (profile ${name})`));
  });

  test('a folder spelled with capitals is a profile: omp is launched with the lowercase spelling, which a case-insensitive filesystem (the macOS default) opens', async () => {
    const { home } = await scratchOmpHome();
    await mkdir(profileAgentDir(home, 'Work'), { recursive: true });

    expect(profileChecksOf(await doctorUnder(home)).map(({ id }) => id)).toEqual(['wiring:shim (profile Work)']);
  });

  test('what is still printed from the file system is escaped: a control character in the home path never reaches a profile line', async () => {
    const { home: plainHome, currentShim } = await scratchOmpHome();
    const home = join(plainHome, 'ho\nme'); // HOME itself carries a newline
    await writeShimFile(join(home, '.omp', 'agent'), currentShim);
    await writeShimFile(profileAgentDir(home, 'work'), currentShim);
    const [check] = profileChecksOf(await doctorUnder(home));

    expect(check).toMatchObject({ id: 'wiring:shim (profile work)', ok: true });
    expect(check!.message).not.toMatch(/\p{Cc}/u);
    expect(check!.message).toContain('ho\\u{a}me');
  });

  test('a declared profiles directory that is not plain text gets the instruction, never a command built from it', async () => {
    const { home } = await scratchOmpHome();
    // An overlay-declared witness with a space in it: its profiles live in `~/my tools/profiles`.
    const spacey: HarnessDeclaration = { ...PI_AGENT_HARNESS, env: [], witness: '~/my tools/agent' };
    await mkdir(join(home, 'my tools', 'profiles', 'work', 'agent'), { recursive: true });
    const [check] = profileChecksOf(await doctorUnder(home, { harness: spacey }));

    const instruction = 'install it with `bouncer harness shim pi-agent` written to that profile\'s agent/extensions/bouncer.ts';
    expect(check).toMatchObject({ id: 'wiring:shim (profile work)', ok: false });
    expect(check!.message).toEndWith(instruction);
    expect(check!.message).not.toContain('mkdir');
    expect(check!.otherSession).toBe(`another omp profile has no Bouncer shim: work — ${instruction}`);
  });

  // root ignores permission bits: a directory it cannot read does not exist for it.
  test.skipIf(process.getuid?.() === 0)(
    'a profiles directory that cannot be listed is a [fail], never silence: its profiles cannot be vouched for',
    async () => {
      const { home } = await scratchOmpHome();
      const profiles = join(home, '.omp', 'profiles');
      await mkdir(join(profiles, 'work', 'agent'), { recursive: true });
      await chmod(profiles, 0o000);
      const report = await doctorUnder(home);

      expect(profileChecksOf(report)).toEqual([
        {
          id: 'wiring:shim (profiles)',
          ok: false,
          message:
            '~/.omp/profiles is unreadable (EACCES) — the profile agent directories under it cannot be checked, so sessions under them may run without bouncer',
          otherSession: 'omp profiles cannot be checked, they may run without Bouncer: ~/.omp/profiles is unreadable (EACCES)',
        },
      ]);
    },
  );

  test('an explicit shim path (`doctor --settings <path>`) checks that file only: no profile is enumerated', async () => {
    const { home, currentShim } = await scratchOmpHome();
    await mkdir(profileAgentDir(home, 'work'), { recursive: true });
    const shimPath = await writeShimFile(join(home, 'pinned'), currentShim);
    const report = await doctorUnder(home, { shimPath });

    expect(profileChecksOf(report)).toEqual([]);
    expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({ ok: true, message: `${shimPath} matches the printed shim` });
  });

  test.each([
    ['an absolute path', (home: string) => profileAgentDir(home, 'work')],
    ['a leading ~', () => '~/.omp/profiles/work/agent'],
  ])(
    'in a profiled session (omp exports the profile\'s agent directory as PI_CODING_AGENT_DIR, here %s) that profile is reported once, by the default lines; its siblings still are',
    async (_spelling, accountDirFor) => {
      const { home, currentShim } = await scratchOmpHome();
      await writeShimFile(profileAgentDir(home, 'work'), currentShim.replace('failing closed', 'FAILING CLOSED'));
      await mkdir(profileAgentDir(home, 'client'), { recursive: true });
      const report = await doctorUnder(home, { accountDir: accountDirFor(home) });

      expect(report.checks.find((c) => c.id === 'wiring:shim')).toMatchObject({
        ok: false,
        message: expect.stringContaining('differs from'),
      });
      expect(profileChecksOf(report).map(({ id }) => id)).toEqual(['wiring:shim (profile client)']);
    },
  );

  test('a failing profile is announced on a line of its own, never as this session being unguarded', async () => {
    const { home, currentShim } = await scratchOmpHome();
    await mkdir(profileAgentDir(home, 'work'), { recursive: true });
    await writeShimFile(profileAgentDir(home, 'client'), currentShim.replace('failing closed', 'FAILING CLOSED'));
    const notice = buildSessionStartContext(await doctorUnder(home))!;

    expect(notice.split('\n')).toEqual(expect.arrayContaining([
      `bouncer doctor: another omp profile carries a stale Bouncer shim: client — reprint it with \`${installCommandFor('client')}\``,
      `bouncer doctor: another omp profile has no Bouncer shim: work — install it with \`${installCommandFor('work')}\``,
    ]));
    // The scream is a claim about THIS session, whose own wiring is healthy here.
    expect(notice).not.toContain('WIRING/POLICY PROBLEM DETECTED');
    expect(notice).not.toContain('unguarded');
  });

  test('a session whose own shim is stale still gets the scream — about itself only; a failing profile stays on its own line', async () => {
    const { home, currentShim } = await scratchOmpHome();
    await writeShimFile(join(home, '.omp', 'agent'), currentShim.replace('failing closed', 'FAILING CLOSED'));
    await mkdir(profileAgentDir(home, 'work'), { recursive: true });
    const notice = buildSessionStartContext(await doctorUnder(home))!;

    expect(notice).toContain('bouncer doctor: WIRING/POLICY PROBLEM DETECTED — this session may be running partially or fully unguarded.');
    expect(notice).toContain('  - wiring:shim: extensions/bouncer.ts differs from');
    expect(notice).not.toContain('  - wiring:shim (profile');
    expect(notice).toContain('bouncer doctor: another omp profile has no Bouncer shim: work — ');
  });

  test('a profile whose shim file cannot be read is announced as unreadable, not as stale', async () => {
    const { home } = await scratchOmpHome();
    await mkdir(join(profileAgentDir(home, 'work'), 'extensions', 'bouncer.ts'), { recursive: true }); // a directory where the file should be
    const [check] = profileChecksOf(await doctorUnder(home));

    expect(check).toMatchObject({ id: 'wiring:shim (profile work)', ok: false, message: expect.stringContaining('unreadable') });
    expect(check!.otherSession).toStartWith('another omp profile\'s Bouncer shim cannot be read: work — ');
  });

  test('the checklist form is unchanged by the notice wording: one [fail] line per profile, with the reason it runs without bouncer', async () => {
    const { home } = await scratchOmpHome();
    await mkdir(profileAgentDir(home, 'work'), { recursive: true });
    const checklist = formatDoctorChecklist(await doctorUnder(home)).split('\n');

    expect(checklist).toContain(
      '[fail] wiring:shim (profile work) — extensions/bouncer.ts is missing — a session under this profile loads nothing from the default agent '
        + `directory and runs without bouncer; install it with \`${installCommandFor('work')}\``,
    );
  });
});
