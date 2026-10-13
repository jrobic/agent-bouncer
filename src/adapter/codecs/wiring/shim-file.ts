// The `shim-file` wiring codec (ADR-0006 § 6/7, ticket 15c): doctor's
// "was the printed shim cut, drifted, or never installed" detection for
// an in-process harness (pi-agent, omp). Unlike hook-file/codex-hooks,
// there is no per-event settings shape to read here — pi-agent/omp never
// write stdin themselves, the ONE installed shim relays every event the
// declaration names uniformly, so there is no separate "PreToolUse
// wired"/"canary" concept to check per event; two checks instead, plus
// one `wiring:shim` per omp profile (ticket 56, below):
//
// - `wiring:shim` — the installed `<dir>/extensions/bouncer.ts` exists
//   and is byte-identical to what `bouncer harness shim <id>` prints
//   TODAY, rendered with the SAME `BOUNCER` path the installed copy
//   ALREADY carries (never this doctor process's own `process.execPath`
//   — a doctor run from a different checkout must never claim drift
//   solely because its own binary happens to live somewhere else; compare
//   AFTER substitution, per the ticket's own contract).
// - `wiring:binary` — that baked `BOUNCER` path resolves to an
//   executable file (the one thing the shim itself cannot verify at
//   spawn time without literally trying, which is exactly what its own
//   fail-closed spawn-failure branch already covers live), outside a
//   versioned Homebrew Cellar directory.

import { access, constants as fsConstants, readdir, readFile, stat } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import type { HarnessDeclaration } from '../../../policy/schema.ts';
import type { DoctorCheck } from '../../doctor.ts';
import { configDirFor, expandHome } from '../../log-path.ts';
import { renderShim } from '../../shim.ts';

/** `<configDir>/extensions/bouncer.ts` — this codec's own file, under the target harness's account directory. */
export function shimPathFor(harness: HarnessDeclaration): string {
  return join(configDirFor(harness), 'extensions', 'bouncer.ts');
}

export type ShimReadResult =
  | { readonly kind: 'absent'; }
  | { readonly kind: 'ok'; readonly content: string; }
  | { readonly kind: 'corrupt'; readonly detail: string; };

export async function readShimFile(shimPath: string): Promise<ShimReadResult> {
  try {
    const content = await readFile(shimPath, 'utf8');
    return { kind: 'ok', content };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') return { kind: 'absent' };
    const detail = err instanceof Error ? err.message : String(err);
    return { kind: 'corrupt', detail: `unreadable: ${detail}` };
  }
}

// The installed shim's own baked `BOUNCER` path, read back out — the
// printed source's ONE substitution point
// (`const BOUNCER = process.env.BOUNCER_BIN ?? "<path>";`), inverted.
// `undefined` when the line is missing entirely (a hand-edited or
// unrelated file) — `checkShim`'s own drift message already names that,
// this just has nothing further to extract for `wiring:binary`.
const BOUNCER_LINE = /const BOUNCER = process\.env\.BOUNCER_BIN \?\? ("(?:[^"\\]|\\.)*");/;

export function extractBouncerPath(shimContent: string): string | undefined {
  const match = BOUNCER_LINE.exec(shimContent);
  if (match === null) return undefined;
  try {
    const parsed: unknown = JSON.parse(match[1]!);
    return typeof parsed === 'string' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

// `shimPath` names the resolved location in the two messages that never
// reach a SessionStart scream (`corrupt` — a genuine read error, rare
// enough that no committed fixture exercises it; `ok` — never rendered
// at all, success is silent) — useful there for a human running
// `bouncer doctor` manually. The three FAILURE messages that CAN reach
// a SessionStart scream (`absent`, the two "not a real shim" cases, and
// `drift`) instead name the fixed, harness-neutral relative label
// (`extensions/bouncer.ts`, matching this ticket's own exact expected
// wording) — a resolved scratch-account path there would make
// `fixtures/protocol/pi-agent.json`'s own captured SessionStart-broken
// case unreproducible byte for byte (a fresh temp dir every capture).
const SHIM_LABEL = 'extensions/bouncer.ts';
const SHIM_CHECK_ID = 'wiring:shim';

export function checkShim(result: ShimReadResult, shimPath: string, harnessId: string): DoctorCheck {
  const id = SHIM_CHECK_ID;
  if (result.kind === 'corrupt') {
    return { id, ok: false, message: `${shimPath} ${result.detail}` };
  }
  if (result.kind === 'absent') {
    return {
      id,
      ok: false,
      message: `${SHIM_LABEL} is missing — print it with \`bouncer harness shim ${harnessId}\` and write it there`,
    };
  }
  const bouncerPath = extractBouncerPath(result.content);
  if (bouncerPath === undefined) {
    return {
      id,
      ok: false,
      message: `${SHIM_LABEL} does not look like a printed bouncer shim (no BOUNCER path found) — reprint it`,
    };
  }
  const canonical = renderShim(harnessId, bouncerPath);
  if (canonical === undefined) {
    return { id, ok: false, message: `harness ${JSON.stringify(harnessId)} has no embedded shim to compare against` };
  }
  if (result.content !== canonical) {
    return { id, ok: false, message: `${SHIM_LABEL} differs from \`bouncer harness shim ${harnessId}\`; reprint it` };
  }
  return { id, ok: true, message: `${shimPath} matches the printed shim` };
}

// `brew upgrade` deletes `<prefix>/Cellar/<formula>/<old version>`;
// `<prefix>/bin/<exe>` survives it.
const CELLAR_BIN_PATH = /^(.*)\/Cellar\/[^/]+\/[^/]+\/bin\/([^/]+)$/;

export async function checkShimBinary(result: ShimReadResult, harnessId: string): Promise<DoctorCheck> {
  const id = 'wiring:binary';
  if (result.kind !== 'ok') {
    return { id, ok: false, message: 'cannot verify — the shim itself is unreadable/missing (see wiring:shim)' };
  }
  const bouncerPath = extractBouncerPath(result.content);
  if (bouncerPath === undefined) {
    return { id, ok: false, message: 'cannot verify — no BOUNCER path found in the installed shim (see wiring:shim)' };
  }
  try {
    await access(bouncerPath, fsConstants.X_OK);
  } catch {
    return {
      id,
      ok: false,
      message: `${bouncerPath} is not executable (or does not exist) — every tool call would fail closed`,
    };
  }
  const cellar = CELLAR_BIN_PATH.exec(bouncerPath);
  if (cellar !== null) {
    const [, prefix, exe] = cellar;
    const stable = `${prefix}/bin/${exe}`;
    const reprint = PASTE_SAFE_PATH.test(stable)
      ? `reprint it with \`bouncer harness shim ${harnessId} --bin ${stable}\``
      : `reprint it with \`bouncer harness shim ${harnessId}\` and \`--bin\` set to the stable bin/${exe} symlink next to that Cellar directory`;
    const risk = 'the next `brew upgrade` removes it and every tool call then fails closed';
    return {
      id,
      ok: false,
      message: `${printable(bouncerPath)} is a versioned Homebrew Cellar path — ${risk}; ${reprint}`,
    };
  }
  return { id, ok: true, message: `${bouncerPath} is executable` };
}

// Ticket 56 — omp profiles.
//
// omp's profile layout, measured on omp 18.9.1 (docs/how-to/wire-into-pi-
// agent.md § omp profiles): a profile `<name>` has its OWN agent directory,
// `<root>/profiles/<name>/agent`, a sibling of the default agent directory
// `<root>/agent`, and a profiled session loads extensions from that
// directory only — never from the default one. So a harness whose declared
// default account directory (`witness`) is `<root>/agent` has its profiles
// under `<root>/profiles`, and each of them needs its own copy of the
// shim. A witness of any other shape names no layout this codec knows: no
// profile to report.
//
// The root comes from the declaration — never a hard-coded `~/.omp` — and
// never from PI_CODING_AGENT_DIR (under a profile omp ignores it and
// exports the profile's own agent directory in its place, measured). `~` is
// expanded by the same expandHome() as the default account directory's, one
// processHome() (log-path.ts), so the two can never disagree.
const OMP_AGENT_DIR = 'agent';
const OMP_PROFILES_DIR = 'profiles';

interface ProfilesRoot {
  /** The resolved directory to read. */
  readonly dir: string;
  /** The declaration's own spelling (`~/.omp/profiles`) — what a message prints, never a resolved scratch path. */
  readonly display: string;
}

function profilesRootFor(harness: HarnessDeclaration): ProfilesRoot | undefined {
  if (basename(harness.witness) !== OMP_AGENT_DIR) return undefined;
  const display = join(dirname(harness.witness), OMP_PROFILES_DIR);
  return { dir: expandHome(display), display };
}

// omp's profile-name rule, measured on omp 18.9.1: `omp --profile=Work`
// exits 1 with `Error: Invalid OMP profile "Work". Profile names must match
// ^[a-z0-9][a-z0-9._-]{0,63}$, cannot be "." or "..", cannot end with ".",
// and cannot be a Windows reserved device name (CON, PRN, AUX, NUL, COM0-9,
// LPT0-9, or any of those with an extension).`; and `OMP_PROFILE=default`
// opens the default agent directory, never `profiles/default` (a marker
// extension in each: only the default directory's loaded). A folder named
// outside that rule is one no session can open: it is no profile, and
// reporting it would be a standing false alarm — a failing line in every
// session's notice, for a folder that cannot run.
//
// Case is the one place this errs towards reporting: omp refuses `Work`,
// but launched as `work` it opens `profiles/Work/agent` on a
// case-insensitive filesystem (the macOS default — measured: the extension
// of a `Work/agent` folder loaded under OMP_PROFILE=work), so the rule
// judges the LOWERCASED folder name. On a case-sensitive filesystem such a
// folder can never run and is listed anyway: a false alarm, never a hole.
const OMP_PROFILE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const WINDOWS_DEVICE_NAME = /^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?$/i;
const OMP_DEFAULT_PROFILE = 'default';

function ompCanOpenProfileFolder(folder: string): boolean {
  const name = folder.toLowerCase();
  return OMP_PROFILE_NAME.test(name) && !name.endsWith('.') && !WINDOWS_DEVICE_NAME.test(name) && name !== OMP_DEFAULT_PROFILE;
}

// A folder name that passed the rule above holds no control character, but
// the rest of a profile line is still file system text — a path built from
// the home directory, an OS error's message — and a line the operator
// reads, their terminal and a model's context must neither be forged nor
// drive the terminal: control, format and line/paragraph-separator
// characters are rendered `\u{hex}`.
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

function printable(text: string): string {
  return text.replace(UNPRINTABLE, (char) => `\\u{${char.codePointAt(0)!.toString(16)}}`);
}

// A command the operator will paste is only ever built from a path of plain
// characters — no space, quote, `$`, backtick, glob or control character —
// rooted at `~/` or `/`. A folder name that passed omp's rule is plain by
// construction; the part that is not is the declaration's own spelling of
// the profiles directory (an overlay may declare any witness).
const PASTE_SAFE_PATH = /^(?:~\/|\/)[A-Za-z0-9._/-]+$/;

/** What puts the current shim into one profile: the command, or — when the path is not plain — the instruction without one. */
function printShimInto(harnessId: string, extensionsDir: string): string {
  return PASTE_SAFE_PATH.test(extensionsDir)
    ? `\`mkdir -p ${extensionsDir} && bouncer harness shim ${harnessId} > ${extensionsDir}/bouncer.ts\``
    : `\`bouncer harness shim ${harnessId}\` written to that profile's agent/extensions/bouncer.ts`;
}

// Two texts for one fact, both about a profile: `message` is the checklist
// line (what the shim check found, for the operator at a shell) and
// `otherSession` the SessionStart notice's sentence — its own wording,
// because the scream's "this session may be running unguarded" would be
// false of a session that is guarded (doctor.ts's DoctorCheck).
async function checkProfileShim(harness: HarnessDeclaration, root: ProfilesRoot, folder: string): Promise<DoctorCheck | undefined> {
  // omp creates `agent/` the first time a profile launches: a folder
  // without one (never launched) or a stray file holds no extension a
  // session could load, so it is not reported.
  const agentDir = join(root.dir, folder, OMP_AGENT_DIR);
  if (!await stat(agentDir).then((entry) => entry.isDirectory(), () => false)) return undefined;
  const shimPath = join(agentDir, 'extensions', 'bouncer.ts');
  const result = await readShimFile(shimPath);
  const name = printable(folder);
  const id = `${SHIM_CHECK_ID} (profile ${name})`;
  const printIt = printShimInto(harness.id, join(root.display, folder, OMP_AGENT_DIR, 'extensions'));
  if (result.kind === 'absent') {
    return {
      id,
      ok: false,
      message:
        `${SHIM_LABEL} is missing — a session under this profile loads nothing from the default agent directory and runs without bouncer; `
        + `install it with ${printIt}`,
      otherSession: `another omp profile has no Bouncer shim: ${name} — install it with ${printIt}`,
    };
  }
  const check = checkShim(result, shimPath, harness.id);
  const message = printable(check.message);
  if (check.ok) return { ...check, id, message };
  // A readable file that is not the printed shim — drifted, hand-edited or
  // not a shim at all — is "stale": one remedy, reprint it. An unreadable
  // one cannot be vouched for, and says so.
  const otherSession = result.kind === 'corrupt'
    ? `another omp profile's Bouncer shim cannot be read: ${name} — ${message}`
    : `another omp profile carries a stale Bouncer shim: ${name} — reprint it with ${printIt}`;
  return { ...check, id, message, otherSession };
}

/**
 * One `wiring:shim (profile <name>)` check per profile of the harness found
 * on disk — none when there is no profiles directory. A directory that
 * exists but cannot be listed is a failure, never silence: the sessions
 * under it cannot be vouched for.
 */
export async function checkProfileShims(harness: HarnessDeclaration): Promise<readonly DoctorCheck[]> {
  const root = profilesRootFor(harness);
  if (root === undefined) return [];
  let folders: string[];
  try {
    folders = (await readdir(root.dir)).toSorted();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return [];
    const unreadable = `${printable(root.display)} is unreadable (${code ?? 'unknown error'})`;
    return [{
      id: `${SHIM_CHECK_ID} (profiles)`,
      ok: false,
      message: `${unreadable} — the profile agent directories under it cannot be checked, so sessions under them may run without bouncer`,
      otherSession: `omp profiles cannot be checked, they may run without Bouncer: ${unreadable}`,
    }];
  }
  // The profile THIS session runs under is not "another" one: omp exports
  // its agent directory as PI_CODING_AGENT_DIR (measured) — the account
  // directory configDirFor() already resolves, read here as everywhere,
  // with no PI_CODING_AGENT_DIR handling of its own — so the default
  // `wiring:shim` lines already inspect it.
  const active = configDirFor(harness);
  const checks = await Promise.all(
    folders
      .filter((folder) => ompCanOpenProfileFolder(folder) && join(root.dir, folder, OMP_AGENT_DIR) !== active)
      .map((folder) => checkProfileShim(harness, root, folder)),
  );
  return checks.filter((check) => check !== undefined);
}
