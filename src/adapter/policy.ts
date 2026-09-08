// Resolves and loads the layered policy overlay (ADR-0001) — the common
// layer (harness-neutral, every adapter reads the same root) and the
// profile layer, whose root is now declaration-driven (ADR-0006 § 8)
// instead of hardcoded to Claude Code's `CLAUDE_CONFIG_DIR`: it is
// `<configDir>/bouncer/` for whichever harness `--harness <id>` (default
// `claude-code`) names. The parsing/merge/precedence/lint logic itself
// (src/policy/load.ts) has no opinion on where the files live and no
// filesystem access at all — src/policy/ stays I/O-free, this is the one
// adapter module that owns the `node:fs` reads.
//
// Two roots (ADR-0001 § Layers and discovery), same shape each: the
// single `policy.toml` (unchanged since ticket 06), then every
// `policy.d/*.toml` file, in lexicographic FILENAME order — a conf.d-style
// split for personal rules by theme (`10-npm.toml`, `20-client-x.toml`).
// Ordering itself is decided HERE (this is the one place with `readdir`),
// not in src/policy/load.ts, which just processes whatever file list it's
// given, in the order given.
//
// "Absent" vs "present but broken" is decided HERE too, per file, via the
// `optional` flag on readOverlayFile: `policy.toml` not existing yet is
// the normal, unconfigured case (silent, ENOENT and blank text both mean
// "no overlay"). A `policy.d/*.toml` entry is different — `readdir` just
// proved it exists, so it is never `optional`: ANY subsequent read
// failure (permission denied, a broken symlink, a directory entry, a
// TOCTOU race where it vanished between readdir and readFile — even
// ENOENT) is reported as a `readError`, which src/policy/load.ts rejects
// that file's whole LAYER over (ticket 21), naming the file. A file
// readdir proved present has no license to silently vanish.
//
// Migration guard (ADR-0001 § Rejection, ticket 21): this module also owns
// the ONE realpath check that has nothing to do with a broken file — the
// interim per-profile symlink (dotfiles ADR-0004) that used to make
// the common layer reachable before this native read existed. See
// migrationGuardWarning below.
//
// Declaration-driven routing (ADR-0006 § 8) is a two-phase resolution, not
// one read: which directory the PROFILE layer lives under depends on the
// TARGET harness's own `env`/`witness`, which is policy DATA — so phase 1
// loads baseline + the (harness-neutral) common layer alone, enough to
// resolve `harnessId` against the six baseline declarations plus anything
// the common layer itself declares or extends (ADR-0006 § 5: a NEW harness
// is introduced through the common layer, never the profile layer it
// would otherwise need to already know the root of — see
// resolveHarnessForProfile). Phase 2 then reads that harness's profile
// root and composes the full common+profile result exactly as before.
// `harness: undefined` on the return means `harnessId` is unknown to
// every layer — run.ts's exit-2 path, which never reaches a log because
// there is no declaration left to resolve one from.

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, sep } from 'node:path';
import { loadPolicyFromLayers, type LoadResult, type NamedLayer, type OverlayFile } from '../policy/load.ts';
import type { HarnessDeclaration } from '../policy/schema.ts';
import { profileRootFor } from './log-path.ts';

export interface HarnessLoadResult extends LoadResult {
  readonly harness: HarnessDeclaration | undefined;
}

// ~/.agents/bouncer/ — the common layer's root (ADR-0001 § Layers and
// discovery, Option 2): a harness-neutral convention derived straight from
// the home directory, never from any harness's own configDir (that is
// what makes it "common" rather than any one harness's own). No file
// anywhere names this root; every adapter reads the SAME one through this
// same helper.
//
// Reads `process.env.HOME` directly, on purpose, rather than node:os's
// homedir() — Bun resolves homedir() once at process boot (from the OS,
// not from `process.env.HOME`) and never re-reads it, so a test that
// reassigns `process.env.HOME` mid-process (tests/setup.ts sets a
// throwaway one globally; this machine's own dev account genuinely has a
// ~/.agents/bouncer/) would silently keep resolving to the REAL home. A
// non-empty HOME wins verbatim; homedir() is only the fallback for the
// (rare, but real outside test contexts) case where HOME itself is
// unset. GUARD FOR TEST AUTHORS: an empty OR deleted `process.env.HOME`
// both fall through to this SAME homedir() branch — this machine's own
// real home, not a safe default. A test must always REASSIGN `HOME` to
// another throwaway string in its own cleanup, exactly like
// tests/setup.ts's global preload does; never `delete process.env.HOME`
// or set it to `''` to "reset" it.
export function commonRoot(): string {
  const home = process.env.HOME;
  return join(home && home.trim() !== '' ? home : homedir(), '.agents', 'bouncer');
}

function errorCode(err: unknown): string | undefined {
  return err instanceof Error && 'code' in err ? String((err as NodeJS.ErrnoException).code) : undefined;
}

// `optional: true` is the root `policy.toml` contract — genuinely absent
// (ENOENT) or blank is "no overlay file", silently (matches the original,
// pre-ticket-12 single-file behavior exactly). `optional: false` is every
// `policy.d/*.toml` entry — readdir already proved it exists, so it never
// resolves to `null`; every failure, ENOENT included, comes back as a
// `readError` for load.ts to reject the whole set over, naming this file.
async function readOverlayFile(filename: string, path: string, optional: boolean): Promise<OverlayFile | null> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    if (optional && errorCode(err) === 'ENOENT') return null;
    const message = err instanceof Error ? err.message : String(err);
    return { filename, readError: message };
  }
  if (optional && text.trim() === '') return null;
  return { filename, text };
}

// Every `<subdir>/*.toml` file under `dir`, in lexicographic FILENAME
// order (not path, not mtime) — `10-npm.toml` before `20-client-x.toml`
// regardless of which was edited more recently. A missing or unreadable
// directory is "no files there", not a failure (there is nothing readdir
// proved exists in that case). Read in parallel — order is preserved by
// `.map()`, not by await sequencing, so no `no-await-in-loop` concern.
// Shared by `policy.d/` (rule overlays) and `harness.d/` (ADR-0006 § 2:
// one `[[harness]]` block per file, same discovery shape) — both are
// just "every file under a named subdirectory", qualified with that
// subdirectory's own name so provenance reads `common:harness.d/acme.toml`
// exactly like `common:policy.d/10-npm.toml`.
async function readOverlaySubdirFiles(subdir: string, dir: string): Promise<OverlayFile[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const tomlNames = names.filter((n) => n.endsWith('.toml')).toSorted();
  const files = await Promise.all(
    tomlNames.map((name) => readOverlayFile(`${subdir}/${name}`, join(dir, name), false)),
  );
  return files.filter((f): f is OverlayFile => f !== null);
}

async function directoryExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

interface LayerRead {
  readonly files: readonly OverlayFile[];
  // The root path IFF it exists as a directory — undefined otherwise
  // (ADR-0001 § Provenance: "<name>: absent" vs. "<name>: N files", see
  // src/policy/load.ts's LayerInfo). Checked independently of whether the
  // root actually holds any overlay files — an existing-but-empty root is
  // a distinct, real state ("profile: 0 files"), never "absent".
  readonly root: string | undefined;
}

/**
 * Reads one layer's file SET off `root` — `policy.toml` (if present and
 * non-blank), then every `policy.d/*.toml` file, then every
 * `harness.d/*.toml` file (ADR-0006 § 2), each in lexicographic order —
 * AND whether `root` itself exists as a directory. Shared by the common
 * and profile roots (ADR-0001 § Layers and discovery: "both layers have
 * the same shape, read by one function over two roots").
 */
async function readLayer(root: string): Promise<LayerRead> {
  const [exists, primary, policyDirFiles, harnessDirFiles] = await Promise.all([
    directoryExists(root),
    readOverlayFile('policy.toml', join(root, 'policy.toml'), true),
    readOverlaySubdirFiles('policy.d', join(root, 'policy.d')),
    readOverlaySubdirFiles('harness.d', join(root, 'harness.d')),
  ]);
  const files = [...(primary !== null ? [primary] : []), ...policyDirFiles, ...harnessDirFiles];
  return { files, root: exists ? root : undefined };
}

function namedLayer(name: string, read: LayerRead): NamedLayer {
  return { name, ...(read.root !== undefined ? { root: read.root } : {}), files: read.files };
}

// `undefined` (never a thrown error) for a path that doesn't resolve at
// all — the normal case for a profile root/`policy.d` that isn't a link,
// or a common root nobody has set up on this machine.
async function tryRealpath(path: string): Promise<string | undefined> {
  try {
    return await realpath(path);
  } catch {
    return undefined;
  }
}

// ADR-0001 § Rejection, migration guard: the interim per-profile symlink
// (dotfiles ADR-0004) pointed `<configDir>/bouncer/policy.d` AT
// `~/.agents/bouncer/policy.d` directly, before this module's native
// common-layer read existed — the SAME mount also shows up as the
// profile ROOT itself being the link (`<configDir>/bouncer` -> the
// common root, no `policy.d` segment at all). Either shape loads the
// same files TWICE — once as "common", once as "profile" through the
// link, under a different qualified name each time (`profile:policy.toml
// shadows common:policy.toml`) — identical effective policy, lying
// provenance, exactly what this guard exists to kill. Checked by
// REALPATH, never a string compare of the configured paths themselves (a
// relative symlink, an extra hop, or two paths that just happen to
// differ textually while resolving to the same inode would all slip past
// that): when the profile ROOT's real path, OR its `policy.d`'s real
// path, IS the common root's real path or lives under it (equal or
// descendant), the WHOLE profile layer is dropped — not just `policy.d`;
// a profile root that's itself the link has nothing of its own left to
// keep. Neither candidate resolving at all (the common convention
// unused on this machine, or a fresh profile with nothing linked) is
// never a match — returns null, silently, the same "absent is normal"
// discipline every other output in this module already has.
async function migrationGuardWarning(commonRootPath: string, profileRootPath: string): Promise<string | null> {
  const candidates = [profileRootPath, join(profileRootPath, 'policy.d')];
  const [commonReal, candidateReals] = await Promise.all([
    tryRealpath(commonRootPath),
    Promise.all(candidates.map(tryRealpath)),
  ]);
  if (commonReal === undefined) return null; // no common root at all — nothing to guard against
  for (const [i, candidateReal] of candidateReals.entries()) {
    if (candidateReal === undefined) continue; // this candidate doesn't exist
    if (candidateReal === commonReal || candidateReal.startsWith(`${commonReal}${sep}`)) {
      return `profile policy resolves to the common root (${commonReal}) — remove the link (rm ${candidates[i]})`;
    }
  }
  return null;
}

/**
 * Reads and loads the effective, layered policy (ADR-0001, declaration-
 * routed per ADR-0006 § 8) — the common layer (commonRoot()) then the
 * TARGET harness's own profile layer, merged with the profile winning on
 * a shared target (src/policy/load.ts's loadPolicyFromLayers). No files
 * at all, in either layer, is treated exactly like "no overlay": silent,
 * no warning — an absent overlay (or an absent common layer alone) is the
 * normal, unconfigured case, not a failure. A `policy.d/*.toml` or
 * `harness.d/*.toml` entry that exists per `readdir` but fails to read is
 * NOT dropped silently — it flows through as a `readError` that
 * src/policy/load.ts rejects that file's layer over (ticket 21), naming
 * the file.
 *
 * `harnessId` unknown to the baseline AND the common layer resolves no
 * profile root at all — `harness` comes back `undefined`, `layers` names
 * only `common` (there is nothing to call `profile`), and the caller
 * (run.ts) takes the exit-2 path without ever trying to log anywhere.
 *
 * When the migration guard fires (migrationGuardWarning), the WHOLE
 * profile layer is excluded from what's given to the engine — its files
 * are still read off disk above (so `LayerInfo.root`/file count stay
 * accurate), just dropped before merge — and the guard's own message is
 * appended to `warnings` (which is what makes `doctor`/`rules lint` fail
 * on it, same as any other warning; see log.ts's logPolicyWarnings for
 * how it reaches the audit log).
 */
export async function loadCurrentPolicy(harnessId: string): Promise<HarnessLoadResult> {
  const commonRootPath = commonRoot();
  const common = await readLayer(commonRootPath);
  const commonLayer = namedLayer('common', common);

  // Phase 1: baseline + common only, enough to resolve `harnessId` — see
  // this module's own header comment for why a brand-new harness must be
  // introduced through the common layer.
  const commonOnly = loadPolicyFromLayers([commonLayer]);
  const harnessFromCommon = commonOnly.policy.harness.find((h) => h.id === harnessId);
  if (harnessFromCommon === undefined) {
    return { ...commonOnly, harness: undefined };
  }

  const profileRootPath = profileRootFor(harnessFromCommon);
  const [profile, migrationWarning] = await Promise.all([
    readLayer(profileRootPath),
    migrationGuardWarning(commonRootPath, profileRootPath),
  ]);
  const effectiveProfile: LayerRead = migrationWarning === null ? profile : { ...profile, files: [] };
  const layers: readonly NamedLayer[] = [commonLayer, namedLayer('profile', effectiveProfile)];
  const result = loadPolicyFromLayers(layers);
  const harness = result.policy.harness.find((h) => h.id === harnessId);
  return {
    ...(migrationWarning === null ? result : { ...result, warnings: [...result.warnings, migrationWarning] }),
    harness,
  };
}
