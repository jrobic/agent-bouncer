// Resolves and loads the layered policy overlay (ADR-0001) — the common
// layer (harness-neutral, every adapter reads the same root) and the
// profile layer (the one piece of policy loading that is genuinely
// Claude-Code-specific: which account, which directory). The parsing/
// merge/precedence/lint logic itself (src/policy/load.ts) has no opinion
// on where the files live and no filesystem access at all — src/policy/
// stays I/O-free, this is the one adapter module that owns the `node:fs`
// reads.
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
// ENOENT) is reported as a `readError`, which src/policy/load.ts turns
// into a collective rejection naming the file. A file readdir proved
// present has no license to silently vanish.

import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { loadPolicyFromLayers, type LoadResult, type NamedLayer, type OverlayFile } from '../policy/load.ts';
import { configDir } from './log-path.ts';

// ~/.agents/bouncer/ — the common layer's root (ADR-0001 § Layers and
// discovery, Option 2): a harness-neutral convention derived straight from
// the home directory, not from configDir() (which IS Claude-Code-specific
// — CLAUDE_CONFIG_DIR only means something to this one adapter). No file
// anywhere names this root; every future adapter (ticket 15) reads the
// SAME one through this same helper, which is what makes it "common"
// rather than "Claude's".
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

// <configDir>/bouncer/ — the profile layer's root. Sibling to logs/hooks/
// under the same per-account root, so a second account (client seat)
// gets its own overlay the same way it gets its own log.
function profileRoot(): string {
  return join(configDir(), 'bouncer');
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

// Every `policy.d/*.toml` file under `dir`, in lexicographic FILENAME
// order (not path, not mtime) — `10-npm.toml` before `20-client-x.toml`
// regardless of which was edited more recently. A missing or unreadable
// directory is "no policy.d files", not a failure (there is nothing
// readdir proved exists in that case). Read in parallel — order is
// preserved by `.map()`, not by await sequencing, so no `no-await-in-loop`
// concern. Takes the directory explicitly so the SAME function reads
// either root (readLayer below) — the common and profile layers have
// identical shape.
async function readOverlayDirFiles(dir: string): Promise<OverlayFile[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const tomlNames = names.filter((n) => n.endsWith('.toml')).toSorted();
  const files = await Promise.all(
    tomlNames.map((name) => readOverlayFile(`policy.d/${name}`, join(dir, name), false)),
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
 * non-blank) then every `policy.d/*.toml` file in lexicographic order —
 * AND whether `root` itself exists as a directory. Shared by the common
 * and profile roots (ADR-0001 § Layers and discovery: "both layers have
 * the same shape, read by one function over two roots").
 */
async function readLayer(root: string): Promise<LayerRead> {
  const [exists, primary, dirFiles] = await Promise.all([
    directoryExists(root),
    readOverlayFile('policy.toml', join(root, 'policy.toml'), true),
    readOverlayDirFiles(join(root, 'policy.d')),
  ]);
  const files = primary !== null ? [primary, ...dirFiles] : dirFiles;
  return { files, root: exists ? root : undefined };
}

function namedLayer(name: string, read: LayerRead): NamedLayer {
  return { name, ...(read.root !== undefined ? { root: read.root } : {}), files: read.files };
}

/**
 * Reads and loads the effective, layered policy (ADR-0001) — the common
 * layer (commonRoot()) then the profile layer (profileRoot()), merged
 * with the profile winning on a shared target
 * (src/policy/load.ts's loadPolicyFromLayers). No files at all, in
 * either layer, is treated exactly like "no overlay": silent, no
 * warning — an absent overlay (or an absent common layer alone) is the
 * normal, unconfigured case, not a failure. A `policy.d/*.toml` entry
 * that exists per `readdir` but fails to read is NOT dropped silently —
 * it flows through as a `readError` that src/policy/load.ts rejects the
 * whole load over, naming the file.
 */
export async function loadCurrentPolicy(): Promise<LoadResult> {
  const [common, profile] = await Promise.all([
    readLayer(commonRoot()),
    readLayer(profileRoot()),
  ]);
  const layers: readonly NamedLayer[] = [namedLayer('common', common), namedLayer('profile', profile)];
  return loadPolicyFromLayers(layers);
}
