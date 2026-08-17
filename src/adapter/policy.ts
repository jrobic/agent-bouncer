// Resolves and loads the per-account policy overlay — the one piece of
// policy loading that is genuinely Claude-Code-specific (which account,
// which directory, reading the files off disk). The parsing/merge/lint
// logic itself (src/policy/load.ts) has no opinion on where the files
// live and no filesystem access at all — src/policy/ stays I/O-free, this
// is the one adapter module that owns the `node:fs` reads.
//
// Two overlay locations (ticket 12), merged in this fixed order: the
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

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadPolicyFromOverlayFiles, type LoadResult, type OverlayFile } from '../policy/load.ts';
import { configDir } from './log-path.ts';

// <configDir>/bouncer/policy.toml — sibling to logs/hooks/ under the same
// per-account root, so a second account (client seat) gets its own overlay
// the same way it gets its own log.
export function overlayPath(): string {
  return join(configDir(), 'bouncer', 'policy.toml');
}

// <configDir>/bouncer/policy.d/ — the directory split, same root as
// overlayPath() and the per-account log.
export function overlayDirPath(): string {
  return join(configDir(), 'bouncer', 'policy.d');
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

// Every `policy.d/*.toml` file, in lexicographic FILENAME order (not path,
// not mtime) — `10-npm.toml` before `20-client-x.toml` regardless of which
// was edited more recently. A missing or unreadable directory is "no
// policy.d files", not a failure (there is nothing readdir proved exists
// in that case). Read in parallel — order is preserved by `.map()`, not by
// await sequencing, so no `no-await-in-loop` concern.
async function readOverlayDirFiles(): Promise<OverlayFile[]> {
  const dir = overlayDirPath();
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

/**
 * Reads the overlay file SET — `policy.toml` (if present and non-blank)
 * then every `policy.d/*.toml` file in lexicographic order — and loads
 * it. No files at all is treated exactly like "no overlay": silent, no
 * warning; an absent overlay is the normal, unconfigured case, not a
 * failure. A `policy.d/*.toml` entry that exists per `readdir` but fails
 * to read is NOT dropped silently — it flows through as a `readError`
 * that src/policy/load.ts rejects the whole set over, naming the file.
 */
export async function loadCurrentPolicy(): Promise<LoadResult> {
  const primary = await readOverlayFile('policy.toml', overlayPath(), true);
  const dirFiles = await readOverlayDirFiles();
  const files = primary !== null ? [primary, ...dirFiles] : dirFiles;
  return loadPolicyFromOverlayFiles(files);
}
