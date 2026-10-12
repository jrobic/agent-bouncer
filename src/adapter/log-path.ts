// Per-account audit log / profile-overlay routing. Pure path resolution —
// no file I/O.
//
// ADR-0006 § 8: declaration-driven, not Claude-Code-specific any more — a
// harness's OWN `env` names (in declaration order) give its account
// directory, `witness` the fallback when none of them is set. Claude
// Code's routing is unchanged (`CLAUDE_CONFIG_DIR`, falling back to
// `~/.claude`); a different `--harness <id>` now resolves against THAT
// harness's own declaration instead.
//
// Legacy behavior folded into the engine convergence: the catalog
// generation this repository otherwise ports verbatim always wrote its log
// beside the hook script, one file shared by every account running that
// script. This module resolves the log path from the active account's
// config dir instead, so a second account (a client seat running the same
// binary through an absolute path) never interleaves its audit trail with
// the primary one's.

import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { HarnessDeclaration } from '../policy/schema.ts';

/**
 * The home directory `~` means for this process: its HOME environment
 * variable when that is non-blank, node:os's homedir() otherwise. The ONE
 * resolver of every `~` bouncer expands — the common layer's root
 * (policy.ts's commonRoot()), an account directory written with a tilde
 * (expandHome() below, so configDirFor()), omp's profiles root
 * (codecs/wiring/shim-file.ts) — so a single doctor run never resolves `~`
 * two ways.
 *
 * HOME is read at call time, on purpose, rather than through homedir()
 * alone: Bun resolves homedir() once at process boot (from the OS, not
 * from `process.env.HOME`) and never re-reads it, so a test that
 * reassigns `process.env.HOME` mid-process (tests/setup.ts installs a
 * throwaway one globally; the process user's real home may carry a live
 * `~/.agents/bouncer/` and `~/.omp`) would silently keep resolving to the
 * REAL home. GUARD FOR TEST AUTHORS: an empty OR deleted `process.env.HOME`
 * both fall through to homedir() — the real home, never a safe default. A
 * test must always REASSIGN `HOME` to another throwaway string in its own
 * cleanup, exactly like tests/setup.ts's global preload does; never
 * `delete process.env.HOME` or set it to `''` to "reset" it.
 */
export function processHome(): string {
  const home = process.env.HOME;
  return home !== undefined && home.trim() !== '' ? home : homedir();
}

// `~` is expanded because a witness or an exported env value is often
// written with a literal tilde a shell would otherwise expand, and
// resolve() drops a trailing slash so `.claude-x` and `.claude-x/` agree
// on one directory.
export function expandHome(path: string): string {
  return path.startsWith('~') ? resolve(processHome(), path.replace(/^~[/\\]?/, '')) : resolve(path);
}

/**
 * Resolves the account directory of the harness currently in use: the
 * first of its declared `env` names actually set (in declaration order),
 * falling back to its `witness` when none is. Honoring the env names
 * matters because a second account (client seat) runs the *same*
 * implementation through absolute paths, so without this the client's
 * state would land in the primary account's tree.
 */
export function configDirFor(harness: HarnessDeclaration): string {
  for (const name of harness.env) {
    const value = process.env[name];
    if (value !== undefined && value.trim() !== '') return expandHome(value);
  }
  return expandHome(harness.witness);
}

/** Audit log path for a guard, scoped to the given harness's account. */
export function hookLogPathFor(harness: HarnessDeclaration, hookName: string): string {
  return resolve(configDirFor(harness), 'logs', 'hooks', `${hookName}.log`);
}

/** `<configDir>/bouncer/` — the profile overlay layer's root for the given harness. */
export function profileRootFor(harness: HarnessDeclaration): string {
  return resolve(configDirFor(harness), 'bouncer');
}
