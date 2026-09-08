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
// Workstation delta folded into the engine convergence: the catalog
// generation this repository otherwise ports verbatim always wrote its log
// beside the hook script, one file shared by every account running that
// script. This module resolves the log path from the active account's
// config dir instead, so a second account (a client seat running the same
// binary through an absolute path) never interleaves its audit trail with
// the primary one's.

import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { HarnessDeclaration } from '../policy/schema.ts';

// `~` is expanded because a witness or an exported env value is often
// written with a literal tilde a shell would otherwise expand, and
// resolve() drops a trailing slash so `.claude-x` and `.claude-x/` agree
// on one directory.
function expandHome(path: string): string {
  return path.startsWith('~') ? resolve(homedir(), path.replace(/^~[/\\]?/, '')) : resolve(path);
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
