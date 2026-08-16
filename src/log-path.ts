// Per-account audit log routing. Pure path resolution — no file I/O.
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

// Resolves the config dir of the account currently in use. Honoring
// CLAUDE_CONFIG_DIR matters because a second account (client seat) runs the
// *same* implementation through absolute paths, so without this the
// client's state would land in the personal tree.
//
// `~` is expanded because the variable is often exported from a shell where a
// quoted value keeps the tilde literal, and resolve() drops a trailing slash
// so `.claude-x` and `.claude-x/` agree on one directory.
export function configDir(): string {
  const env = process.env.CLAUDE_CONFIG_DIR;
  if (env && env.trim() !== '') {
    return env.startsWith('~')
      ? resolve(homedir(), env.replace(/^~[/\\]?/, ''))
      : resolve(env);
  }
  return resolve(homedir(), '.claude');
}

// Audit log path for a guard, scoped to the active account. Kept under the
// config dir rather than beside the script — a shared implementation would
// otherwise interleave two accounts' denials in one file.
export function hookLogPath(hookName: string): string {
  return resolve(configDir(), 'logs', 'hooks', `${hookName}.log`);
}
