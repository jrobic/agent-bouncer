// Secret-guard: which filesystem paths and which Bash commands reference
// secret-bearing material. Pure — no Bun/Node APIs, no harness protocol
// shapes. The rule tables are policy data (policy/secret.toml,
// `rules.secret.path` and `rules.secret.bash`); this module owns the
// scanning algorithms, parameterized over whichever tables are loaded.
//
// ─── Known limits (this is a defense, not a sandbox) ─────────────────
// The Bash matcher tokenizes the literal command and is trivially defeated
// by hex/base64/quote-splitting tricks (e.g. `printf '\x2eenv' | xargs
// cat`). Treat this as protection against accidental leaks, not against an
// adversarial agent.

import { hasUnsafeGitConfigRemoteUrl } from './command-rules.ts';
import { BASELINE } from './policy/baseline.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { RegexRule } from './policy/schema.ts';
import type { Verdict } from './types.ts';

// Path-like token: contiguous run covering absolute, relative, and ~/ paths.
export const BASH_PATH_TOKEN = /[\w./~-]+/g;

export interface SecretChecker {
  readonly checkPath: (path: string) => Verdict | null;
  readonly checkSecretBash: (cmd: string) => Verdict | null;
  readonly checkUrl: (url: string) => Verdict | null;
}

/**
 * Builds {checkPath, checkSecretBash, checkUrl} bound to the given rule
 * tables (baseline, or a merged baseline+overlay+override set) and the
 * git config read-mode list the "git_remote_url" special rule needs —
 * shared with the command family (see policy/command.toml's
 * `rules.command.git.config_read_modes`) so both stay a single source of
 * truth instead of two hardcoded lists drifting apart.
 */
export function createSecretChecker(
  tables: { readonly path: readonly RegexRule[]; readonly bash: readonly RegexRule[] },
  configReadModes: readonly string[],
): SecretChecker {
  const compiledPath = compileRules(tables.path);
  const compiledBash = compileRules(tables.bash);
  const specials = {
    // Reading remote.*.url is the same read-only class as `git remote
    // get-url` (command family) — the structural parser decides that
    // exception; the regex itself stays conservative and matches every
    // remote-url config command, read or write.
    git_remote_url: (cmd: string) => hasUnsafeGitConfigRemoteUrl(cmd, configReadModes),
  };

  const checkPath = (path: string): Verdict | null => {
    if (!path) return null;
    return firstMatch(compiledPath, path, 'block');
  };

  const checkSecretBash = (cmd: string): Verdict | null => {
    if (!cmd) return null;
    const hit = firstMatch(compiledBash, cmd, 'block', specials);
    if (hit) return hit;

    const tokens = cmd.match(BASH_PATH_TOKEN) ?? [];
    for (const tok of tokens) {
      const normalized = tok.replace(/^~\//, '/');
      const pathHit = checkPath(normalized);
      if (pathHit) {
        return {
          verdict: 'block',
          ruleId: `bash-${pathHit.ruleId}`,
          reason: `Bash command references sensitive path: ${pathHit.reason}`,
          target: cmd,
        };
      }
    }
    return null;
  };

  // A fetched URL gets the literal-string bash rules but NOT the
  // path-token scan checkSecretBash runs, and NOT the git_remote_url
  // special (no `specials` passed — a URL is never a git command):
  // `https://docs.example.com/secrets/overview` names a web page, not a
  // file on disk, and the scan would deny every fetch of a page whose path
  // merely reads like a sensitive directory.
  const checkUrl = (url: string): Verdict | null => {
    if (!url) return null;
    return firstMatch(compiledBash, url, 'block');
  };

  return { checkPath, checkSecretBash, checkUrl };
}

const BASELINE_CHECKER = createSecretChecker(
  BASELINE.rules.secret,
  BASELINE.rules.command.git.config_read_modes,
);

/** Uses the embedded baseline's secret.path table. */
export const checkPath = BASELINE_CHECKER.checkPath;
/** Uses the embedded baseline's secret.bash table. */
export const checkSecretBash = BASELINE_CHECKER.checkSecretBash;
/** Uses the embedded baseline's secret.bash table (URL-shaped targets). */
export const checkUrl = BASELINE_CHECKER.checkUrl;
