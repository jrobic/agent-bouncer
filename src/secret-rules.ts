// Secret-guard: which filesystem paths and which Bash commands reference
// secret-bearing material. Pure — no Bun/Node APIs, no harness protocol
// shapes. The rule tables are policy data (policy/secret.toml,
// `rules.secret.path` and `rules.secret.bash`); this module owns the
// scanning algorithms, parameterized over whichever tables are loaded.
//
// ─── Known limits (this is a defense, not a sandbox) ─────────────────
// The Bash matcher scans literal path-like tokens. A token containing `*` or
// `?` is checked with every metacharacter read as `x` and with every
// metacharacter empty; the stricter verdict wins. A metacharacter inside the
// extension has no faithful witness: the two readings cover names and prefixes,
// not extensions. Character classes, comma-brace expansion, a bare `*`,
// variables, command substitutions, and escaped metacharacters stay out of
// that expansion.
// Search-pattern exclusions are opt-in per tool and declared argument shape;
// unknown commands or options, unterminated quotes, and unterminated heredocs
// retain the full scan. Whitespace-bearing quoted strings and heredoc bodies
// mask only individual tokens without `/` or a leading `~`, so source literals
// carrying a guarded path stay scanned. `rg --hidden -i env` can still print
// dotenv lines, as `grep -r env .` already can. Treat this as protection
// against accidental leaks, not against an adversarial agent.

import { hasUnsafeGitConfigRemoteUrl, maskSearchPatternArguments } from './command-rules.ts';
import { BASELINE } from './policy/baseline.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { RegexRule } from './policy/schema.ts';
import { type Verdict, VERDICT_SEVERITY } from './types.ts';

// Path-like token: contiguous run covering absolute, relative, and ~/ paths.
export const BASH_PATH_TOKEN = /[\w./~-]+/g;

const BASH_SHELL_TOKEN = /(?:^|[\s;|&])(\$\([^)]*\)|\S+)/g;
const BASH_GLOB_PATH_TOKEN = /[-\w./~?*]*[?*][-\w./~?*]*/;
const UNSUPPORTED_GLOB_SYNTAX = /[[\]$\\]|\{[^}]*,[^}]*\}/;

export function globPathReadings(shellToken: string): readonly string[] | null {
  if (shellToken === '*' || UNSUPPORTED_GLOB_SYNTAX.test(shellToken)) return null;
  const glob = shellToken.match(BASH_GLOB_PATH_TOKEN)?.[0];
  if (glob === undefined) return null;
  const anyNameReading = glob.replaceAll(/[?*]/g, 'x');
  const emptyNameReading = glob.replaceAll(/[?*]/g, '');
  return [anyNameReading, emptyNameReading];
}

function strictestPathHit(first: Verdict | null, second: Verdict | null): Verdict | null {
  if (first === null) return second;
  if (second === null) return first;
  return VERDICT_SEVERITY[second.verdict] > VERDICT_SEVERITY[first.verdict] ? second : first;
}

function bashPathHit(pathHit: Verdict, cmd: string): Verdict {
  return {
    // The underlying path rule's OWN verdict, not a hardcoded "block" —
    // confirm rules must retain their verdict when reached from Bash.
    verdict: pathHit.verdict,
    ruleId: `bash-${pathHit.ruleId}`,
    reason: `Bash command references sensitive path: ${pathHit.reason}`,
    target: cmd,
  };
}

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
  tables: { readonly path: readonly RegexRule[]; readonly bash: readonly RegexRule[]; },
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

    const masked = maskSearchPatternArguments(cmd, BASH_PATH_TOKEN);
    for (const match of masked.matchAll(BASH_SHELL_TOKEN)) {
      const shellToken = match[1]!;
      const candidates = globPathReadings(shellToken) ?? shellToken.match(BASH_PATH_TOKEN) ?? [];
      const pathHit = candidates.reduce<Verdict | null>(
        (strictest, candidate) =>
          strictestPathHit(
            strictest,
            checkPath(candidate.replace(/^~\//, '/')),
          ),
        null,
      );
      if (pathHit) return bashPathHit(pathHit, cmd);
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
