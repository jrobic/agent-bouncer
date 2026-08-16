// Secret-guard rules: which filesystem paths and which Bash commands
// reference secret-bearing material. Pure — no Bun/Node APIs, no harness
// protocol shapes.
//
// ─── Known limits (this is a defense, not a sandbox) ─────────────────
// The Bash matcher tokenizes the literal command and is trivially defeated
// by hex/base64/quote-splitting tricks (e.g. `printf '\x2eenv' | xargs
// cat`). Treat this as protection against accidental leaks, not against an
// adversarial agent.

import type { BashRule, Deny } from './types.ts';
import { hasUnsafeGitConfigRemoteUrl } from './command-rules.ts';

export interface PathRule {
  id: string;
  test: (path: string) => boolean;
  reason: string;
}

export const ENV_WHITELIST = /(^|\/)\.env\.(example|test)$/;

// Specific rules (single file or precise extension) come BEFORE broad
// directory rules so that, e.g., ~/.aws/credentials is reported as
// "aws-creds" and not as the generic "secret-dir".
export const PATH_RULES: readonly PathRule[] = [
  {
    id: 'dotenv',
    test: (p) => /(^|\/)\.env[^/]*$/.test(p) && !ENV_WHITELIST.test(p),
    reason: '.env file blocked (only .env.example and .env.test are allowed)',
  },
  {
    id: 'crypto-key',
    // The basename must have a non-dot leading stem (`server.key`, not
    // `.key` / `.settings.key`): jq field accessors tokenized out of Bash
    // commands (`jq '.settings.key' f.json`) were false-positives. Known
    // trade-off: a hidden dotfile key (`.secret.pem`) now passes.
    test: (p) =>
      /(^|\/)[^/.][^/]*\.(pem|key|pkey|crt|cert|pfx|p12|jks|keystore|gpg|asc|kdbx|kbx|agekey|ovpn)$/i
        .test(p),
    reason: 'Cryptographic key/certificate file blocked',
  },
  {
    id: 'ssh-key',
    test: (p) => /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/.test(p),
    reason: 'SSH key file blocked',
  },
  {
    id: 'aws-creds',
    test: (p) => /(^|\/)\.aws\/(credentials|config)$/.test(p),
    reason: 'AWS credentials/config blocked',
  },
  {
    id: 'netrc-pgpass',
    test: (p) => /(^|\/)\.(netrc|pgpass)$/.test(p),
    reason: '.netrc/.pgpass blocked',
  },
  {
    id: 'cloud-sa',
    test: (p) => /(service-account|firebase-adminsdk|gcp-key)[^/]*\.json$/i.test(p),
    reason: 'Cloud service-account JSON blocked',
  },
  {
    id: 'tfstate',
    test: (p) => /\.tfstate(\.backup)?$|\.terraform\.tfstate\.lock\.info$/.test(p),
    reason: 'Terraform state file blocked (often contains plaintext secrets)',
  },
  {
    id: 'npmrc',
    test: (p) => /(^|\/)\.npmrc$/.test(p) && !p.includes('/node_modules/'),
    reason: '.npmrc blocked outside node_modules/ (may contain _authToken)',
  },
  {
    id: 'gitconfig',
    test: (p) => /(^|\/)\.gitconfig$/.test(p),
    reason: '.gitconfig blocked (may contain [credential] tokens or signing keys)',
  },
  {
    id: 'hook-log',
    // Literal names, not a generalisation (`guard-[a-z-]+` was discarded at
    // design time): widening a security rule to cover files that do not
    // exist yet would remove any test able to name what it covers. Every
    // guard's own audit log is named here explicitly.
    test: (p) =>
      /(^|\/)(?:guard-command|guard-secret|guard-write-secret|guard-mcp-write|transcript-backup)\.log$/
        .test(p),
    reason: 'hook audit log blocked (would leak history of denied tool calls)',
  },
  {
    id: 'transcript-backup',
    test: (p) => /(^|\/)\.claude\/transcripts(\/|$)/.test(p),
    reason: 'transcript backup directory blocked (contains full session history)',
  },
  {
    id: 'secret-dir',
    test: (p) => /(^|\/)(\.?secrets|credentials)(\/|$)/.test(p),
    reason: 'Path inside secrets/ or credentials/ directory blocked',
  },
  {
    id: 'ssh-dir',
    test: (p) => /(^|\/)\.ssh(\/|$)/.test(p),
    reason: '.ssh directory blocked',
  },
  {
    id: 'gnupg-dir',
    test: (p) => /(^|\/)\.gnupg(\/|$)/.test(p),
    reason: '.gnupg directory blocked',
  },
];

export function checkPath(path: string): Deny | null {
  if (!path) return null;
  for (const rule of PATH_RULES) {
    if (rule.test(path)) {
      return { ruleId: rule.id, reason: rule.reason, target: path };
    }
  }
  return null;
}

// Path-like token: contiguous run covering absolute, relative, and ~/ paths.
export const BASH_PATH_TOKEN = /[\w./~-]+/g;

const GIT_REMOTE_URL_RULE: BashRule = {
  // Reading remote.*.url is the same read-only class as `git remote get-url`
  // above. The canonical parser in checkSecretBash decides that exception; the
  // regex stays conservative and matches every remote-url config command.
  regex: /\bgit\s+config\b[^\n]*\bremote\.[^\s]+\.url\b/,
  ruleId: 'bash-git-leak',
  reason:
    'git command may leak credentials (tokens in remote URLs, signing keys, credential helpers)',
};

export const SECRET_BASH_RULES: readonly BashRule[] = [
  {
    // `git remote -v` / `get-url` / `--verbose` are deliberately NOT matched
    // by any entry here: command-guard auto-approves them as read-only, and
    // the actual risk they proxied for — a token embedded in the URL — is
    // caught by bash-url-creds below.
    // credential/signingkey stay blocked even for reads (auth mechanisms),
    // hence no read exception on this entry.
    regex: /\bgit\s+config\b[^\n]*\b(credential|user\.signingkey)\b/,
    ruleId: 'bash-git-leak',
    reason:
      'git command may leak credentials (tokens in remote URLs, signing keys, credential helpers)',
  },
  GIT_REMOTE_URL_RULE,
  {
    regex: /\b(?:https?|git|ssh|ftp):\/\/[^\s/@:]+:[^\s/@]+@/,
    ruleId: 'bash-url-creds',
    reason: 'URL contains embedded user:password credentials (likely token leak)',
  },
];

export function checkSecretBash(cmd: string): Deny | null {
  if (!cmd) return null;
  for (const rule of SECRET_BASH_RULES) {
    if (rule === GIT_REMOTE_URL_RULE) {
      if (hasUnsafeGitConfigRemoteUrl(cmd)) {
        return { ruleId: rule.ruleId, reason: rule.reason, target: cmd };
      }
      continue;
    }
    if (rule.regex.test(cmd)) {
      return { ruleId: rule.ruleId, reason: rule.reason, target: cmd };
    }
  }
  const tokens = cmd.match(BASH_PATH_TOKEN) ?? [];
  for (const tok of tokens) {
    const normalized = tok.replace(/^~\//, '/');
    const hit = checkPath(normalized);
    if (hit) {
      return {
        ruleId: `bash-${hit.ruleId}`,
        reason: `Bash command references sensitive path: ${hit.reason}`,
        target: cmd,
      };
    }
  }
  return null;
}

// Workstation delta (target-extraction parity): a fetched URL gets the
// literal-string SECRET_BASH_RULES but NOT the path-token scan checkSecretBash runs —
// `https://docs.example.com/secrets/overview` names a web page, not a file
// on disk, and the scan would deny every fetch of a page whose path merely
// reads like a sensitive directory. Needed so extractTargets()'s `urls`
// bucket (ctx_fetch_and_index) has a matching check function — without it,
// a URL target is extracted but nothing ever inspects it.
export function checkUrl(url: string): Deny | null {
  if (!url) return null;
  for (const rule of SECRET_BASH_RULES) {
    if (rule === GIT_REMOTE_URL_RULE) continue;
    if (rule.regex.test(url)) {
      return { ruleId: rule.ruleId, reason: rule.reason, target: url };
    }
  }
  return null;
}
