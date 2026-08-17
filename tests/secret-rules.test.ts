import { describe, expect, test } from 'bun:test';
import { checkSecretBash, checkPath, checkUrl } from '../src/secret-rules.ts';

// One test per PATH_RULES id (nominal) + the two ENV_WHITELIST counter-examples
// and the node_modules/.npmrc counter-example called out in the task.

describe('secret-rules: PATH_RULES', () => {
  test('ruleId dotenv: .env is blocked', () => {
    expect(checkPath('/home/user/.env')?.ruleId).toBe('dotenv');
  });

  test('benign: .env.example passes (ENV_WHITELIST)', () => {
    expect(checkPath('/home/user/.env.example')).toBeNull();
  });

  test('benign: .env.test passes (ENV_WHITELIST)', () => {
    expect(checkPath('/home/user/.env.test')).toBeNull();
  });

  test('ruleId crypto-key: .pem file is blocked', () => {
    expect(checkPath('/home/user/id_rsa.pem')?.ruleId).toBe('crypto-key');
  });

  // crypto-key requires a non-dot leading stem. Path chosen OUTSIDE any
  // already-covered directory (not .ssh/, not secrets/, not .aws/ …) so
  // this test cannot stay green by accident if crypto-key itself
  // disappears — some other rule would have to catch it, and none does.
  test('ruleId crypto-key: certs/server.key stays blocked (path outside any other covered dir)', () => {
    expect(checkPath('/home/u/certs/server.key')?.ruleId).toBe('crypto-key');
  });

  // Pins the end anchor ($) in the crypto-key pattern: without it, ".key"
  // would match as a mid-string substring and "server.keychain" would be
  // mistaken for a key file.
  test('ruleId crypto-key: server.keychain is not blocked (end anchor, not a substring match)', () => {
    expect(checkPath('/home/u/certs/server.keychain')).toBeNull();
  });

  // Pins the case-insensitive flag (i) in the crypto-key pattern: without it,
  // an uppercase extension like .PEM would stop matching.
  test('ruleId crypto-key: uppercase extension .PEM stays blocked (case-insensitive flag)', () => {
    expect(checkPath('/home/u/certs/server.PEM')?.ruleId).toBe('crypto-key');
  });

  // One positive vector per branch of crypto-key's fifteen-way extension
  // alternation. The stem is fixed at `certs/server`: a directory covered by
  // no other PATH_RULES entry, and a non-dot leading stem, so a hit can only
  // come from crypto-key.
  test.each([
    'pem',
    'key',
    'pkey',
    'crt',
    'cert',
    'pfx',
    'p12',
    'jks',
    'keystore',
    'gpg',
    'asc',
    'kdbx',
    'kbx',
    'agekey',
    'ovpn',
  ])('ruleId crypto-key: server.%s is blocked (one vector per extension branch)', (ext) => {
    expect(checkPath(`/home/u/certs/server.${ext}`)?.ruleId).toBe('crypto-key');
  });

  test('ruleId ssh-key: id_rsa is blocked', () => {
    expect(checkPath('/home/user/.ssh/id_rsa')?.ruleId).toBe('ssh-key');
  });

  test('ruleId ssh-key: id_ed25519.pub is blocked (public key, same rule as the private one)', () => {
    expect(checkPath('/some/path/id_ed25519.pub')?.ruleId).toBe('ssh-key');
  });

  test('ruleId aws-creds: ~/.aws/credentials is blocked', () => {
    expect(checkPath('/home/user/.aws/credentials')?.ruleId).toBe('aws-creds');
  });

  test('ruleId netrc-pgpass: .netrc is blocked', () => {
    expect(checkPath('/home/user/.netrc')?.ruleId).toBe('netrc-pgpass');
  });

  test('ruleId cloud-sa: gcp-key-*.json is blocked', () => {
    expect(checkPath('/proj/gcp-key-1234.json')?.ruleId).toBe('cloud-sa');
  });

  test('ruleId tfstate: terraform.tfstate is blocked', () => {
    expect(checkPath('/proj/terraform.tfstate')?.ruleId).toBe('tfstate');
  });

  test('ruleId npmrc: .npmrc outside node_modules is blocked', () => {
    expect(checkPath('/proj/.npmrc')?.ruleId).toBe('npmrc');
  });

  test('benign: .npmrc under node_modules passes', () => {
    expect(checkPath('/proj/node_modules/foo/.npmrc')).toBeNull();
  });

  test('ruleId gitconfig: .gitconfig is blocked', () => {
    expect(checkPath('/home/user/.gitconfig')?.ruleId).toBe('gitconfig');
  });

  // hook-log moved OUT of the baseline by ticket 13 (baseline universality
  // triage) — predecessor-tool/personal-migration artifact, not a
  // universal hazard. Its behavioral cases, including the "documented
  // gap: rotated .log.1 is not blocked" case and the workstation-naming
  // negative discriminator, moved with it to tests/personal-policy.test.ts,
  // exercised against examples/personal-overlay.toml instead of BASELINE
  // directly.

  test('ruleId transcript-backup: .claude/transcripts/ is confirmed, not blocked outright', () => {
    // Review round 2's arbitration: stays in the baseline (protects by
    // default) but at verdict "confirm" rather than "block" — a
    // legitimate read isn't stopped outright, just asked about. See the
    // `verdict = "confirm"` row in policy/secret.toml.
    const hit = checkPath('/home/user/.claude/transcripts/foo.json');
    expect(hit?.ruleId).toBe('transcript-backup');
    expect(hit?.verdict).toBe('confirm');
  });

  test('ruleId secret-dir: secrets/ directory is blocked', () => {
    expect(checkPath('/proj/secrets/db.yaml')?.ruleId).toBe('secret-dir');
  });

  test('ruleId ssh-dir: .ssh/ directory is blocked', () => {
    expect(checkPath('/home/user/.ssh/config')?.ruleId).toBe('ssh-dir');
  });

  test('ruleId ssh-dir: known_hosts is blocked by the directory rule, not the ssh-key rule', () => {
    // known_hosts isn't an id_* key file, so it falls through to the
    // broader .ssh/ directory rule rather than the specific ssh-key one.
    expect(checkPath('/Users/foo/.ssh/known_hosts')?.ruleId).toBe('ssh-dir');
  });

  test('ruleId gnupg-dir: .gnupg/ directory is blocked', () => {
    expect(checkPath('/home/user/.gnupg/random-file.txt')?.ruleId).toBe('gnupg-dir');
  });

  test('benign: an ordinary source file passes', () => {
    expect(checkPath('/proj/src/index.ts')).toBeNull();
  });
});

describe('secret-rules: BASH_RULES (secret)', () => {
  test('ruleId bash-git-leak-credential: git config credential.* is denied', () => {
    expect(checkSecretBash('git config credential.helper store')?.ruleId).toBe('bash-git-leak-credential');
  });

  // bash-git-leak is split in two entries. credential and user.signingkey
  // are auth mechanisms — they stay blocked unconditionally, reads
  // included; remote.*.url carries the read exception, because reading a
  // remote URL is the same read-only class as `git remote get-url`.
  test('ruleId bash-git-leak-credential: git config --get credential.helper stays denied (read included)', () => {
    expect(checkSecretBash('git config --get credential.helper')?.ruleId).toBe('bash-git-leak-credential');
  });

  test('ruleId bash-git-leak-credential: git config user.signingkey ABC is denied', () => {
    expect(checkSecretBash('git config user.signingkey ABC')?.ruleId).toBe('bash-git-leak-credential');
  });

  test('ruleId bash-git-leak-credential: git config --get user.signingkey stays denied (read included)', () => {
    expect(checkSecretBash('git config --get user.signingkey')?.ruleId).toBe('bash-git-leak-credential');
  });

  // Discriminating write vector, deliberately WITHOUT credentials in the URL:
  // `https://user:pass@host/x` would match bash-url-creds too, and since that
  // rule comes second, the assertion below would stay green even if the
  // remote.*.url entry disappeared entirely — the first match wins, so rule
  // order decides the reported ruleId.
  test('ruleId bash-git-leak-remote-url: writing a remote url is denied (no credentials in the URL)', () => {
    expect(checkSecretBash('git config remote.origin.url https://host/x.git')?.ruleId).toBe(
      'bash-git-leak-remote-url',
    );
  });

  test('ruleId bash-git-leak-remote-url: a quoted remote-url key stays an effective write', () => {
    expect(
      checkSecretBash('git config "remote.origin.url" https://host/x.git')?.ruleId,
    ).toBe('bash-git-leak-remote-url');
    expect(
      checkSecretBash("git config 'remote.origin.url' https://host/x.git")?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  test('ruleId bash-git-leak-remote-url: a continued remote-url key stays an effective write', () => {
    expect(
      checkSecretBash('git config remote.origin.\\\nurl https://host/x.git')?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  test('benign: reading a remote url with --get passes', () => {
    expect(checkSecretBash('git config --get remote.origin.url')).toBeNull();
  });

  test('benign: shell negation preserves the read-only remote-url classification', () => {
    expect(checkSecretBash('! git config --get remote.origin.url')).toBeNull();
    expect(checkSecretBash('echo ok; ! git config get remote.origin.url')).toBeNull();
  });

  test('benign: time may introduce shell negation before a remote-url read', () => {
    expect(checkSecretBash('time ! git config --get remote.origin.url')).toBeNull();
    expect(checkSecretBash('time -p ! git config get remote.origin.url')).toBeNull();
  });

  test('benign: reading a remote url with the positional get mode passes', () => {
    expect(checkSecretBash('git config get remote.origin.url')).toBeNull();
  });

  test('benign: a remote-url read in a compound command stays allowed', () => {
    expect(checkSecretBash('git config --get remote.origin.url && echo done')).toBeNull();
  });

  test('benign: every remote-url occurrence in a composed read belongs to its own read segment', () => {
    expect(
      checkSecretBash(
        'git config --get remote.origin.url; command -- git config get remote.backup.url',
      ),
    ).toBeNull();
  });

  test('ruleId bash-git-leak-remote-url: a compound read cannot hide a later remote-url write', () => {
    expect(
      checkSecretBash(
        'git config --get remote.origin.url && git config remote.origin.url https://host/x.git',
      )?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  test('ruleId bash-git-leak-remote-url: the ratified wrapped write is denied in its own segment', () => {
    expect(
      checkSecretBash(
        'git config --get user.name; command -- git config remote.origin.url https://host/x.git',
      )?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  test('ruleId bash-git-leak-remote-url: a read in one segment cannot exempt an unrecognised remote-url write segment', () => {
    expect(
      checkSecretBash(
        'git config --get user.name; ! git config remote.origin.url https://host/x.git',
      )?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  test('ruleId bash-git-leak-remote-url: a shell comment cannot turn a remote-url write into --get', () => {
    expect(
      checkSecretBash('git config remote.origin.url https://host/x.git # --get')?.ruleId,
    ).toBe('bash-git-leak-remote-url');
  });

  // `git remote -v` is read-only and auto-approved by command-guard; the
  // risk it used to proxy for — a token embedded in the URL — is caught by
  // bash-url-creds, asserted just below.
  test.each([
    'git remote get-url origin',
    'git remote --verbose',
  ])('benign: %s passes the secret guard', (cmd) => {
    expect(checkSecretBash(cmd)).toBeNull();
  });

  test('ruleId bash-url-creds: URL with embedded user:pass is denied', () => {
    expect(checkSecretBash('curl https://user:pass@example.com/api')?.ruleId).toBe('bash-url-creds');
  });

  test('benign: an SSH scp-like URL (git@host:path) has no colon-credentials, no user:pass to catch', () => {
    // `git@github.com:org/repo.git` puts `:` where the URL rule expects a
    // password, not a "user:password@" pair — the colon here separates host
    // from path, the scp shorthand form. Nothing to catch, nothing asks.
    expect(checkSecretBash('git clone git@github.com:org/repo.git')).toBeNull();
  });

  test('bash path scan: a bare .env token in a command is denied via PATH_RULES', () => {
    const deny = checkSecretBash('cat /home/user/.env');
    expect(deny?.ruleId).toBe('bash-dotenv');
  });

  // The tokenizer extracts ".settings.key" out of this jq accessor, and the
  // un-anchored extension-only crypto-key pattern used to match it as a key
  // file.
  test('benign: jq field accessor is not mistaken for a key file', () => {
    expect(checkSecretBash("jq '.settings.key' config.json")).toBeNull();
  });

  test('benign: an ordinary command passes', () => {
    expect(checkSecretBash('ls -la')).toBeNull();
  });

  test('benign: git status passes', () => {
    expect(checkSecretBash('git status')).toBeNull();
  });
});

// Workstation delta: checkUrl gives extractTargets()'s `urls` bucket
// (ctx_fetch_and_index) a matching check function. Unlike checkSecretBash, it
// skips the PATH_RULES path-token scan — a URL's path segment names a web
// page, not a file on disk, so `/secrets/` inside a documentation URL is not
// a leak.
describe('secret-rules: checkUrl (target-extraction parity)', () => {
  test('ruleId bash-url-creds: a URL with embedded user:pass credentials is denied', () => {
    expect(checkUrl('https://user:ghp_secret@api.example.com/repos')?.ruleId).toBe(
      'bash-url-creds',
    );
  });

  test('benign: a documentation URL whose path reads like a secret dir is allowed', () => {
    expect(checkUrl('https://docs.example.com/secrets/overview')).toBeNull();
  });

  test('benign: an ordinary URL passes', () => {
    expect(checkUrl('https://example.com/api/status')).toBeNull();
  });

  test('benign: an empty URL passes', () => {
    expect(checkUrl('')).toBeNull();
  });

  test('ssh URL with embedded credentials is denied', () => {
    expect(checkUrl('ssh://root:hunter2@internal.example.com/b')?.ruleId).toBe('bash-url-creds');
  });
});

// The documented bypasses of the shell-obfuscation matcher, ported from the
// workstation generation. Verified against this engine — these commands DO
// leak secrets but pass the hook by design: the tokenizer cannot interpret
// real shell semantics. A test here documents the gap rather than hiding it.
describe('secret-rules: known limits (shell obfuscation bypasses)', () => {
  test.each([
    "printf '\\x2e\\x65\\x6e\\x76' | xargs cat",
    'F=secret_path_var; cat $F',
    'cat $(echo Lmlu | base64 -d)nv',
  ])('does NOT detect obfuscated reference: %s', (cmd) => {
    expect(checkSecretBash(cmd)).toBeNull();
  });
});
