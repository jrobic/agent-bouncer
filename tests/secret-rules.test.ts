import { describe, expect, test } from 'bun:test';
import { checkPath, checkSecretBash, checkUrl } from '../src/secret-rules.ts';

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

  describe('ruleId age-identity: every default sops and age identity location', () => {
    test('ruleId age-identity: the macOS default identity location is blocked', () => {
      expect(checkPath('/Users/user/Library/Application Support/sops/age/keys.txt')).toMatchObject({
        verdict: 'block',
        ruleId: 'age-identity',
      });
    });

    test.each([
      '/home/user/.config/sops/age/keys.txt',
      '/srv/age/keys.txt',
    ])('%s is blocked', (path) => {
      expect(checkPath(path)).toMatchObject({ verdict: 'block', ruleId: 'age-identity' });
    });

    test.each([
      '/repo/.sops.yaml',
      '/home/user/.config/sops/config.yaml',
    ])('%s is allowed', (path) => {
      expect(checkPath(path)).toBeNull();
    });

    test('Bash: a configured age identity reference is blocked by the path scan', () => {
      expect(checkSecretBash('cat ~/.config/sops/age/keys.txt')).toMatchObject({
        verdict: 'block',
        ruleId: 'bash-age-identity',
      });
    });
  });

  describe('ruleId aws-creds: the whole AWS home directory', () => {
    test.each([
      '/home/user/.aws/config',
      '/home/user/.aws/sso/cache/x.json',
      '/home/user/.aws/cli/cache/x.json',
      '/home/user/.aws/',
    ])('%s is blocked', (path) => {
      expect(checkPath(path)).toMatchObject({ verdict: 'block', ruleId: 'aws-creds' });
    });

    test.each([
      '/home/user/.aws-sam/template.yaml',
      '/opt/aws/bin/x',
    ])('%s is allowed', (path) => {
      expect(checkPath(path)).toBeNull();
    });
  });

  test('Bash: an AWS SSO cache reference is blocked by the path scan', () => {
    expect(checkSecretBash('cat ~/.aws/sso/cache/x.json')).toMatchObject({
      verdict: 'block',
      ruleId: 'bash-aws-creds',
    });
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

  // Ticket 14: the binary's OWN audit log — universal (every consumer has
  // it), confirm not block (Jonathan's arbitration: same reasoning as
  // transcript-backup — `bouncer audit` is the sanctioned read path and
  // never goes through this guard at all; a direct ad hoc read is a
  // legitimate, if less common, path that gets asked about, not stopped).
  describe('ruleId bouncer-audit-log: the binary\'s own audit trail', () => {
    test('ruleId bouncer-audit-log: a relative path ending in logs/hooks/bouncer.log is confirmed', () => {
      const hit = checkPath('logs/hooks/bouncer.log');
      expect(hit?.ruleId).toBe('bouncer-audit-log');
      expect(hit?.verdict).toBe('confirm');
    });

    test('an absolute path under an arbitrary CLAUDE_CONFIG_DIR shape is confirmed', () => {
      const hit = checkPath('/custom/config/dir/logs/hooks/bouncer.log');
      expect(hit?.ruleId).toBe('bouncer-audit-log');
      expect(hit?.verdict).toBe('confirm');
    });

    // Rotation sibling: src/adapter/log.ts's rotateIfNeeded always renames
    // to exactly `.log.1` (single slot — a fresh rotation overwrites the
    // previous one via `rename`, never `.2`/`.3`/...), so covering it
    // exactly does not widen onto any other .log file. Chosen over a
    // knownLimit — unlike the predecessor hook-log rule (whose SEVERAL
    // legacy log stems made a wildcard-ish widening a real risk), this
    // rule names exactly one file, so the one-slot rotation sibling can be
    // matched precisely.
    test('the rotation sibling logs/hooks/bouncer.log.1 is ALSO confirmed (covered, not a known limit)', () => {
      const hit = checkPath('/home/user/logs/hooks/bouncer.log.1');
      expect(hit?.ruleId).toBe('bouncer-audit-log');
      expect(hit?.verdict).toBe('confirm');
    });

    test('a second rotation generation (.log.2, which the engine never produces) is NOT matched', () => {
      // Pins the precision of the choice above: the pattern names exactly
      // what rotateIfNeeded can produce, not "any numbered suffix".
      expect(checkPath('/home/user/logs/hooks/bouncer.log.2')).toBeNull();
    });

    test('negative: a file named bouncer.log OUTSIDE logs/hooks/ is not touched', () => {
      // The discriminant is the full logs/hooks/bouncer.log path, not the
      // bare filename — a user's own unrelated file sharing the name is
      // never a bouncer audit log.
      expect(checkPath('/home/user/projects/my-app/bouncer.log')).toBeNull();
      expect(checkPath('/home/user/bouncer.log')).toBeNull();
    });

    test('negative: a near-miss directory name (other-logs/hooks/) does not match', () => {
      expect(checkPath('/home/user/other-logs/hooks/bouncer.log')).toBeNull();
    });

    test('Bash: cat logs/hooks/bouncer.log propagates the confirm verdict, not a hardcoded block', () => {
      // Regression seam: checkSecretBash used to hardcode verdict:"block"
      // on every path-token hit regardless of the underlying rule's own
      // verdict — silently upgrading a "confirm" rule (transcript-backup,
      // and now this one) to "block" the moment it was reached through a
      // Bash command instead of a Read/Grep tool call. Fixed alongside
      // this ticket; see src/secret-rules.ts's checkSecretBash.
      const hit = checkSecretBash('cat logs/hooks/bouncer.log');
      expect(hit?.ruleId).toBe('bash-bouncer-audit-log');
      expect(hit?.verdict).toBe('confirm');
    });
  });

  test('Bash: cat on a transcript-backup path also propagates confirm, not a hardcoded block', () => {
    // Same regression seam as bouncer-audit-log above, proven against the
    // OTHER confirm-verdict rule already in the baseline (ticket 13).
    const hit = checkSecretBash('cat .claude/transcripts/foo.json');
    expect(hit?.ruleId).toBe('bash-transcript-backup');
    expect(hit?.verdict).toBe('confirm');
  });

  // Ticket 19: the policy the binary RUNS ON — <configDir>/bouncer/policy.toml
  // and <configDir>/bouncer/policy.d/ — is the disarmament counterpart of
  // bouncer-audit-log (reconnaissance). Baseline, not overlay: an invalid
  // overlay SET falls back to the baseline (docs/reference/policy.md
  // § Fail-closed behavior), so an overlay-hosted self-protection would be
  // disarmed exactly in the murky scenarios it exists for. Confirm, not
  // block: editing one's own policy is legitimate and gets asked about.
  describe('ruleId bouncer-policy: the policy the binary runs on', () => {
    test('ruleId bouncer-policy: a relative bouncer/policy.toml is confirmed', () => {
      const hit = checkPath('bouncer/policy.toml');
      expect(hit?.ruleId).toBe('bouncer-policy');
      expect(hit?.verdict).toBe('confirm');
    });

    test('a policy.d file under an arbitrary CLAUDE_CONFIG_DIR shape is confirmed', () => {
      const hit = checkPath('/custom/config/dir/bouncer/policy.d/10-personal.toml');
      expect(hit?.ruleId).toBe('bouncer-policy');
      expect(hit?.verdict).toBe('confirm');
    });

    test('the policy.d directory itself (a directory-level read or glob root) is confirmed', () => {
      expect(checkPath('/custom/config/dir/bouncer/policy.d')?.ruleId).toBe('bouncer-policy');
      expect(checkPath('/custom/config/dir/bouncer/policy.d/')?.ruleId).toBe('bouncer-policy');
    });

    test('negative: this repository\'s own baseline sources (policy/*.toml, no bouncer/ segment) are not touched', () => {
      // The baseline lives in `policy/` (a directory, not `policy.toml`),
      // under a checkout whose name only CONTAINS "bouncer" — the
      // `(^|/)bouncer/` anchor never sees a segment boundary there.
      expect(checkPath('/home/user/code/agent-bouncer/policy/secret.toml')).toBeNull();
      expect(checkPath('/home/user/code/agent-bouncer/policy')).toBeNull();
      expect(checkPath('/home/user/code/agent-bouncer/policy.toml')).toBeNull();
    });

    test('negative: a bouncer/ segment without the live policy file or directory does not match', () => {
      // The rule guards what the loader READS (src/adapter/policy.ts's
      // overlayPath/overlayDirPath) — a backup directory alongside is a
      // copy, not the live policy, and stays an ordinary path.
      expect(checkPath('/custom/config/dir/bouncer/policy.d.pre-mount.bak/10-personal.toml')).toBeNull();
      expect(checkPath('/custom/config/dir/bouncer/README.md')).toBeNull();
    });

    // Review round 1: pins the trailing `/`-or-end requirement on the FILE
    // branch too — `(policy\.toml|policy\.d)(/|$)`, not `policy\.d(/|$)`
    // alone — same discriminating gesture as the bouncer-audit-log sibling
    // above pinning `bouncer.log.2` against its own pattern. A `.bak`/`~`
    // copy or a longer near-miss filename is a copy, not the live file.
    test('negative: policy.toml near-misses (.bak, ~, a longer name) are NOT matched', () => {
      expect(checkPath('/custom/config/dir/bouncer/policy.toml.bak')).toBeNull();
      expect(checkPath('/custom/config/dir/bouncer/policy.toml~')).toBeNull();
      expect(checkPath('/custom/config/dir/bouncer/policy.tomlx')).toBeNull();
    });

    test('Bash: appending to a policy.d file propagates the confirm verdict, not a hardcoded block', () => {
      const hit = checkSecretBash('echo "[[override]]" >> ~/.claude/bouncer/policy.d/10-personal.toml');
      expect(hit?.ruleId).toBe('bash-bouncer-policy');
      expect(hit?.verdict).toBe('confirm');
    });

    test('Bash: a cat of the root overlay is ALSO confirmed — secret.path covers reads and writes alike (assumed, not a gap)', () => {
      const hit = checkSecretBash('cat ~/.claude-work/bouncer/policy.toml');
      expect(hit?.ruleId).toBe('bash-bouncer-policy');
      expect(hit?.verdict).toBe('confirm');
    });
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

describe('secret-rules: sops and age decryption', () => {
  test('ruleId sops-decrypt: sops -d f is blocked', () => {
    expect(checkSecretBash('sops -d f')).toMatchObject({ verdict: 'block', ruleId: 'sops-decrypt' });
  });

  test.each([
    'sops --decrypt f',
    'sops decrypt f',
    'sops exec-env f \'pnpm start\'',
    'sops exec-file f \'cmd\'',
    'sops edit f',
    'sops f.yaml',
    'sops --input-type dotenv --output-type dotenv -d f',
    'sops -d f > out',
    'rtk sops -d f',
    'cd x && sops -d f',
    'sops my-app.enc.yaml',
    'SOPS_AGE_KEY_FILE=k sops prod.enc.yaml',
    'env SOPS_AGE_KEY_FILE=k sops prod.enc.yaml',
    'rtk sops prod.enc.yaml',
    'sops ./cfg/prod.enc.yaml',
    'cd x && sops f.yaml',
  ])('%s is blocked', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'sops-decrypt' });
  });

  test.each([
    'sops -e f',
    'sops encrypt f',
    'sops -e -i f',
    `sops set f '["k"]' '"v"'`,
    'sops rotate -i f',
    'sops updatekeys f',
    'sops filestatus f',
    'sops --version',
    'sops --help',
    'echo sops',
    'which sops',
    'brew install sops',
    'brew install sops age',
    'rg sops docs/',
    'git commit -m "add sops config"',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId age-decrypt: age -d f.age is blocked', () => {
    expect(checkSecretBash('age -d f.age')).toMatchObject({ verdict: 'block', ruleId: 'age-decrypt' });
  });

  test.each([
    'age --decrypt -i k f.age',
    'age -d -o out f.age',
    'rage -d f.age',
  ])('%s is blocked', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'age-decrypt' });
  });

  test.each([
    'age -r recipient -o f.age f',
    'age -e f',
    'age-keygen -o k',
    'age --version',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
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
      checkSecretBash('git config \'remote.origin.url\' https://host/x.git')?.ruleId,
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
    expect(checkSecretBash('jq \'.settings.key\' config.json')).toBeNull();
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
    'printf \'\\x2e\\x65\\x6e\\x76\' | xargs cat',
    'F=secret_path_var; cat $F',
    'cat $(echo Lmlu | base64 -d)nv',
  ])('does NOT detect obfuscated reference: %s', (cmd) => {
    expect(checkSecretBash(cmd)).toBeNull();
  });
});
