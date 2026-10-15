import { describe, expect, test } from 'bun:test';
import { BASELINE } from '../src/policy/baseline.ts';
import { isProtectedName } from '../src/protected-names.ts';
import { checkPath, checkSecretBash, checkUrl, createSecretChecker } from '../src/secret-rules.ts';
import { PROTECTED_NAMES, UNPROTECTED_NAMES } from './protected-name-examples.ts';

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
  // gap: rotated .log.1 is not blocked" case and the legacy-naming
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

  test('ruleId dotenv: .envrc is blocked through file-path and Bash token scans', () => {
    expect(checkPath('/repo/.envrc')).toMatchObject({ verdict: 'block', ruleId: 'dotenv' });
    expect(checkSecretBash('cat .envrc')).toMatchObject({ verdict: 'block', ruleId: 'bash-dotenv' });
  });

  test('ruleId shell-history: a representative history path is confirmed', () => {
    expect(checkPath('/home/user/.zsh_history')).toMatchObject({ verdict: 'confirm', ruleId: 'shell-history' });
  });

  test('ruleId shell-history: Bash token scan confirms a history path without blocking the history builtin', () => {
    expect(checkSecretBash('tail -n 50 ~/.bash_history')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-shell-history',
    });
    expect(checkSecretBash('history | tail')).toBeNull();
  });

  test('ruleId session-transcripts: profile JSONL paths are confirmed while memory remains available', () => {
    expect(checkPath('/home/user/.claude/projects/x/abc.jsonl')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'session-transcripts',
    });
    expect(checkPath('/home/user/.claude-work/projects/x/s.jsonl')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'session-transcripts',
    });
    expect(checkSecretBash('grep foo ~/.claude/projects/x/s.jsonl')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-session-transcripts',
    });
    expect(checkPath('/home/user/.claude/projects/x/memory/MEMORY.md')).toBeNull();
  });

  test('ruleId keychain-dump: a Security password printer is blocked', () => {
    expect(checkSecretBash('security find-generic-password -w -s x')).toMatchObject({
      verdict: 'block',
      ruleId: 'keychain-dump',
    });
  });

  test('ruleId credential-printer: gh auth token is confirmed', () => {
    expect(checkSecretBash('gh auth token')).toMatchObject({ verdict: 'confirm', ruleId: 'credential-printer' });
  });

  // Ticket 57 completed the row (same id, `confirm`): the short flag of
  // `auth status`, `glab config get token`, `git credential fill`, a docker
  // credential helper, an npm auth token, the AWS CLI's secret reads. The
  // original forms are listed again so a regression on either side shows.
  test.each([
    'gh auth token',
    'glab auth status --show-token',
    'op read op://v/i/f',
    'op item get x --reveal',
    'gcloud auth print-access-token',
    'aws sts get-session-token',
    'vault kv get secret/x',
    'doppler secrets download',
    'glab auth status -t',
    'gh auth status -t',
    'gh auth status --hostname github.com --show-token',
    'glab config get token --host gitlab.example.com',
    'git credential fill',
    'printf \'protocol=https\\nhost=example.com\\n\' | git credential fill',
    'docker-credential-osxkeychain get',
    'echo https://index.docker.io/v1/ | docker-credential-desktop get',
    'npm config get //registry.npmjs.org/:_authToken',
    'pnpm config get //registry.npmjs.org/:_authToken',
    'npm config get _auth',
    'aws configure get aws_secret_access_key',
    'aws configure get aws_session_token --profile dev',
    'aws configure export-credentials --profile dev',
  ])('credential-printer: %s is confirmed', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'confirm', ruleId: 'credential-printer' });
  });

  test.each([
    'gh auth status',
    'gh auth login',
    'glab auth status',
    'glab auth status --hostname gitlab.example.com',
    'glab auth status -h gitlab.example.com',
    'glab config get host',
    'glab config set token x',
    'git credential approve',
    'docker-credential-osxkeychain list',
    'docker login',
    'npm config get registry',
    'npm config set registry https://registry.example',
    'npm config get //registry.npmjs.org/:_foo',
    'aws configure get region',
    'aws configure get aws_access_key_id',
    'aws configure list',
    'aws configure set region eu-west-1',
  ])('credential-printer: benign %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
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

describe('secret-rules: checkSecretBash quoted prose and heredoc bodies', () => {
  test('ruleId secret-dir: quoted prose with whitespace is not a path candidate', () => {
    expect(checkSecretBash('git commit -m "rotate secrets before release"')).toBeNull();
  });

  test('ruleId ssh-dir: a heredoc prose body is not a path candidate', () => {
    expect(checkSecretBash('cat > notes.md <<\'EOF\'\nsecrets and credentials are prose\nEOF')).toBeNull();
  });

  test('ruleId secret-dir: shell command strings retain the full path scan', () => {
    expect(checkSecretBash('bash -c "cd secrets && cat db.yaml"')?.ruleId).toBe('bash-secret-dir');
  });

  test('ruleId secret-dir: an unterminated quote retains the full path scan', () => {
    expect(checkSecretBash('cat "my secrets')?.ruleId).toBe('bash-secret-dir');
  });

  test('ruleId secret-dir: quoted prose masks path tokens independently', () => {
    expect(checkSecretBash('git commit -m "rotate secrets and/or keys"')).toBeNull();
  });

  test('substitutions do not turn surrounding prose into a secret read', () => {
    expect(checkSecretBash('echo "do not read .env $(printf ok)"')).toBeNull();
    expect(checkSecretBash('echo "do not read .env $(cat .env)"')).toMatchObject({
      verdict: 'block',
      ruleId: 'bash-dotenv',
    });
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

// Environment rows refuse commands that print or reference the agent's
// inherited environment (docs/reference/policy.md).
describe('secret-rules: environment dumps', () => {
  test('ruleId env-dump: env with nothing to run is blocked', () => {
    expect(checkSecretBash('env')).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test.each([
    'env | sort',
    'env -i',
    'env -u HOME',
    'env -0',
    'env --',
    'env FOO=1',
    'env FOO="a b"',
    'env FOO=\'a b\'',
    'FOO=1 env',
    'env 2>&1 | head',
    'env; echo done',
    'cd app && env',
    'KEYS=$(env | cut -d= -f1)',
    'bash -c env',
    'bash -c \'env | sort\'',
    'sh -c \'env\'',
    'sh -c "printenv"',
    '/usr/bin/env',
    'if env | grep -q TOKEN; then echo yes; fi',
    'diff <(env) <(env -i)',
    'time env',
    'rtk env',
    'exec env',
    'echo start\nenv',
    'printenv',
    'printenv -0',
    'printenv | sort',
    'export',
    'export -p | sort',
    'declare -p',
    'declare -px',
    'declare -x',
    'typeset -x',
    'declare',
    'typeset',
    'set',
    'set | grep TOKEN',
    'set; echo done',
    'compgen -e',
    'compgen -e | grep TOKEN',
    'compgen -A export',
    'echo ${!AWS_@}',
    'echo ${!AWS_*}',
  ])('%s is blocked', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  // `env` that runs a command, `set` as an option or a word, an assignment,
  // a word that merely contains `env`, a search pattern that spells it.
  test.each([
    'env FOO=1 make test',
    'env -i FOO=1 make',
    'env -u HOME make',
    'env -- make test',
    'env FOO="a b" make',
    '/usr/bin/env bash',
    '#!/usr/bin/env python3',
    'which env',
    'echo env',
    'pnpm env use 20',
    'conda env list',
    'env = ["TOY_HOME"]',
    'pyenv versions',
    'env -S \'FOO=1 make\'',
    'env -i HOME=$T PATH=/usr/bin:/bin bun run x',
    'cd /tmp && env DIR=\'/var/x y\' omp',
    'printenv HOME',
    'printenv HOME PATH',
    'printenv MY_TOKEN_FILE',
    'export PATH="$PATH:/opt/bin"',
    'export -n FOO',
    'declare -x FOO=bar',
    'declare -a arr=(1 2)',
    'declare -r X=1',
    'declare -f',
    'set -euo pipefail',
    'set -x',
    'set -o pipefail',
    'set --',
    'git remote set-url origin https://example.com/repo.git',
    'npm config set registry https://registry.example',
    'gh variable set FOO --body x',
    'claude config set theme dark',
    'compgen -c',
    'echo "${!arr[@]}"',
    'rg "env|printenv" src',
    'grep -rn "a|env|b" .',
    'ENV FOO=bar',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId env-dump: a fetched URL ending in an env word is not a command', () => {
    expect(checkUrl('https://example.com/search?q=release&env')).toBeNull();
    expect(checkSecretBash('curl -s "https://example.com/search?q=release&env"')).toBeNull();
  });

  test('ruleId env-dump-ps: BSD e and macOS -E print a process environment', () => {
    expect(checkSecretBash('ps eww -p $$')).toMatchObject({ verdict: 'block', ruleId: 'env-dump-ps' });
  });

  test.each([
    'ps e',
    'ps auxe',
    'ps axeww',
    'ps -E',
    'ps -E -o command= -p 4242 | tr " " "\\n"',
    'ps -p 4242 -E',
    'ps ax -E',
  ])('%s is blocked as a process environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-ps' });
  });

  // `-ef`, `-e` (every process, `-A` on macOS) and `aux` print no
  // environment; a `grep -E` after the pipe is grep's, not ps's.
  test.each([
    'ps -ef',
    'ps -e',
    'ps aux',
    'ps -ax -o pid=,command=',
    'ps aux | grep -E "node|bun"',
    'ps -ef | grep -E java',
    'ps -p 4242 -o comm=',
    'ps -U someuser',
    'ps aux --sort=-pcpu | head',
    'docker ps -a',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId env-dump-launchctl: launchctl getenv reads the launchd environment', () => {
    expect(checkSecretBash('launchctl getenv PATH')).toMatchObject({ verdict: 'block', ruleId: 'env-dump-launchctl' });
    expect(checkSecretBash('launchctl list')).toBeNull();
    expect(checkSecretBash('launchctl print gui/501')).toBeNull();
  });

  test('ruleId env-dump-jq: the env builtin and $ENV are blocked', () => {
    expect(checkSecretBash('jq -n env')).toMatchObject({ verdict: 'block', ruleId: 'env-dump-jq' });
  });

  test.each([
    'jq -n \'env | keys\'',
    'jq -n \'$ENV\'',
    'jq -n "\\$ENV | to_entries"',
    'jq -nr \'env|to_entries[]\'',
    'jq -n --arg x 1 env',
    'gojq -n env',
  ])('%s is blocked as the jq environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-jq' });
  });

  // `.env` is a field accessor, `{env: …}` an object key,
  // `env.NAME` one variable (a non-protected one is allowed), and a `| grep
  // env` after the program is not jq.
  test.each([
    'jq -n \'env.PREFIX + "x"\'',
    'jq \'.scripts.env\' package.json',
    'jq \'.env // {}\' settings.json',
    'jq \'{cleanupPeriodDays, env: (.env // {})}\' x.json',
    'jq \'{name, env}\' package.json',
    'jq -n \'$ENV.PATH\'',
    'jq -r .name package.json | grep env',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId env-dump-docker: docker exec … env and docker compose config are blocked', () => {
    expect(checkSecretBash('docker exec app env')).toMatchObject({ verdict: 'block', ruleId: 'env-dump-docker' });
  });

  test.each([
    'docker exec -it app printenv',
    'docker compose exec web env | sort',
    'docker-compose exec web env',
    'docker compose config',
    'docker compose -f compose.yaml config',
    'docker-compose -p proj --profile dev config',
    'docker compose config --no-interpolate',
    'docker compose config web',
    'docker compose config > resolved.yml',
    'docker compose config -q; docker compose config',
  ])('%s is blocked as a container environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-docker' });
  });

  test.each([
    'docker exec app env FOO=1 make test',
    'docker exec app ls -la',
    'docker compose up -d',
    'docker compose exec lab herdr config check',
    'docker compose --project-name p --file f.yaml exec --tty=false lab herdr config check',
    'docker config ls',
    'docker compose config --quiet',
    'docker compose config -q',
    'docker compose -f a.yml -f b.yml config --services',
    'docker compose config --volumes',
    'docker compose config --profiles',
    'docker compose config --images',
    'docker compose config --hash=web',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId env-dump-docker-inspect: docker inspect is confirmed, not blocked', () => {
    expect(checkSecretBash('docker inspect app-db')).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-docker-inspect' });
    expect(checkSecretBash('docker inspect --format \'{{.State.Status}}\' app-db')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'env-dump-docker-inspect',
    });
    expect(checkSecretBash('docker container inspect app-db')).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-docker-inspect' });
    expect(checkSecretBash('docker network inspect bridge')).toBeNull();
    expect(checkSecretBash('docker image inspect alpine')).toBeNull();
  });

  // Past the eight the lead-in reads, the command is not judged: the row asks,
  // and a block found elsewhere in the same command still wins.
  test('ruleId env-dump-unjudged: a ninth wrapper or option asks instead of passing', () => {
    const run = (word: string, count: number): string => Array.from({ length: count }, () => word).join(' ');
    expect(checkSecretBash(`timeout ${run('-k 1', 9)} 5 env`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    expect(checkSecretBash(`timeout ${run('-k 1', 8)} 5 env`)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
    expect(checkSecretBash(`${run('nice', 9)} make; env`)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test('ruleId env-dump-unjudged: a value past 256 characters asks instead of passing', () => {
    const value = (length: number): string => 'x'.repeat(length);
    expect(checkSecretBash(`A=${value(256)} env`)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
    expect(checkSecretBash(`A=${value(257)} env`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    expect(checkSecretBash(`env A=${value(256)}`)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
    expect(checkSecretBash(`env A=${value(257)}`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    expect(checkSecretBash(`env -u ${value(257)}`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    expect(checkSecretBash(`timeout ${'0'.repeat(256)}5 env`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    expect(checkSecretBash(`bash -o ${value(257)} -c env`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-dump-unjudged' });
    // A lone assignment runs nothing, however long its value.
    expect(checkSecretBash(`KEY=${value(300)}`)).toBeNull();
  });

  test('a block row beats a confirm row in the same command (first match wins, block rows come first)', () => {
    expect(checkSecretBash('docker inspect app-db && env')).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
    expect(checkSecretBash('gh auth token; env')).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
    expect(checkSecretBash('curl -H "x: $API_TOKEN" u && echo $DB_PASSWORD')).toMatchObject({
      verdict: 'block',
      ruleId: 'env-ref-display',
    });
  });

  test('ruleId proc-environ: /proc/<pid>/environ is a secret path, for Read and for Bash', () => {
    expect(checkPath('/proc/self/environ')).toMatchObject({ verdict: 'block', ruleId: 'proc-environ' });
    expect(checkPath('/proc/thread-self/environ')?.ruleId).toBe('proc-environ');
    expect(checkPath('/proc/4242/environ')?.ruleId).toBe('proc-environ');
    expect(checkPath('/proc/4242/task/4242/environ')?.ruleId).toBe('proc-environ');
    expect(checkPath('proc/self/environ')?.ruleId).toBe('proc-environ');
    expect(checkSecretBash('cat /proc/self/environ')).toMatchObject({ verdict: 'block', ruleId: 'bash-proc-environ' });
    expect(checkSecretBash('tr \'\\0\' \'\\n\' < /proc/4242/environ')?.ruleId).toBe('bash-proc-environ');
  });

  test('ruleId proc-environ: the rest of /proc stays readable', () => {
    expect(checkPath('/proc/self/status')).toBeNull();
    expect(checkPath('/proc/cpuinfo')).toBeNull();
    expect(checkPath('/home/user/notes/proc/self/environ.md')).toBeNull();
    expect(checkSecretBash('cat /proc/self/status')).toBeNull();
  });
});

describe('secret-rules: references to a protected variable', () => {
  test('ruleId env-ref-display: a protected variable fed to echo is blocked', () => {
    expect(checkSecretBash('echo $ATLASSIAN_TOKEN')).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
  });

  test.each([
    'echo "$API_KEY"',
    'echo ${GITHUB_TOKEN:-none}',
    'printf %s "${SONARQUBE_TOKEN}"',
    'echo "$(printenv DB_PASSWORD)"',
    'printenv ATLASSIAN_TOKEN',
    'printenv HOME ATLASSIAN_TOKEN',
    'printenv "GITHUB_TOKEN"',
    'docker exec app printenv DB_PASSWORD',
    'declare -p ATLASSIAN_TOKEN',
    'typeset -px AWS_SECRET_ACCESS_KEY',
    'jq -n env.ATLASSIAN_TOKEN',
    'jq -n \'.a + env.GITHUB_TOKEN\'',
    'jq -n \'$ENV.GITHUB_TOKEN\'',
    'node -e "console.log(process.env.ATLASSIAN_TOKEN)"',
    'node -e "console.log(process.env[\'API_KEY\'])"',
    'node -e "console.error(process.env?.NPM_TOKEN)"',
    'node -p "process.env.GITHUB_TOKEN"',
    'node -pe "process.env.GITHUB_TOKEN"',
    'bun -e "console.log(Bun.env.NPM_TOKEN)"',
    'deno eval "console.log(Deno.env.get(\'API_KEY\'))"',
    'python3 -c "import os;print(os.environ[\'API_KEY\'])"',
    'python3 -c "import os;print(os.environ[\\"API_KEY\\"])"',
    'python3 -c "import os;print(os.environ.get(\'API_KEY\'))"',
    'python3 -c "import os;print(os.getenv(\'API_KEY\'))"',
    'ruby -e \'puts ENV["ATLASSIAN_TOKEN"]\'',
    'ruby -e \'puts ENV.fetch("GITHUB_TOKEN")\'',
    'awk \'BEGIN{print ENVIRON["ATLASSIAN_TOKEN"]}\'',
    'php -r \'echo getenv("API_KEY");\'',
    'go run -e \'fmt.Println(os.Getenv("API_KEY"))\'',
    'echo $AWS_SECRET_ACCESS_KEY',
    'echo $STRIPE_API_KEY',
    'echo $ANTHROPIC_API_KEY',
    'echo $TOKEN',
  ])('%s is blocked as a display', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
  });

  test('ruleId env-ref: a protected variable that feeds no display is confirmed', () => {
    expect(checkSecretBash('curl -H "Authorization: Bearer $SONARQUBE_TOKEN" https://sonar.example')).toMatchObject({
      verdict: 'confirm',
      ruleId: 'env-ref',
    });
  });

  test.each([
    'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.example',
    'export GH_TOKEN=$GITHUB_TOKEN',
    'git commit -m "docs: $API_TOKEN usage"',
    'echo calling && curl -H "x: $API_TOKEN" https://api.example',
    'echo calling | curl -H "x: $API_TOKEN" https://api.example',
    'node -e "fetch(url,{headers:{authorization:process.env.API_KEY}})"',
    'node -e "const k = process.env[\'API_KEY\']; use(k)"',
    'python3 -c "import os;x=os.environ[\'API_KEY\'];use(x)"',
    'ruby -e \'k = ENV["GITHUB_TOKEN"]; use(k)\'',
    'cat > src/db.ts <<\'EOF\'\nexport const password = process.env.DB_PASSWORD;\nEOF',
    'rg process.env.API_KEY src',
  ])('%s is confirmed as a reference', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'confirm', ruleId: 'env-ref' });
  });

  // Decision F1 (the name definition) and its examples live in
  // tests/protected-name-examples.ts, shared with the env-value detector's own
  // drift test: ONE definition (src/protected-names.ts) — the baseline rows
  // write `{{protected-name}}` and the loader fills it in, so the rows and
  // isProtectedName() agree on every name of that list.

  test.each(PROTECTED_NAMES)('protected name %s: the reference rows and isProtectedName agree', (name) => {
    expect(isProtectedName(name)).toBe(true);
    expect(checkSecretBash(`echo $${name}`)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
    expect(checkSecretBash(`echo \${${name}}`)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
    expect(checkSecretBash(`curl -H "x: $${name}" u`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-ref' });
    expect(checkSecretBash(`node -e "console.log(process.env.${name})"`)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
  });

  test.each(UNPROTECTED_NAMES)('unprotected name %s: the reference rows and isProtectedName agree', (name) => {
    expect(isProtectedName(name)).toBe(false);
    expect(checkSecretBash(`echo $${name}`)).toBeNull();
    expect(checkSecretBash(`echo \${${name}}`)).toBeNull();
    expect(checkSecretBash(`curl -H "x: $${name}" u`)).toBeNull();
    expect(checkSecretBash(`node -e "console.log(process.env.${name})"`)).toBeNull();
  });

  test('the shell length expansion ${#TOKEN} names the variable but reads no value', () => {
    expect(checkSecretBash('echo ${#TOKEN}')).toBeNull();
  });

  test.each([
    'echo $HOME',
    'echo ${PATH}',
    'node -e "console.log(process.env.NODE_ENV)"',
    'node -e "console.log(process.env[\'HOME\'])"',
    'python3 -c "import os;print(os.environ[\'HOME\'], os.environ.get(\'PATH\', \'\'))"',
    'ruby -e \'p ENV["HOME"]\'',
    'awk \'BEGIN{print ENVIRON["HOME"]}\'',
    'php -r \'echo getenv("HOME");\'',
    'echo $(printenv PATH)',
    'ENV=production npm run build',
    'NODE_ENV=test pnpm test',
    'cat > Dockerfile <<\'EOF\'\nFROM node:20\nENV NODE_ENV=production\nEOF',
  ])('benign: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test('ruleId env-ref-whole: the whole environment object is blocked', () => {
    expect(checkSecretBash('node -p process.env')).toMatchObject({ verdict: 'block', ruleId: 'env-ref-whole' });
  });

  test.each([
    'node -e "console.log(process.env)"',
    'node -e "console.log(JSON.stringify(process.env, null, 2))"',
    'node -e "console.log(Object.keys(process.env))"',
    'node -e "const {A} = process.env; console.log(A)"',
    'node -e "run({...process.env, B: 1})"',
    'bun -e "console.log(Bun.env)"',
    'deno eval "console.log(Deno.env.toObject())"',
    'python3 -c "import os;print(os.environ)"',
    'python3 -c "import os;print(dict(os.environ))"',
    'python3 -c "import os;print(os.environ.copy())"',
    'python3 -c "import os;print(list(os.environ.items()))"',
    'ruby -e \'puts ENV.to_h\'',
    'ruby -e \'p ENV\'',
    'ruby -e \'pp ENV\'',
    'awk \'BEGIN{for (k in ENVIRON) print k}\'',
    'git commit -m "fix: read process.env at startup"',
  ])('%s is blocked as the whole environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-whole' });
  });

  // A search PATTERN that spells the object is not an access; a command that
  // is not only searches still is (the except reads the whole command).
  test.each([
    'rg \'process.env\' src',
    'grep -rn os.environ .',
    'grep -n "BOUNCER_BIN\\|process.env" run.ts | sed -n \'1,6p\'',
    'cd src && rg \'os.environ\' .',
    'rg \'process.env\' src | head -20',
    'git grep -n \'process.env\'',
    'rtk rg -e \'process.env\'',
    'cd src && grep -n "env\\b\\|process.env" run.ts cli.ts | head -30; echo ---; grep -rn SCRUB . -l 2>/dev/null | head',
    'git log -S\'process.env\' --oneline',
  ])('search: %s is allowed', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test.each([
    'rg \'process.env\' src && node -p process.env',
    'grep -rn x . ; python3 -c "import os;print(os.environ)"',
    'rg process.env $(node -p process.env)',
    'rg foo | node -p process.env',
  ])('search then a real access: %s is still blocked', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-whole' });
  });

  test('a documentation URL that spells the object is not an access', () => {
    expect(checkUrl('https://docs.python.org/3/library/os.html#os.environ')).toBeNull();
    expect(checkUrl('https://nodejs.org/docs/latest/api/process.env')).toBeNull();
  });

  test('ruleId env-ref-computed: a name computed at runtime counts as whole-environment access', () => {
    expect(checkSecretBash('python3 -c "import os;print(os.environ.get(chr(65)+chr(84)))"')).toMatchObject({
      verdict: 'block',
      ruleId: 'env-ref-computed',
    });
  });

  test.each([
    'python3 -c "import os;print(os.environ.get(name))"',
    'python3 -c "import os;print(os.environ[key])"',
    'python3 -c "import os;print(os.getenv(k))"',
    'python3 -c "import os;print(os.getenv(f\'{p}_X\'))"',
    'python3 -c "import os;print(os.environ.get(\'AT\' + \'LASSIAN_TOKEN\'))"',
    'node -e "console.log(process.env[name])"',
    'node -e "console.log(process.env[\'AT\' + \'LASSIAN_TOKEN\'])"',
    'node -e "console.log(process.env[`${p}_TOKEN`])"',
    'ruby -e \'puts ENV[name]\'',
    'ruby -e \'puts ENV.fetch(name)\'',
    'awk \'BEGIN{print ENVIRON[k]}\'',
    'php -r \'echo getenv($k);\'',
    'echo "${!name}"',
    'printenv "$name"',
  ])('%s is blocked as a computed name', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-computed' });
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

  test.each([
    'git -C /tmp config remote.origin.url https://example.com/repo.git',
    'git --no-pager -C /tmp config remote.origin.url https://example.com/repo.git',
  ])('ruleId bash-git-leak-remote-url: global options preserve a remote-url write: %s', (cmd) => {
    expect(checkSecretBash(cmd)?.ruleId).toBe('bash-git-leak-remote-url');
  });

  test('git_remote_url ignores an unrelated replacement candidate and owns its unsafe predicate', () => {
    const checker = createSecretChecker(
      {
        ...BASELINE.rules.secret,
        bash: BASELINE.rules.secret.bash.map((rule) =>
          rule.id === 'bash-git-leak-remote-url'
            ? { ...rule, regex: '\\becho\\s+unrelated\\b', except: '\\becho\\s+unrelated\\b' }
            : rule
        ),
      },
      BASELINE.rules.command.git.config_read_modes,
    );

    expect(checker.checkSecretBash('echo unrelated; git config --get remote.origin.url')).toBeNull();
    expect(
      checker.checkSecretBash(
        'echo unrelated; git -C /tmp config remote.origin.url https://example.com/repo.git',
      )?.ruleId,
    ).toBe('bash-git-leak-remote-url');
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

describe('secret-rules: glob path readings', () => {
  test('Bash: captures a token with multiple glob metacharacters', () => {
    expect(checkSecretBash('cat **/*.pem')?.ruleId).toBe('bash-crypto-key');
  });

  test('Bash: any-name reading replaces every glob metacharacter', () => {
    const checker = createSecretChecker({
      path: [{ id: 'glob-name', regex: '(^|/)xx/x\\.glob$', reason: 'glob name', verdict: 'block' }],
      bash: [],
    }, []);
    expect(checker.checkSecretBash('cat **/*.glob')?.ruleId).toBe('bash-glob-name');
  });

  test('Bash: empty-name reading removes every glob metacharacter', () => {
    const checker = createSecretChecker({
      path: [{ id: 'glob-empty', regex: '(^|/)\\.glob$', reason: 'glob empty', verdict: 'block' }],
      bash: [],
    }, []);
    expect(checker.checkSecretBash('cat ?*.glob')?.ruleId).toBe('bash-glob-empty');
  });

  test('Bash: keeps the strictest verdict across glob readings', () => {
    const checker = createSecretChecker({
      path: [
        { id: 'glob-name', regex: '(^|/)x\\.glob$', reason: 'glob name', verdict: 'confirm' },
        { id: 'glob-empty', regex: '(^|/)\\.glob$', reason: 'glob empty', verdict: 'block' },
      ],
      bash: [],
    }, []);
    expect(checker.checkSecretBash('cat *.glob')).toMatchObject({
      verdict: 'block',
      ruleId: 'bash-glob-empty',
    });
  });

  test('Bash: does not synthesize a glob suffix absent from the token', () => {
    const checker = createSecretChecker({
      path: [{ id: 'glob-suffix', regex: '(^|/)\\.zshrc$', reason: 'glob suffix', verdict: 'block' }],
      bash: [],
    }, []);
    expect(checker.checkSecretBash('cat ~/.zsh*')).toBeNull();
  });
});

describe('secret-rules: path scan exclusions for search patterns', () => {
  test('benign: explicit pattern argument is allowed', () => {
    expect(checkSecretBash('rg -e \'\\.env|dotenv\' src')).toBeNull();
  });

  test('benign: positional pattern after combined search flags is allowed', () => {
    expect(checkSecretBash('grep -ril \'\\.env\' src')).toBeNull();
  });

  test('benign: wrapper-prefixed pattern argument is allowed', () => {
    expect(checkSecretBash('command grep -e \'\\.env\' src')).toBeNull();
  });

  test('benign: pattern in a later command segment is allowed', () => {
    expect(checkSecretBash('cd src && rg -e \'\\.env\' .')).toBeNull();
  });

  test('ruleId dotenv: undeclared option retains the full path scan', () => {
    expect(checkSecretBash('rg --future-option \'\\.env\' src')?.ruleId).toBe('bash-dotenv');
  });

  test('ruleId dotenv: pattern file remains scanned', () => {
    expect(checkSecretBash('grep -f .env x')?.ruleId).toBe('bash-dotenv');
  });

  test('ruleId dotenv: file-selection glob remains scanned', () => {
    expect(checkSecretBash('rg -e \'\\.env\' -g \'*.env\' src')?.ruleId).toBe('bash-dotenv');
  });

  test('benign: Object.prototype tool name falls back to the full path scan', () => {
    const check = () => checkSecretBash('valueOf -n foo');
    expect(check).not.toThrow();
    expect(check()).toBeNull();
  });
});

// Legacy delta: checkUrl gives extractTargets()'s `urls` bucket
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
// legacy implementation. Verified against this engine — these commands DO
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

// Environment regression coverage: ps precision, compose flags, protected
// reference forms and pathological inputs.
describe('secret-rules: environment rows and linear matching', () => {
  // The BSD `e` rides on the FIRST operand of a `ps` at command position:
  // a later word, a compose service, prose that mentions ps never counts.
  test.each([
    'docker compose ps redis',
    'docker compose ps postgres',
    'git commit -m \'fix ps output here\'',
    'echo ps eww',
    'which ps e',
    'kubectl get pods | ps',
    'pgrep -fl postgres | xargs ps -o comm=',
  ])('benign: %s is not a ps environment dump', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test.each([
    'time ps eww -p 4242',
    'FOO=1 ps e',
    'cd app && ps auxe',
    'sh -c \'ps e\'',
    '/bin/ps eww -p 1',
  ])('%s is blocked as a process environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-ps' });
  });

  // One name (`API_KEY`), every form the reference rows know, in a display
  // (block) and in a plain statement (confirm); the same forms with a
  // computed name are blocked as such.
  const FORMS = [
    '$API_KEY',
    '${API_KEY}',
    'process.env.API_KEY',
    'process.env?.API_KEY',
    'process.env["API_KEY"]',
    'process.env[\'API_KEY\']',
    'Bun.env.API_KEY',
    'Bun.env["API_KEY"]',
    'Deno.env.get("API_KEY")',
    'os.environ["API_KEY"]',
    'os.environ.get("API_KEY")',
    'os.environ.pop("API_KEY")',
    'os.environ.setdefault("API_KEY", "x")',
    'os.getenv("API_KEY")',
    'environ.get("API_KEY")',
    'ENV["API_KEY"]',
    'ENV.fetch("API_KEY")',
    'ENV.dig("API_KEY")',
    'ENVIRON["API_KEY"]',
    'getenv("API_KEY")',
    'os.Getenv("API_KEY")',
    'System.getenv("API_KEY")',
    'env::var("API_KEY")',
    'env::var_os("API_KEY")',
  ];

  test.each(FORMS)('form %s: a display blocks, a plain statement confirms', (form) => {
    expect(checkSecretBash(`echo ${form}`)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-display' });
    expect(checkSecretBash(`x = ${form}`)).toMatchObject({ verdict: 'confirm', ruleId: 'env-ref' });
  });

  test.each([
    'process.env[name]',
    'Bun.env[name]',
    'os.environ[name]',
    'ENV[name]',
    'ENVIRON[name]',
    'Deno.env.get(name)',
    'os.environ.get(name)',
    'os.getenv(name)',
    'environ.get(name)',
    'ENV.fetch(name)',
    'getenv(name)',
    'os.Getenv(name)',
    'System.getenv(name)',
    'env::var(name)',
  ])('form %s with a computed name is blocked as computed', (form) => {
    expect(checkSecretBash(`x = ${form}`)).toMatchObject({ verdict: 'block', ruleId: 'env-ref-computed' });
  });

  // The reviewer's pathological inputs (plus a few of mine): every environment
  // row, regex and except, must stay far below the seconds a backtracking
  // regression costs (18.4 s measured before the fix pass). The ceiling is
  // 1 s, not the 49 ms worst case measured locally: a shared CI runner took
  // 154 ms on one input (v1.8.0 release run), and this test exists to catch
  // catastrophic backtracking, not runner speed.
  const PATHOLOGICAL: ReadonlyArray<readonly [string, string]> = [
    ['docker exec repeated (24 KB)', 'docker exec '.repeat(2000)],
    ['a search, 20 KB of spaces, then a substitution', `grep process.env${' '.repeat(20000)}$(true)`],
    ['jq repeated (15 KB)', 'jq '.repeat(5000)],
    ['ps repeated (30 KB)', 'ps '.repeat(10000)],
    ['ps with a word per operand (30 KB)', `ps ${'ab '.repeat(10000)}`],
    ['ps after separators (30 KB)', '; ps '.repeat(6000)],
    ['display words repeated (20 KB)', 'echo '.repeat(4000)],
    ['display words inside a substitution (20 KB)', `echo $(${'echo '.repeat(4000)})`],
    ['compose options (25 KB)', `docker compose ${'-f a '.repeat(5000)}x`],
    ['compose config flags (25 KB)', `docker compose config ${'web '.repeat(6000)}-q`],
    ['env options (18 KB)', `env ${'-i '.repeat(6000)}x`],
    ['spaces after env (20 KB)', `env${' '.repeat(20000)}x`],
    ['jq after separators (25 KB)', '; jq '.repeat(5000)],
    ['jq after pipes (30 KB)', ' | jq '.repeat(5000)],
    ['docker exec after separators (28 KB)', '; docker exec '.repeat(2000)],
    ['launchctl after separators (24 KB)', '; launchctl '.repeat(2000)],
    ['wrappers repeated, then jq (25 KB)', `${'time '.repeat(5000)}jq`],
    ['wrappers after separators (28 KB)', '; time '.repeat(4000)],
    ['timeout wrappers repeated (27 KB)', 'timeout 5 '.repeat(3000) + 'env'],
    ['watch wrappers repeated (22 KB)', 'watch -n 1 '.repeat(2000) + 'env'],
    ['timeout wrappers after separators (26 KB)', '; timeout 5 '.repeat(2000)],
    ['timeout unknown option repeated (220 B)', 'timeout -x '.repeat(20)],
    [
      'timeout unknown option plus nested shell and wrapper split',
      'timeout -x '.repeat(8) + 'bash -c ' + 'timeout -x '.repeat(100) + 'env',
    ],
    ['xargs unknown option repeated', 'xargs -x '.repeat(100) + 'env'],
    ['watch unknown option repeated', 'watch -b '.repeat(100) + '\'env\''],
    [
      'timeout unknown options, nested shell and repeats without a command',
      'timeout -x '.repeat(8) + 'bash -c ' + 'timeout -x '.repeat(100),
    ],
    ['xargs unknown options repeated without a command', 'xargs -x '.repeat(100)],
    ['watch unknown options repeated without a command', 'watch -b '.repeat(100)],
    [
      'interleaved unknown wrappers with ambiguous command words',
      'timeout -x '.repeat(40) + 'xargs -x '.repeat(40) + 'watch -b '.repeat(40),
    ],
    ['timeout and xargs ambiguous wrapper splits', 'timeout -x '.repeat(100) + 'xargs -x '.repeat(100) + 'env'],
    ['xargs and watch ambiguous wrapper splits', 'xargs -x '.repeat(100) + 'watch -b '.repeat(100) + 'env'],
    ['watch and timeout ambiguous wrapper splits', 'watch -b '.repeat(100) + 'timeout -x '.repeat(100) + 'env'],
    ['xargs shell and watch ambiguous wrapper splits', 'xargs -x '.repeat(100) + 'bash -c ' + 'watch -b '.repeat(100) + 'env'],
    ['braces (2 KB)', '{ '.repeat(1000)],
    ['braces (4 KB)', '{ '.repeat(2000)],
    ['one word (20 KB)', 'a'.repeat(20000)],
    ['one path (20 KB)', 'a/'.repeat(10000)],
    ['braces and parentheses (20 KB)', '{ ( '.repeat(5000)],
    ['a shell -c, then braces (10 KB)', 'bash -c ' + '{ '.repeat(5000)],
    ['a word without a space (40 KB)', 'x'.repeat(40000)],
    ['a path that ends in a shell (40 KB)', '/usr'.repeat(10000) + '/bin/bash'],
    ['shell names glued to dashes (20 KB)', 'sh -'.repeat(5000)],
    ['assignments that open braces (20 KB)', 'A={ '.repeat(5000)],
    ['env options whose values open braces (20 KB)', '{env -u'.repeat(2857)],
    ['env options whose values open backticks (20 KB)', '`env -u'.repeat(2857)],
    ['env assignments whose values open braces (20 KB)', 'env A={'.repeat(2857)],
    ['declare flags that hold x twice (30 flags)', `declare${' -xx'.repeat(30)} Q`],
    ['glued assignments that open braces (36 KB)', '{A='.repeat(12000)],
    ['glued assignments that open backticks (36 KB)', '`A='.repeat(12000)],
    ['glued timeout signals that open braces (88 KB)', '{timeout -s'.repeat(8000)],
    ['glued xargs sizes that open braces (72 KB)', '{xargs -s'.repeat(8000)],
    ['glued watch intervals that open braces (72 KB)', '{watch -n'.repeat(8000)],
    // The printenv, export and declare flag runs have no bound; this pins that they stay linear.
    ['declare with ten thousand -x flags (30 KB)', `declare${' -x'.repeat(10000)}`],
  ];

  test.each(PATHOLOGICAL)('pathological input stays fast: %s', (_name, input) => {
    for (const rule of BASELINE.rules.secret.bash.filter((r) => r.id.startsWith('env-'))) {
      const regex = new RegExp(rule.regex, rule.flags);
      const except = rule.except === undefined ? null : new RegExp(rule.except, rule.flags);
      const start = performance.now();
      if (regex.test(input) && except !== null) except.test(input);
      expect(performance.now() - start, rule.id).toBeLessThan(1000);
    }
  });
});

describe('secret-rules: environment-specific command starts', () => {
  test.each([
    'find . -exec sh -c \'env\' \\;',
    'stdbuf -o0 bash -c \'env\'',
    'flock f bash -c \'env\'',
    'caffeinate bash -c \'env\'',
    'script -q /dev/null bash -c \'env\'',
    'docker compose exec app sh -c \'env\'',
    'docker exec c /bin/sh -c \'env\'',
    'docker exec c ksh -c \'env\'',
    'docker --context x exec c sh -c \'env\'',
    'podman exec c bash -lc \'env\'',
    'kubectl exec pod -- sh -c \'env\'',
    '/bin/bash -lc \'env\'',
    'ksh -ec \'printenv\'',
  ])('%s blocks a command read by a shell', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test.each([
    'true&&env',
    'true &&env',
    'true&env',
    'x=1&&set',
    'true | env',
    'true |env',
  ])('%s starts an environment command', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test.each([
    'timeout -x env',
    'timeout -x 5 env',
    'xargs -x env',
  ])('%s keeps an unknown wrapper option conservative', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test.each([
    'limactl shell vm -- bash -c \'env\'',
    'limactl shell vm -- bash -c \'printenv\'',
    'ssh h \'printenv\'',
    'ssh h \'bash -lc "env"\'',
    'docker exec c sh -c \'echo env\'',
    'true|env',
    'node -e \'console.log(env)\'',
    'python3 -c \'print(set)\'',
    'git commit -m "docs: explain (env) usage"',
    'grep -n "(env)" README.md',
    '{ env }',
  ])('%s is not an environment dump command', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test.each([
    '(env)',
    '( env )',
    'true && (env)',
    '{ env; }',
    '{ env;}',
  ])('%s starts an environment dump command', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });

  test.each([
    'docker exec c sh -c \'env\'',
    'docker exec c bash -c "printenv"',
    'docker exec c zsh -c \'env\'',
    'docker exec c dash -c \'printenv\'',
  ])('%s blocks a container environment dump', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump' });
  });
});

// These rows share command-position matching: a search or sentence that only
// spells a command is not itself the command.
describe('secret-rules: launchctl, docker and jq rows read command position', () => {
  test.each([
    'grep -n "TERM\\|launchctl getenv" docs/reference/policy.md',
    'git commit -m \'docs: launchctl getenv reads the launchd environment\'',
    'ls -la # see also launchctl getenv PATH',
    'git commit -m \'docs: jq -n env dumps the environment\'',
    'ls -la # see also jq -n env',
    'grep -rn "jq -n env" scripts',
    'ls -la # see also docker exec app env',
    'make test # same as docker compose config',
    'git log --oneline -S\'docker compose config\' -- docs',
  ])('benign: %s only spells a command', (command) => {
    expect(checkSecretBash(command)).toBeNull();
  });

  test.each([
    'launchctl getenv PATH',
    '/bin/launchctl getenv PATH',
    'cd app && launchctl getenv PATH',
    'FOO=1 launchctl getenv PATH',
    'command launchctl getenv PATH',
    'sh -c \'launchctl getenv PATH\'',
    'x=$(launchctl getenv PATH)',
    'if true; then launchctl getenv PATH; fi',
  ])('%s is blocked as the launchd environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-launchctl' });
  });

  // A jq after a pipe IS at command position (the lead-in takes a pipe
  // preceded by whitespace), so a dump fed through a pipeline stays blocked.
  test.each([
    'jq -n env',
    'cat data.json | jq -n env',
    'curl -s https://api.example.com/x | jq env',
    'time jq -n env',
    'FOO=1 jq -n env',
    '/usr/bin/jq -n \'$ENV\'',
    'cd app && gojq -n env',
    'sh -c "jq -n env"',
    'x=$(jq -n env)',
  ])('%s is blocked as the jq environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-jq' });
  });

  test.each([
    'docker exec app env',
    '/usr/local/bin/docker exec app env',
    'cd app && docker compose config',
    'FOO=1 docker compose config',
    'command docker exec app printenv',
    'sh -c \'docker exec app env | sort\'',
    'x=$(docker compose config)',
    'if true; then docker-compose exec web env; fi',
  ])('%s is blocked as a container environment', (command) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId: 'env-dump-docker' });
  });

  // Wrappers preserve command position across the environment rows. A pipe
  // without preceding whitespace remains outside the shared start forms.
  test.each([
    ['timeout 5 docker exec app env', 'env-dump-docker'],
    ['env DOCKER_HOST=ssh://build docker exec app env', 'env-dump-docker'],
    ['watch -n 5 launchctl getenv PATH', 'env-dump-launchctl'],
    ['(docker exec app env)', 'env-dump-docker'],
  ])('%s is checked at command position', (command, ruleId) => {
    expect(checkSecretBash(command)).toMatchObject({ verdict: 'block', ruleId });
  });

  test('a pipe without separating whitespace remains outside the command starts', () => {
    expect(checkSecretBash('cat data.json|jq -n env')).toBeNull();
  });

  // Not a command-position problem: jq IS the command and the text `|env ` sits
  // inside a string literal of its own program, which a regex cannot tell from
  // the builtin. Recorded as a known false positive.
  test('known limit: a jq string literal that holds `|env` still matches', () => {
    expect(checkSecretBash('jq -r \'.[]|select(.cmd|test("nice -n 5|env FOO=1"))\' cases.json')).toMatchObject({
      verdict: 'block',
      ruleId: 'env-dump-jq',
    });
  });
});
