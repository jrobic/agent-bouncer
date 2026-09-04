import { describe, expect, test } from 'bun:test';
import { checkBash as checkCommandBash, checkGit, GIT_BENIGN_PREFIXES, WRAPPER_OPTION_POLICIES } from '../src/command-rules.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { AskFlagsRule, SafeFirstArgRule, SafeGrammarRule } from '../src/policy/schema.ts';

// ─────────────────────────────────────────────────────────────────────────
// REPOINTED (ticket 06): every rule table this file locks used to be a TS
// array literal or a TS if-chain; they are now policy/*.toml data (one
// file per family since ticket 12), loaded through src/policy/baseline.ts.
// The repointing touches WHERE each
// digest reads from, never the digest DISCIPLINE: this is still a tripwire
// that names the mutated entry at its own index, never a hash, and the
// frozen arrays below are still DERIVED by running the real projection and
// printing it, never hand-transcribed.
//
// Two structures actually got SIMPLER to lock, not just relocated:
//   • secret.path (formerly PATH_RULES) no longer needs the source-text
//     scrape this file used to run (bounds, `significantLines`,
//     `uniqueIndexOf`) — a TOML array has no "is this predicate function
//     the live one" ambiguity a `test: (p) => …` closure had. It is
//     digested exactly like the four regex tables below.
//   • The git conditional chain (16 subcommands, formerly 15
//     `if (sub === …)` blocks scraped out of command-rules.ts) is now DATA
//     for 14 of them — ask_flags/safe_first_arg/safe_grammar, digested
//     directly — plus the two named engine escapes (checkout, restore),
//     whose behaviour is asserted the same way it always was (the
//     GIT_CONDITIONAL_MATRIX below, unchanged).
// ─────────────────────────────────────────────────────────────────────────

function ruleDigest(
  rules: readonly { readonly id: string; readonly regex: string; readonly flags?: string; }[],
): string[] {
  return rules.map((r, i) => `${i} ${r.id} ${r.regex} ${r.flags ?? ''}`);
}

function orderedValueDigest(values: Iterable<string>): string[] {
  return [...values].map((value, index) => `${index} ${value}`);
}

const EXPECTED_PRIVILEGE_TOOL_DIGEST: readonly string[] = [
  '0 sudo',
  '1 doas',
  '2 pkexec',
  '3 runas',
  '4 please',
];

test('guards-digest: privilege tools are frozen exhaustively and in order', () => {
  expect(orderedValueDigest(BASELINE.rules.command.privilege_escalation.commands)).toEqual([
    ...EXPECTED_PRIVILEGE_TOOL_DIGEST,
  ]);
});

function wrapperPolicyDigest(
  policies: Readonly<
    Record<
      string,
      {
        readonly flags: ReadonlySet<string>;
        readonly optionsWithArg: ReadonlySet<string>;
        readonly acceptsAssignments?: true;
      }
    >
  >,
): string[] {
  return Object.entries(policies).map(([name, policy], index) =>
    `${index} ${name} flags=[${[...policy.flags].join(',')}] `
    + `args=[${[...policy.optionsWithArg].join(',')}] `
    + `assignments=${policy.acceptsAssignments === true}`
  );
}

const EXPECTED_WRAPPER_POLICY_DIGEST: readonly string[] = [
  '0 rtk flags=[] args=[] assignments=false',
  '1 proxy flags=[] args=[] assignments=false',
  '2 command flags=[--] args=[] assignments=false',
  '3 exec flags=[--] args=[] assignments=false',
  '4 env flags=[--,-i] args=[-u] assignments=true',
  '5 nice flags=[] args=[-n] assignments=false',
  '6 time flags=[-p] args=[] assignments=false',
  '7 builtin flags=[] args=[] assignments=false',
];

test('guards-digest: wrapper option policies freeze names, flags, arities, and order', () => {
  // WRAPPER_OPTION_POLICIES stays TS (tokenizer grammar, not a security
  // rule table — see command-rules.ts's module header) — unaffected by the
  // TOML migration.
  expect(wrapperPolicyDigest(WRAPPER_OPTION_POLICIES)).toEqual([
    ...EXPECTED_WRAPPER_POLICY_DIGEST,
  ]);
});

const PRIVILEGE_TOOL_CASES: readonly string[] = [
  'sudo apt',
  'doas apt',
  'pkexec apt',
  'runas apt',
  'please apt',
];

describe('guards-digest: every frozen privilege tool is effective', () => {
  for (const cmd of PRIVILEGE_TOOL_CASES) {
    test(`${cmd} is denied`, () => {
      expect(checkCommandBash(cmd)?.ruleId).toBe('sudo');
    });
  }
});

const KNOWN_WRAPPER_CASES: readonly string[] = [
  'rtk sudo apt',
  'proxy sudo apt',
  'command -- sudo apt',
  'exec -- sudo apt',
  'env -- sudo apt',
  'env -i sudo apt',
  'env -u FOO sudo apt',
  'env FOO=1 sudo apt',
  'nice -n 10 sudo apt',
  'time -p sudo apt',
  'builtin sudo apt',
];

describe('guards-digest: every wrapper policy is effective and unknown options fail closed', () => {
  for (const cmd of KNOWN_WRAPPER_CASES) {
    test(`${cmd} is structurally recognised`, () => {
      expect(checkCommandBash(cmd)?.ruleId).toBe('sudo');
    });
  }

  for (const wrapper of Object.keys(WRAPPER_OPTION_POLICIES)) {
    test(`${wrapper} unknown option fails closed`, () => {
      expect(checkCommandBash(`${wrapper} --unknown sudo apt`)?.ruleId).toBe('sudo');
    });
  }
});

// policy/command.toml `rules.command.bash` — regex-only rules. Privilege
// escalation is intentionally outside this table: it shares the structural
// tokenizer and wrapper consumer with Git, and is locked by behavioral
// mutations (above) rather than a table digest.
const EXPECTED_COMMAND_DIGEST: readonly string[] = [
  '0 dd-device-write \\bdd\\s+[^|;&\\n]*\\bof=\\/dev\\/ ',
  '1 mkfs \\bmkfs(\\.\\w+)?\\b ',
  '2 device-redirect-shell >\\s*\\/dev\\/(sda|sdb|disk|nvme|hd|md|loop)\\w* ',
  '3 device-redirect-tee \\btee\\s+(?:-a\\s+|--append\\s+)?\\/dev\\/(sda|sdb|disk|nvme|hd|md|loop)\\w* ',
  '4 chmod-root \\bchmod\\s+-R\\s+0?[0-7]{1,4}\\s+\\/(?:\\s|$) ',
  '5 chown-root \\bchown\\s+-R\\s+\\S+\\s+\\/(?:\\s|$) ',
  '6 curl-file-upload \\bcurl\\b[^|;&\\n]*?\\s(?:(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\\s+@\\S+|(?:-F|--form)\\s+\\S*=@|(?:-T|--upload-file)\\s+\\S+) ',
  '7 wget-post-file \\bwget\\b[^|;&\\n]*--post-(?:file|data)= ',
  '8 nc-file-redirect \\bn(?:c|cat)\\b[^|;&\\n]*<\\s*[^\\s<] ',
  '9 setuid \\bchmod\\s+(?:-\\S+\\s+)*(?:(?:[ugoa]*[+=-][rwxXst]*,)*[ugoa]*[+=][rwxXst]*s[rwxXst]*|0*[2-7][0-7]{3})\\b ',
  '10 etc-write-shell (?:>|>>)\\s*\\/etc\\/(sudoers|passwd|shadow|hosts|ssh\\/sshd_config)\\b ',
  '11 etc-write-tee \\btee\\s+(?:-a\\s+|--append\\s+)?\\/etc\\/(sudoers|passwd|shadow|hosts|ssh\\/sshd_config)\\b ',
  '12 kill-init \\bkill(?:all)?\\s+(?:-(?:9|KILL)\\s+)?(?:-?-?\\s*)?(?:1|init)\\b ',
  '13 fork-bomb :\\s*\\(\\s*\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\}\\s*;\\s*: ',
  '14 download-exec (?:curl|wget)\\b[^|;&\\n]*\\|\\s*(?:sh|bash|zsh|ksh|fish|sudo)\\b ',
  '15 eval-download \\beval\\s+["\']?(?:\\$\\(|`)\\s*(?:curl|wget)\\b ',
  '16 process-substitution-download \\b(?:bash|sh|zsh|ksh)\\s+<\\s*\\(\\s*(?:curl|wget)\\b ',
  '17 fd-exec-destructive \\bfd\\b[^|;&\\n]*\\s(?:-x|-X|--exec|--exec-batch)\\s+(?:rm|mv|chmod|chown|truncate|shred|git\\s+(?:rm|checkout|reset|clean|push)|sed\\s+-i)\\b ',
  '18 find-exec-destructive \\bfind\\b[^|;&\\n]*\\s(?:-delete\\b|(?:-exec|-execdir|-ok)\\s+(?:rm|mv|chmod|chown|truncate|shred|git\\s+(?:rm|checkout|reset|clean|push)|sed\\s+-i)\\b) ',
  '19 xargs-destructive \\b(?:xargs|parallel)\\b[^|;&\\n]*\\s(?:rm|mv|chmod|chown|truncate|shred|git\\s+(?:rm|checkout|reset|clean|push)|sed\\s+-i)\\b ',
  '20 rg-pre-exec \\brg\\b[^|;&\\n]*\\s--pre(?:=|\\s+)\\S+ ',
  '21 publish \\b(?:npm|pnpm|yarn)\\s+publish\\b|\\bcargo\\s+publish\\b|\\bgem\\s+push\\b|\\bpoetry\\s+publish\\b|\\btwine\\s+upload\\b|\\bdocker\\s+push\\b|\\b(?:gh|glab)\\s+release\\s+create\\b ',
  '22 forge-api-write \\b(?:gh|glab)\\s+api\\b[^|;&\\n]*\\s(?:-X|--method)(?:\\s+|=)(?:POST|PUT|PATCH|DELETE)\\b|\\b(?:gh|glab)\\s+api\\b[^|;&\\n]*\\s(?:-f|-F|--field|--raw-field|--input)\\b ',
  '23 base64-decode-exec \\b(?:base64\\s+(?:-d|--decode|-D)\\b|xxd\\s+-r\\b|openssl\\s+enc\\s+-d\\b)[^|;&\\n]*\\|\\s*(?:sh|bash|zsh|python3?|node|perl)\\b ',
  '24 direnv-trust \\bdirenv\\s+(?:allow|permit|grant)\\b ',
  '25 persistence-scheduler \\bcrontab\\s+(?:-u\\s+\\S+\\s+)*(?:-\\s|-$|-\\S*[er]\\S*(?:\\s|$)|[^-\\s]\\S*(?:\\s|$))|\\blaunchctl\\s+(?:load|bootstrap|enable|submit)\\b|\\bsystemctl\\s+(?:(?:--user\\s+)?enable|--user\\s+start)\\b|(?:^|[|;&]\\s*)at\\s+(?:-f\\s+\\S+\\s+|-\\S+\\s+)*(?:now|noon|midnight|teatime|\\+|\\d) ',
  '26 terraform-mutating \\b(?:terraform|tofu)\\s+(?:apply|destroy|import|state\\s+(?:rm|mv|push))\\b ',
  '27 kubectl-mutating \\bkubectl\\b[^|;&\\n]*\\s(?:apply|create|delete|drain|cordon|taint|replace|patch|scale|rollout\\s+(?:restart|undo))\\b ',
  '28 helm-mutating \\bhelm\\s+(?:install|upgrade|uninstall|delete|rollback)\\b ',
  '29 docker-destructive \\bdocker\\s+(?:system\\s+prune|volume\\s+(?:rm|prune)|compose\\s+down\\b[^|;&\\n]*\\s(?:-v|--volumes)\\b) ',
  '30 sql-destructive-inline (?:\\b(?:psql|mysql)\\b[^|;&\\n]*\\s(?:-c|-e)\\s+["\'][^"\']*\\b(?:DROP|TRUNCATE|DELETE\\s+FROM|ALTER)\\b|\\bsqlite3\\b[^|;&\\n]*\\s+["\'][^"\']*\\b(?:DROP|TRUNCATE|DELETE\\s+FROM|ALTER)\\b) ',
];

// policy/secret.toml `rules.secret.bash`. Seven entries, each with its own
// id. The git-config pair remains split: `bash-git-leak-credential` (index
// 2: credential/signingkey, unconditional) and `bash-git-leak-remote-url`
// (index 3: remote.*.url, read-excepted, marked `special`) cannot disable
// each other. `keychain-dump` and `credential-printer` each own their
// independent override target, so a consumer can relax a printer without
// weakening the macOS keychain boundary.
const EXPECTED_SECRET_DIGEST: readonly string[] = [
  '0 sops-decrypt \\bsops(?:\\s+[^;&|\\n]*)?\\s(?:-d|--decrypt|decrypt|exec-env|exec-file|edit)(?:\\s|$)|(?:^|[;&|(]\\s*)(?:(?:[A-Za-z_][A-Za-z0-9_]*=\\S*|rtk|command|exec|env|nice|time|builtin|proxy)\\s+)*sops\\s+[^\\s;&|\\-][^\\s;&|]*\\s*(?:$|[;&|)]) ',
  '1 age-decrypt \\b(?:age|rage)(?:\\s+[^;&|\\n]*)?\\s(?:-d|--decrypt)(?:\\s|$) ',
  '2 bash-git-leak-credential \\bgit\\s+config\\b[^\\n]*\\b(credential|user\\.signingkey)\\b ',
  '3 bash-git-leak-remote-url \\bgit\\s+config\\b[^\\n]*\\bremote\\.[^\\s]+\\.url\\b ',
  '4 bash-url-creds \\b(?:https?|git|ssh|ftp):\\/\\/[^\\s/@:]+:[^\\s/@]+@ ',
  '5 keychain-dump \\bsecurity\\s+(?:find-(?:generic|internet)-password|export|dump-keychain)\\b ',
  '6 credential-printer \\bgh\\s+auth\\s+token\\b|\\bglab\\s+auth\\s+status\\b[^|;&\\n]*\\s--show-token\\b|\\bop\\s+read\\b|\\bop\\s+item\\s+get\\b[^|;&\\n]*\\s(?:--reveal|--fields)\\b|\\bgcloud\\s+auth\\s+print-(?:access|identity)-token\\b|\\baws\\s+sts\\s+(?:get-session-token|assume-role)\\b|\\bvault\\s+(?:read|kv\\s+get)\\b|\\bdoppler\\s+secrets\\s+download\\b ',
];

// policy/write-secret.toml `rules.write_secret` — an identity control: 8
// entries, none of which this port touches (no signature added, removed,
// or widened).
const EXPECTED_WRITE_SECRET_DIGEST: readonly string[] = [
  '0 private-key -----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY----- ',
  '1 aws-access-key-id \\bAKIA[0-9A-Z]{16}\\b ',
  '2 github-pat \\bghp_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{22,}\\b ',
  '3 github-token \\bgh[ousr]_[A-Za-z0-9]{36}\\b ',
  '4 slack-token \\bxox[baprs]-[A-Za-z0-9-]{10,}\\b ',
  '5 google-api-key \\bAIza[0-9A-Za-z_-]{35}\\b ',
  '6 stripe-secret-key \\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\\b ',
  '7 jwt \\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b ',
];

// policy/prompt.toml `rules.prompt` — the other identity control. The
// base64-blob signature (formerly a module constant BASE64_BLOB, evaluated
// in scanPrompt's body OUTSIDE PROMPT_RULES) is now a plain 7th table row —
// as policy data there was no structural reason left to keep it apart, and
// folding it in means this digest no longer needs a special "append the
// out-of-table entry" step.
const EXPECTED_PROMPT_DIGEST: readonly string[] = [
  '0 ignore-previous \\bignore\\s+(?:all\\s+|the\\s+|any\\s+)?(?:previous|prior|above|earlier|preceding)\\s+(?:instructions?|prompts?|messages?|context|rules?)\\b i',
  '1 disregard \\bdisregard\\s+(?:all\\s+|the\\s+|any\\s+)?(?:previous|prior|above|earlier|system)\\b i',
  '2 role-override \\b(?:you\\s+are\\s+now|from\\s+now\\s+on|act\\s+as|pretend\\s+to\\s+be)\\b[^.\\n]{0,60}\\b(?:dan|jailbreak|unrestricted|no\\s+(?:restrictions?|rules?|limits?)|developer\\s+mode|do\\s+anything)\\b i',
  '3 injected-role-tag <\\/?\\s*(?:system|instructions?|assistant|developer|tool_call|function_call)\\s*> i',
  '4 new-instructions \\b(?:new|updated|real|actual|important)\\s+(?:system\\s+)?(?:instructions?|prompt|directives?)\\s*: i',
  '5 prompt-exfil \\b(?:reveal|print|show|repeat|output|leak)\\s+(?:me\\s+)?(?:your\\s+|the\\s+)?(?:system\\s+prompt|initial\\s+instructions|hidden\\s+(?:prompt|instructions)|developer\\s+(?:prompt|message))\\b i',
  '6 base64-blob [A-Za-z0-9+/]{200,}={0,2} ',
];

describe('guards-digest: tamper lock — the four tabular guards', () => {
  test('command.bash matches the frozen ordered digest (31 regex entries)', () => {
    expect(ruleDigest(BASELINE.rules.command.bash)).toEqual([...EXPECTED_COMMAND_DIGEST]);
  });

  test('secret.bash matches the frozen ordered digest (7 entries, distinct ids)', () => {
    expect(ruleDigest(BASELINE.rules.secret.bash)).toEqual([...EXPECTED_SECRET_DIGEST]);
  });

  test('write_secret matches the frozen ordered digest (8 entries, identity control)', () => {
    expect(ruleDigest(BASELINE.rules.write_secret)).toEqual([...EXPECTED_WRITE_SECRET_DIGEST]);
  });

  test('prompt matches the frozen ordered digest (7 entries incl. base64-blob, identity control)', () => {
    expect(ruleDigest(BASELINE.rules.prompt)).toEqual([...EXPECTED_PROMPT_DIGEST]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// secret.path. Each row is `{id, regex, reason, except?, verdict?}` — a
// plain data row, so it digests exactly like the four regex tables above
// instead of needing a source-text scrape.
//
// Two mutations were measured to escape the ENTIRE suite before this lock
// existed (on the pre-TOML source) — the suite stayed green end to end
// after each: removing one extension from crypto-key's list of fifteen,
// and removing the END ANCHOR from hook-log's pattern (without `$`, the
// rule would block reading the hooks' SOURCES, not only their logs — a
// silent widening that no assertion contradicted). Both mutations still
// redden THIS digest today, on the TOML-sourced data. `verdict` is in the
// projection too, so a row silently losing its non-default verdict (or
// gaining a stray one) reddens here as well.
// ─────────────────────────────────────────────────────────────────────────

function pathRuleDigest(
  rules: readonly {
    readonly id: string;
    readonly regex: string;
    readonly flags?: string;
    readonly except?: string;
    readonly verdict?: string;
  }[],
): string[] {
  return rules.map((r, i) => `${i} ${r.id} ${r.regex} flags=${r.flags ?? ''} except=${r.except ?? ''} verdict=${r.verdict ?? ''}`);
}

// DERIVED by running the projection above against policy/secret.toml and
// printing the output — never hand-transcribed. `except` carries the
// ENV_WHITELIST (dotenv) and node_modules (npmrc) exceptions that used to
// be separate module-level regexes; they are policy data now too, one
// field on the row they qualify, which is what let this lock stop needing
// a second "declared outside the block" append step. `transcript-backup`,
// `bouncer-audit-log`, `bouncer-policy`, `shell-history`, and
// `session-transcripts` are the five rows with a non-default `verdict`
// ("confirm"; see policy/secret.toml for their distinct rationale).
const EXPECTED_PATH_DIGEST: readonly string[] = [
  '0 dotenv (^|/)\\.env[^/]*$ flags= except=(^|/)\\.env\\.(example|test)$ verdict=',
  '1 crypto-key (^|/)[^/.][^/]*\\.(pem|key|pkey|crt|cert|pfx|p12|jks|keystore|gpg|asc|kdbx|kbx|agekey|ovpn)$ flags=i except= verdict=',
  '2 age-identity (^|/)sops/age/[^/]+$|(^|/)age/keys\\.txt$ flags= except= verdict=',
  '3 ssh-key (^|/)id_(rsa|dsa|ecdsa|ed25519)(\\.pub)?$ flags= except= verdict=',
  '4 aws-creds (^|/)\\.aws(/|$) flags= except= verdict=',
  '5 netrc-pgpass (^|/)\\.(netrc|pgpass)$ flags= except= verdict=',
  '6 cloud-sa (service-account|firebase-adminsdk|gcp-key)[^/]*\\.json$ flags=i except= verdict=',
  '7 tfstate \\.tfstate(\\.backup)?$|\\.terraform\\.tfstate\\.lock\\.info$ flags= except= verdict=',
  '8 npmrc (^|/)\\.npmrc$ flags= except=/node_modules/ verdict=',
  '9 gitconfig (^|/)\\.gitconfig$ flags= except= verdict=',
  '10 transcript-backup (^|/)\\.claude/transcripts(/|$) flags= except= verdict=confirm',
  '11 bouncer-audit-log (^|/)logs/hooks/bouncer\\.log(\\.1)?$ flags= except= verdict=confirm',
  '12 bouncer-policy (^|/)bouncer/(policy\\.toml|policy\\.d)(/|$) flags= except= verdict=confirm',
  '13 secret-dir (^|/)(\\.?secrets|credentials)(/|$) flags= except= verdict=',
  '14 ssh-dir (^|/)\\.ssh(/|$) flags= except= verdict=',
  '15 gnupg-dir (^|/)\\.gnupg(/|$) flags= except= verdict=',
  '16 shell-history (^|/)\\.(?:zsh_history|bash_history|zhistory|python_history|node_repl_history|psql_history|mysql_history|lesshst)$ flags= except= verdict=confirm',
  '17 session-transcripts (^|/)\\.claude(?:-[A-Za-z0-9_-]+)?/projects/[^/]+/[^/]+\\.jsonl$ flags= except= verdict=confirm',
];

describe('guards-digest: tamper lock — secret.path, the eighteen-entry path guard', () => {
  test('secret.path matches the frozen ordered digest (18 entries + except/verdict fields)', () => {
    expect(pathRuleDigest(BASELINE.rules.secret.path)).toEqual([...EXPECTED_PATH_DIGEST]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The git guard's membership sets and declarative conditional tables.
//
// Two holes were measured on the suite as it stood before this lock
// existed, and they are the reason it exists:
//
//   1. The only test that iterates safe_subcommands (command-rules.test.ts,
//      "benign: every SAFE_GIT_SUBCOMMANDS entry passes") LOOPS OVER THE SET
//      ITSELF. Delete an entry and it leaves the loop with it: the assertion
//      still passes, on a smaller allowlist. A lock that re-derives its
//      expectation from the structure it is checking proves nothing. The
//      frozen arrays below are therefore an INDEPENDENT second copy — the
//      one place in this file where duplicating the source is the point,
//      not the defect.
//   2. `nice` is a member of GIT_BENIGN_PREFIXES that no test exercised
//      (measured: the only `nice` in command-rules.test.ts drives the `sudo`
//      regex, an unrelated pattern that carries its own copy of the word).
//      Likewise the `config` read alternation had a vector for `--get` and
//      for none of its seven other branches.
// ─────────────────────────────────────────────────────────────────────────

const EXPECTED_SAFE_GIT_SUBCOMMANDS: readonly string[] = [
  'status',
  'diff',
  'log',
  'show',
  'blame',
  'shortlog',
  'describe',
  'rev-parse',
  'ls-files',
  'cat-file',
  'grep',
  'add',
  'commit',
  'fetch',
  'ls-remote',
  'for-each-ref',
  'ls-tree',
  'check-ignore',
  'rev-list',
  'merge-base',
  'show-ref',
  'show-branch',
  'name-rev',
  'count-objects',
  'var',
  'range-diff',
  'cherry',
  'whatchanged',
  'diff-tree',
  'diff-index',
  'fsck',
];

const EXPECTED_GIT_BENIGN_PREFIXES: readonly string[] = [
  'rtk',
  'command',
  'exec',
  'env',
  'nice',
  'time',
  'builtin',
];

describe('guards-digest: tamper lock — the git guard\'s two membership sets', () => {
  test('command.git.safe_subcommands matches the frozen list, in order (31 entries)', () => {
    expect(BASELINE.rules.command.git.safe_subcommands).toEqual([...EXPECTED_SAFE_GIT_SUBCOMMANDS]);
  });

  test('GIT_BENIGN_PREFIXES matches the frozen list, in declaration order (7 entries)', () => {
    // Stays TS (tokenizer grammar — which wrappers may precede `git` at
    // command position — not a security verdict table).
    expect([...GIT_BENIGN_PREFIXES]).toEqual([...EXPECTED_GIT_BENIGN_PREFIXES]);
  });

  test('GIT_BENIGN_PREFIXES still holds exactly 7 entries', () => {
    expect(GIT_BENIGN_PREFIXES.size).toBe(7);
  });

  // Membership alone is not behaviour: an entry can sit in the set while the
  // parser stops consulting it. This vector goes through checkGit, so it
  // reddens both when `nice` leaves the set AND when extractGitSubcommand
  // stops honouring the set at all.
  test('a benign prefix is honoured end to end: nice git push still asks', () => {
    expect(checkGit('nice git push')?.ruleId).toBe('git-protected');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The 14-subcommand conditional matrix — UNCHANGED from before ticket 06,
// other than ticket 13 removing `pull`/`merge` (16 → 14): both moved out
// of the baseline entirely (their `--ff-only` safe form was a personal git
// habit, not a hazard) and now ask UNCONDITIONALLY, with no reading-safe
// form left to pair into this matrix's {reading, mutating} shape — see
// tests/command-rules.test.ts's dedicated "always ask in the trunk
// baseline" block instead. It is a pure BEHAVIOURAL lock (calls checkGit
// with real commands), so it does not care whether the decision underneath
// comes from a TS if-chain or from TOML data — it keeps testing the
// OBSERVABLE property regardless of mechanism, which is exactly why it
// survives the repointing untouched.
// ─────────────────────────────────────────────────────────────────────────

interface GitConditionalCase {
  readonly sub: string;
  readonly reading: string;
  readonly mutating: string;
}

const GIT_CONDITIONAL_MATRIX: readonly GitConditionalCase[] = [
  { sub: 'branch', reading: 'git branch --list', mutating: 'git branch -D old-branch' },
  { sub: 'tag', reading: 'git tag v1.0', mutating: 'git tag -d v1.0' },
  { sub: 'stash', reading: 'git stash list', mutating: 'git stash drop' },
  { sub: 'reflog', reading: 'git reflog show', mutating: 'git reflog expire --all' },
  { sub: 'submodule', reading: 'git submodule status', mutating: 'git submodule update --init' },
  {
    sub: 'remote',
    reading: 'git remote -v',
    mutating: 'git remote add origin https://example.test/x.git',
  },
  { sub: 'config', reading: 'git config --get user.name', mutating: 'git config user.name x' },
  { sub: 'bundle', reading: 'git bundle verify b.pack', mutating: 'git bundle create b.pack HEAD' },
  { sub: 'symbolic-ref', reading: 'git symbolic-ref HEAD', mutating: 'git symbolic-ref -d HEAD' },
  { sub: 'checkout', reading: 'git checkout main', mutating: 'git checkout -f' },
  { sub: 'switch', reading: 'git switch feat', mutating: 'git switch --discard-changes' },
  { sub: 'worktree', reading: 'git worktree list', mutating: 'git worktree remove w' },
  { sub: 'apply', reading: 'git apply --check p.diff', mutating: 'git apply p.diff' },
  { sub: 'restore', reading: 'git restore --staged f.ts', mutating: 'git restore f.ts' },
];

describe('guards-digest: tamper lock — the 14 conditional git subcommands', () => {
  for (const { sub, reading, mutating } of GIT_CONDITIONAL_MATRIX) {
    test(`git ${sub}: the reading form stays silent (${reading})`, () => {
      expect(checkGit(reading)).toBeNull();
    });

    test(`git ${sub}: the mutating form asks (${mutating})`, () => {
      expect(checkGit(mutating)?.ruleId).toBe('git-protected');
    });
  }
});

describe('guards-digest: tamper lock — every branch of the config read alternation', () => {
  const GIT_CONFIG_READ_BRANCHES: readonly { readonly branch: string; readonly cmd: string; }[] = [
    { branch: '--get', cmd: 'git config --get user.name' },
    { branch: '--get-all', cmd: 'git config --get-all user.name' },
    { branch: '--get-regexp', cmd: 'git config --get-regexp ^user\\.' },
    { branch: '--get-urlmatch', cmd: 'git config --get-urlmatch http https://example.test' },
    { branch: '--list', cmd: 'git config --list' },
    { branch: '-l', cmd: 'git config -l' },
    { branch: 'get', cmd: 'git config get user.name' },
    { branch: 'list', cmd: 'git config list' },
  ];

  for (const { branch, cmd } of GIT_CONFIG_READ_BRANCHES) {
    test(`git config ${branch} is a read and stays silent`, () => {
      expect(checkGit(cmd)).toBeNull();
    });
  }

  test('git config user.name x is a write and still asks', () => {
    expect(checkGit('git config user.name x')?.ruleId).toBe('git-protected');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// REPLACES the old "conditional chain, scraped from its source" lock: there
// is no more TS if-chain to scrape for 12 of the 14 subcommands — they are
// policy/command.toml data (ask_flags / safe_first_arg / safe_grammar),
// digested directly, the same discipline as every other table in this file.
// `checkout` and `restore` are the two that stay engine code (pathspec
// detection, index-only form — beyond what any of the three declarative
// forms can express as data); their behaviour is already covered by the
// matrix above, so this section's own job is narrower: prove the
// declarative tables plus those two names together account for EXACTLY
// the 14 subcommands, with no gap and no double-coverage. (16 → 14,
// ticket 13: `pull`/`merge` moved out of safe_grammar entirely, see that
// section's own note.)
// ─────────────────────────────────────────────────────────────────────────

function askFlagsDigest(rules: readonly AskFlagsRule[]): string[] {
  return rules.map((r, i) => `${i} ${r.sub} flags=[${r.flags.join(',')}] max_positionals=${r.max_positionals ?? 'none'}`);
}

function safeFirstArgDigest(rules: readonly SafeFirstArgRule[]): string[] {
  return rules.map((r, i) =>
    `${i} ${r.sub} values=[${r.values.join(',')}] invert=${r.invert ?? false} safe_when_absent=${r.safe_when_absent}`
  );
}

function safeGrammarDigest(rules: readonly SafeGrammarRule[]): string[] {
  return rules.map((r, i) => `${i} ${r.sub} sequences=${JSON.stringify(r.sequences)}`);
}

// DERIVED by running the three projections above against
// policy/command.toml and printing the output.
const EXPECTED_ASK_FLAGS_DIGEST: readonly string[] = [
  '0 branch flags=[-d,-D,--delete,-m,-M,--move,-f,--force] max_positionals=none',
  '1 tag flags=[-d,--delete] max_positionals=none',
  '2 switch flags=[-C,--force-create,-f,--force,--discard-changes] max_positionals=none',
  '3 symbolic-ref flags=[-d,--delete] max_positionals=1',
];

const EXPECTED_SAFE_FIRST_ARG_DIGEST: readonly string[] = [
  '0 stash values=[drop,clear] invert=true safe_when_absent=true',
  '1 reflog values=[show,list,exists] invert=false safe_when_absent=true',
  '2 submodule values=[status,summary] invert=false safe_when_absent=true',
  '3 remote values=[-v,--verbose,show,get-url] invert=false safe_when_absent=true',
  '4 config values=[--get,--get-all,--get-regexp,--get-urlmatch,--list,-l,get,list] invert=false safe_when_absent=false',
  '5 bundle values=[verify,list-heads] invert=false safe_when_absent=false',
  '6 worktree values=[list] invert=false safe_when_absent=false',
];

// Ticket 13: `pull`/`merge` removed (fast-forward-only was a personal git
// habit, not a hazard — see policy/command.toml's own comment at the old
// location; the personal overlay restores both, see
// tests/personal-policy.test.ts). `apply` is now the sole entry.
const EXPECTED_SAFE_GRAMMAR_DIGEST: readonly string[] = [
  '0 apply sequences=[["--check"],["--check","*"]]',
];

describe('guards-digest: tamper lock — the three declarative git-conditional forms', () => {
  const git = BASELINE.rules.command.git;

  test('ask_flags matches the frozen ordered digest (4 entries)', () => {
    expect(askFlagsDigest(git.ask_flags)).toEqual([...EXPECTED_ASK_FLAGS_DIGEST]);
  });

  test('safe_first_arg matches the frozen ordered digest (7 entries)', () => {
    expect(safeFirstArgDigest(git.safe_first_arg)).toEqual([...EXPECTED_SAFE_FIRST_ARG_DIGEST]);
  });

  test('safe_grammar matches the frozen ordered digest (1 entry)', () => {
    expect(safeGrammarDigest(git.safe_grammar)).toEqual([...EXPECTED_SAFE_GRAMMAR_DIGEST]);
  });

  // The equation that makes the split non-circular: taking the expected
  // coverage from the matrix itself would let a subcommand silently fall
  // out of BOTH the declarative tables and the engine escapes without
  // reddening anything. Comparing SETS (not counts) names which subcommand
  // moved, not just that the total changed.
  test('the declarative tables plus checkout/restore cover exactly the 14-subcommand matrix', () => {
    const declared = [
      ...git.ask_flags.map((r) => r.sub),
      ...git.safe_first_arg.map((r) => r.sub),
      ...git.safe_grammar.map((r) => r.sub),
      'checkout',
      'restore',
    ];
    expect(new Set(declared)).toEqual(new Set(GIT_CONDITIONAL_MATRIX.map((c) => c.sub)));
    // No duplicates across the three tables + the two engine names: a
    // subcommand claimed twice would pass the Set comparison above while
    // still being a real drift (two competing definitions of its ask
    // behaviour), so length is checked apart from set equality.
    expect(declared).toHaveLength(GIT_CONDITIONAL_MATRIX.length);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// mcp_write.read_prefixes — the last of this file's locks. It is an
// allowlist rather than a rule table, so the named projection is
// `${index} ${prefix}`: an edit, addition, removal or reorder appears at
// its own index instead of collapsing to a count-only assertion.
// ─────────────────────────────────────────────────────────────────────────

const EXPECTED_MCP_READ_PREFIX_DIGEST: readonly string[] = [
  '0 get',
  '1 list',
  '2 search',
  '3 fetch',
  '4 read',
  '5 query',
  '6 lookup',
  '7 describe',
  '8 view',
];

describe('guards-digest: tamper lock — the MCP read allowlist', () => {
  test('mcp_write.read_prefixes matches the frozen ordered digest (9 entries)', () => {
    expect(orderedValueDigest(BASELINE.rules.mcp_write.read_prefixes)).toEqual([
      ...EXPECTED_MCP_READ_PREFIX_DIGEST,
    ]);
  });
});
