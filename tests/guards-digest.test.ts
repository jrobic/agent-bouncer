import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  BASH_RULES as COMMAND_RULES,
  checkBash as checkCommandBash,
  checkGit,
  GIT_BENIGN_PREFIXES,
  PRIVILEGE_ESCALATION_COMMANDS,
  SAFE_GIT_SUBCOMMANDS,
  WRAPPER_OPTION_POLICIES,
} from "../src/command-rules.ts";
import { BASE64_BLOB, PROMPT_RULES } from "../src/prompt-rules.ts";
import {
  SECRET_BASH_RULES,
  PATH_RULES,
} from "../src/secret-rules.ts";
import { MCP_READ_PREFIXES } from "../src/mcp-write-rules.ts";
import { SECRET_RULES as WRITE_SECRET_RULES } from "../src/write-secret-rules.ts";

// ─────────────────────────────────────────────────────────────────────────
// The first of this file's several tamper locks: an ordered digest of the
// four `{ruleId, regex}` tables (command, secret, write-secret, prompt) plus
// the base64 constant that `scanPrompt` evaluates OUT OF the prompt table.
// This is the only describe block that sees all five guards together — the
// other non-tabular structures (path rules; the git block's two sets plus
// conditional chain; the mcp-write allowlist) get their own locks further
// down this file.
//
// This is a TRIPWIRE, not a semantic assertion: it says a pattern changed,
// never what the change means, and it is read in the diff. It is
// deliberately NOT a hash — a single digest per table would redden without
// saying which line moved, and naming the mutated entry (not just detecting
// that something moved) is the whole point of this lock. The projection is
// `${index} ${ruleId} ${regex.source} ${regex.flags}`, one string per rule,
// compared with `toEqual` against a frozen array: a removed, added,
// reordered, or edited entry shows up as a diff AT ITS OWN INDEX, naming
// both the position and the entry.
//
// Position is part of identity: two entries of secret-rules' BASH_RULES
// share the ruleId `bash-git-leak`. An unordered digest (e.g. sorted by
// ruleId, or a Set of ruleIds) could not tell them apart, and could not
// detect either one disappearing — the surviving ruleId would paper over
// the loss, so removing one entry must still redden this lock even though
// its ruleId survives via the other.
//
// The four frozen arrays below were DERIVED by running this exact
// projection against the real modules and printing the output — never
// hand-transcribed from the regex literals. Hand-copying `.source`/`.flags`
// would be a second source of truth for the same bytes.
// `.source`/`.flags` were chosen over `Function.prototype.toString()`
// specifically because the latter is bun-runtime-coupled (measured: `return
// false` becomes `return !1;` post-transpile) and would redden at the next
// bun upgrade for zero behaviour change.
// ─────────────────────────────────────────────────────────────────────────

function ruleDigest(
  rules: readonly { readonly ruleId: string; readonly regex: RegExp }[],
): string[] {
  return rules.map((r, i) => `${i} ${r.ruleId} ${r.regex.source} ${r.regex.flags}`);
}

function orderedValueDigest(values: Iterable<string>): string[] {
  return [...values].map((value, index) => `${index} ${value}`);
}

const EXPECTED_PRIVILEGE_TOOL_DIGEST: readonly string[] = [
  "0 sudo",
  "1 doas",
  "2 pkexec",
  "3 runas",
  "4 please",
];

test("guards-digest: privilege tools are frozen exhaustively and in order", () => {
  expect(orderedValueDigest(PRIVILEGE_ESCALATION_COMMANDS)).toEqual([
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
    `${index} ${name} flags=[${[...policy.flags].join(",")}] `
    + `args=[${[...policy.optionsWithArg].join(",")}] `
    + `assignments=${policy.acceptsAssignments === true}`
  );
}

const EXPECTED_WRAPPER_POLICY_DIGEST: readonly string[] = [
  "0 rtk flags=[] args=[] assignments=false",
  "1 proxy flags=[] args=[] assignments=false",
  "2 command flags=[--] args=[] assignments=false",
  "3 exec flags=[--] args=[] assignments=false",
  "4 env flags=[--,-i] args=[-u] assignments=true",
  "5 nice flags=[] args=[-n] assignments=false",
  "6 time flags=[-p] args=[] assignments=false",
  "7 builtin flags=[] args=[] assignments=false",
];

test("guards-digest: wrapper option policies freeze names, flags, arities, and order", () => {
  expect(wrapperPolicyDigest(WRAPPER_OPTION_POLICIES)).toEqual([
    ...EXPECTED_WRAPPER_POLICY_DIGEST,
  ]);
});

const PRIVILEGE_TOOL_CASES: readonly string[] = [
  "sudo apt",
  "doas apt",
  "pkexec apt",
  "runas apt",
  "please apt",
];

describe("guards-digest: every frozen privilege tool is effective", () => {
  for (const cmd of PRIVILEGE_TOOL_CASES) {
    test(`${cmd} is denied`, () => {
      expect(checkCommandBash(cmd)?.ruleId).toBe("sudo");
    });
  }
});

const KNOWN_WRAPPER_CASES: readonly string[] = [
  "rtk sudo apt",
  "proxy sudo apt",
  "command -- sudo apt",
  "exec -- sudo apt",
  "env -- sudo apt",
  "env -i sudo apt",
  "env -u FOO sudo apt",
  "env FOO=1 sudo apt",
  "nice -n 10 sudo apt",
  "time -p sudo apt",
  "builtin sudo apt",
];

describe("guards-digest: every wrapper policy is effective and unknown options fail closed", () => {
  for (const cmd of KNOWN_WRAPPER_CASES) {
    test(`${cmd} is structurally recognised`, () => {
      expect(checkCommandBash(cmd)?.ruleId).toBe("sudo");
    });
  }

  for (const wrapper of Object.keys(WRAPPER_OPTION_POLICIES)) {
    test(`${wrapper} unknown option fails closed`, () => {
      expect(checkCommandBash(`${wrapper} --unknown sudo apt`)?.ruleId).toBe("sudo");
    });
  }
});

// command-rules.ts BASH_RULES — regex-only rules. Privilege escalation is
// intentionally outside this table now: it shares the structural tokenizer
// and wrapper consumer with Git, and is locked by behavioral mutations.
const EXPECTED_COMMAND_DIGEST: readonly string[] = [
  "0 dd-device-write \\bdd\\s+[^|;&\\n]*\\bof=\\/dev\\/ ",
  "1 mkfs \\bmkfs(\\.\\w+)?\\b ",
  "2 device-redirect >\\s*\\/dev\\/(sda|sdb|disk|nvme|hd|md|loop)\\w* ",
  "3 device-redirect \\btee\\s+(?:-a\\s+|--append\\s+)?\\/dev\\/(sda|sdb|disk|nvme|hd|md|loop)\\w* ",
  "4 chmod-root \\bchmod\\s+-R\\s+0?[0-7]{1,4}\\s+\\/(?:\\s|$) ",
  "5 chown-root \\bchown\\s+-R\\s+\\S+\\s+\\/(?:\\s|$) ",
  "6 curl-file-upload \\bcurl\\b[^|;&\\n]*?\\s(?:(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\\s+@\\S+|(?:-F|--form)\\s+\\S*=@|(?:-T|--upload-file)\\s+\\S+) ",
  "7 wget-post-file \\bwget\\b[^|;&\\n]*--post-(?:file|data)= ",
  "8 nc-file-redirect \\bn(?:c|cat)\\b[^|;&\\n]*<\\s*[^\\s<] ",
  "9 setuid \\bchmod\\s+(?:[ugoa]*\\+s|[0-7]?[2-7][0-7]{2,3})\\b ",
  "10 etc-write (?:>|>>)\\s*\\/etc\\/(sudoers|passwd|shadow|hosts|ssh\\/sshd_config)\\b ",
  "11 etc-write \\btee\\s+(?:-a\\s+|--append\\s+)?\\/etc\\/(sudoers|passwd|shadow|hosts|ssh\\/sshd_config)\\b ",
  "12 kill-init \\bkill(?:all)?\\s+(?:-(?:9|KILL)\\s+)?(?:-?-?\\s*)?(?:1|init)\\b ",
  "13 fork-bomb :\\s*\\(\\s*\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\}\\s*;\\s*: ",
  "14 download-exec (?:curl|wget)\\b[^|;&\\n]*\\|\\s*(?:sh|bash|zsh|ksh|fish|sudo)\\b ",
  "15 eval-download \\beval\\s+[\"']?(?:\\$\\(|`)\\s*(?:curl|wget)\\b ",
  "16 process-substitution-download \\b(?:bash|sh|zsh|ksh)\\s+<\\s*\\(\\s*(?:curl|wget)\\b ",
];

// secret-rules.ts BASH_RULES. 3 entries: two share the ruleId
// `bash-git-leak` (index 0: credential/signingkey, unconditional; index 1:
// remote.*.url, read-excepted) — the exact pair the "position is part of
// identity" note above is about.
const EXPECTED_SECRET_DIGEST: readonly string[] = [
  "0 bash-git-leak \\bgit\\s+config\\b[^\\n]*\\b(credential|user\\.signingkey)\\b ",
  "1 bash-git-leak \\bgit\\s+config\\b[^\\n]*\\bremote\\.[^\\s]+\\.url\\b ",
  "2 bash-url-creds \\b(?:https?|git|ssh|ftp):\\/\\/[^\\s/@:]+:[^\\s/@]+@ ",
];

// write-secret-rules.ts SECRET_RULES — an identity control: 8 entries,
// none of which this port touches (no signature added, removed, or
// widened). Nothing compared this table to a reference state before this
// lock existed, so a silent narrowing or widening of a secret signature
// would previously have gone undetected.
const EXPECTED_WRITE_SECRET_DIGEST: readonly string[] = [
  "0 private-key -----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY----- ",
  "1 aws-access-key-id \\bAKIA[0-9A-Z]{16}\\b ",
  "2 github-pat \\bghp_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{22,}\\b ",
  "3 github-token \\bgh[ousr]_[A-Za-z0-9]{36}\\b ",
  "4 slack-token \\bxox[baprs]-[A-Za-z0-9-]{10,}\\b ",
  "5 google-api-key \\bAIza[0-9A-Za-z_-]{35}\\b ",
  "6 stripe-secret-key \\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\\b ",
  "7 jwt \\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b ",
];

// prompt-rules.ts PROMPT_RULES (6 table entries) + BASE64_BLOB, the seventh
// signature — the other identity control alongside write-secret-rules'
// above. BASE64_BLOB is evaluated in scanPrompt's body, OUTSIDE
// PROMPT_RULES: a prompt-injection signature must stay caught even though
// this one constant is not a table row, so it is appended here as index 6
// rather than digested apart — a constant hidden outside every table is
// exactly the entry a table-shaped lock would otherwise miss.
const EXPECTED_PROMPT_DIGEST: readonly string[] = [
  "0 ignore-previous \\bignore\\s+(?:all\\s+|the\\s+|any\\s+)?(?:previous|prior|above|earlier|preceding)\\s+(?:instructions?|prompts?|messages?|context|rules?)\\b i",
  "1 disregard \\bdisregard\\s+(?:all\\s+|the\\s+|any\\s+)?(?:previous|prior|above|earlier|system)\\b i",
  "2 role-override \\b(?:you\\s+are\\s+now|from\\s+now\\s+on|act\\s+as|pretend\\s+to\\s+be)\\b[^.\\n]{0,60}\\b(?:dan|jailbreak|unrestricted|no\\s+(?:restrictions?|rules?|limits?)|developer\\s+mode|do\\s+anything)\\b i",
  "3 injected-role-tag <\\/?\\s*(?:system|instructions?|assistant|developer|tool_call|function_call)\\s*> i",
  "4 new-instructions \\b(?:new|updated|real|actual|important)\\s+(?:system\\s+)?(?:instructions?|prompt|directives?)\\s*: i",
  "5 prompt-exfil \\b(?:reveal|print|show|repeat|output|leak)\\s+(?:me\\s+)?(?:your\\s+|the\\s+)?(?:system\\s+prompt|initial\\s+instructions|hidden\\s+(?:prompt|instructions)|developer\\s+(?:prompt|message))\\b i",
  "6 base64-blob [A-Za-z0-9+/]{200,}={0,2} ",
];

describe("guards-digest: tamper lock — the four tabular guards + the out-of-table prompt constant", () => {
  test("command-rules.BASH_RULES matches the frozen ordered digest (17 regex entries)", () => {
    expect(ruleDigest(COMMAND_RULES)).toEqual([...EXPECTED_COMMAND_DIGEST]);
  });

  test("secret-rules.BASH_RULES matches the frozen ordered digest (3 entries, two sharing bash-git-leak)", () => {
    expect(ruleDigest(SECRET_BASH_RULES)).toEqual([...EXPECTED_SECRET_DIGEST]);
  });

  test("write-secret-rules.SECRET_RULES matches the frozen ordered digest (8 entries, identity control)", () => {
    expect(ruleDigest(WRITE_SECRET_RULES)).toEqual([...EXPECTED_WRITE_SECRET_DIGEST]);
  });

  test("prompt-rules.PROMPT_RULES + BASE64_BLOB match the frozen ordered digest (6 table entries + 1 out-of-table constant, identity control)", () => {
    const digest = [
      ...ruleDigest(PROMPT_RULES),
      `${PROMPT_RULES.length} base64-blob ${BASE64_BLOB.source} ${BASE64_BLOB.flags}`,
    ];
    expect(digest).toEqual([...EXPECTED_PROMPT_DIGEST]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// PATH_RULES, the one structure the ordered digest above cannot see. Its
// fourteen entries are `{id, test, reason}` where `test` is a PREDICATE, not
// a RegExp in a table field: there is no `.source`/`.flags` to project, so
// `ruleDigest` simply does not apply.
//
// Two mutations were measured to escape the ENTIRE suite before this lock
// existed — the suite stayed green end to end after each: removing one
// extension from crypto-key's list of fifteen, and removing the END ANCHOR
// from hook-log's pattern (without `$`, the rule would block reading the
// hooks' SOURCES, not only their logs — a silent widening that no assertion
// contradicted).
//
// The digest is taken on the SOURCE FILE'S TEXT read from disk, never on
// `Function.prototype.toString()`. Measured on this repo: bun hands back the
// TRANSPILED body (`return false` comes out as `return !1;`), so a digest
// built on toString() would go stale at the next runtime upgrade for zero
// behaviour change — it would redden on bun's version, not on anyone's edit.
//
// A single hash over the block is the other alternative, and it is
// discarded for the same reason as the ordered digest above: it reddens
// without NAMING the mutated entry, and naming what moved is this lock's
// entire job. The projection is therefore one string per significant source
// line, prefixed by its index, compared with `toEqual` — a removed, added,
// reordered or edited line shows up as a diff AT ITS OWN INDEX.
//
// This lock is a TRIPWIRE and nothing more: it says the text moved, never
// what the move means. The behaviour of the rules this port actually
// touches is asserted separately, in tests/secret-rules.test.ts. Both must
// bite independently — measured: the extension mutations redden each of the
// two files on their own.
// ─────────────────────────────────────────────────────────────────────────

const SECRET_RULES_SOURCE = join(
  // tests/ sits one level under the repo root, sibling to src/.
  import.meta.dir,
  "..",
  "src",
  "secret-rules.ts",
);

// Bounds chosen for UNIQUENESS, measured with `grep -cF` on the file: each of
// these two lines occurs exactly once. `];` was the obvious closing bound and
// is rejected — measured, it occurs 3 times in the file (PATH_RULES' close,
// BASH_RULES' close, and the `?? [];` fallback in `checkBash`), so it would
// silently pick the wrong block the day a table is reordered.
const BLOCK_START = "export const PATH_RULES: readonly PathRule[] = [";
// Updated for the abstract-verdict refactor (ticket 05): checkPath's return
// type changed from `Deny | null` to `Verdict | null`. This bound is a
// SIGNATURE marker only — it does not sit inside the frozen PATH_RULES
// block above, and the rule TABLE itself (14 entries, unchanged regexes and
// reasons) is untouched, so the digest content below did not need
// recomputation, only this string literal.
const BLOCK_END = "export function checkPath(path: string): Verdict | null {";

// ENV_WHITELIST is referenced BY NAME inside the `dotenv` predicate but
// DEFINED above the block (line 22). A digest bounded to the block alone
// would miss a widening of it — allowing `.env.production` through, say —
// while every line it does cover stayed byte-identical. It is captured by its
// declaration and appended as the digest's last entry: the same geste as
// BASE64_BLOB in the ordered rule-table digest above, which likewise lives
// outside the table it completes.
const ENV_WHITELIST_DECL = "export const ENV_WHITELIST =";

// Anti-false-green. A projection that returns [] when its bounds vanish
// compares two empty arrays and passes — the exact failure this whole file
// exists to prevent. Every degenerate case therefore THROWS with a message
// naming what went wrong, which surfaces as a red test, not as a green one.
//
// `sourcePath` is a parameter rather than the captured SECRET_RULES_SOURCE
// constant: the git-guard lock further below bounds a second file
// (command-rules.ts) with the same guard,
// and a bound failure there must name command-rules.ts. A message hardcoded to
// secret-rules.ts would fail loudly about the wrong file — loud AND wrong is
// worse than loud, since it sends the reader to a file that is intact.
function uniqueIndexOf(source: string, marker: string, sourcePath: string): number {
  const first = source.indexOf(marker);
  if (first === -1) {
    throw new Error(
      `digest bound not found in ${sourcePath}: ${JSON.stringify(marker)}. `
        + "The lock cannot be evaluated — fix the bound rather than letting it compare nothing.",
    );
  }
  if (source.indexOf(marker, first + marker.length) !== -1) {
    throw new Error(
      `digest bound is ambiguous in ${sourcePath}: `
        + `${JSON.stringify(marker)} occurs more than once. Narrow it.`,
    );
  }
  return first;
}

// Comment lines and blank lines are dropped before freezing, on purpose. The
// mutation harness (tests/mutation.ts, `isExecutableMatch`) already REFUSES
// by construction any substitution that lands only in a comment: such a
// substitution can discriminate no test, so freezing comments buys no
// guarantee. What it does buy is noise — every prose correction in a rule's
// rationale would redden this lock for no behaviour change. Each surviving
// line is trimmed so that re-indenting the block is likewise not a false
// alarm.
function significantLines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("//"));
}

function pathRulesSourceDigest(): string[] {
  const source = readFileSync(SECRET_RULES_SOURCE, "utf8");

  const startIdx = uniqueIndexOf(source, BLOCK_START, SECRET_RULES_SOURCE);
  const endIdx = uniqueIndexOf(source, BLOCK_END, SECRET_RULES_SOURCE);
  if (endIdx <= startIdx) {
    throw new Error(
      `PATH_RULES digest bounds are inverted in ${SECRET_RULES_SOURCE}: the closing bound appears `
        + "before the opening one. The lock cannot be evaluated.",
    );
  }

  const blockLines = significantLines(source.slice(startIdx, endIdx));
  if (blockLines.length === 0) {
    throw new Error(
      `PATH_RULES digest extracted an EMPTY block from ${SECRET_RULES_SOURCE}. Comparing two empty `
        + "arrays would pass — failing instead.",
    );
  }

  const envStart = uniqueIndexOf(source, ENV_WHITELIST_DECL, SECRET_RULES_SOURCE);
  const envNewline = source.indexOf("\n", envStart);
  const envLine = source.slice(envStart, envNewline === -1 ? source.length : envNewline).trim();

  return [...blockLines, envLine].map((line, i) => `${i} ${line}`);
}

// Every `id: '…'` the extracted TEXT declares, in reading order. Bridged
// against the loaded module below: without that bridge a digest can happily
// freeze a file that is no longer the one the suite executes (a stale path, a
// renamed module, a re-export), and report green about bytes nobody runs.
function idsDeclaredInSource(): string[] {
  const source = readFileSync(SECRET_RULES_SOURCE, "utf8");
  const startIdx = uniqueIndexOf(source, BLOCK_START, SECRET_RULES_SOURCE);
  const endIdx = uniqueIndexOf(source, BLOCK_END, SECRET_RULES_SOURCE);
  const block = source.slice(startIdx, endIdx);
  return [...block.matchAll(/\bid:\s*'([^']*)'/g)].map((m) => m[1]!);
}

// DERIVED by running the projection above against the real file and printing
// its output — never hand-transcribed from the source. A hand copy would be a
// second source of truth for the same bytes, and would drift silently.
const EXPECTED_PATH_RULES_SOURCE_DIGEST: readonly string[] = [
  "0 export const PATH_RULES: readonly PathRule[] = [",
  "1 {",
  "2 id: 'dotenv',",
  "3 test: (p) => /(^|\\/)\\.env[^/]*$/.test(p) && !ENV_WHITELIST.test(p),",
  "4 reason: '.env file blocked (only .env.example and .env.test are allowed)',",
  "5 },",
  "6 {",
  "7 id: 'crypto-key',",
  "8 test: (p) =>",
  "9 /(^|\\/)[^/.][^/]*\\.(pem|key|pkey|crt|cert|pfx|p12|jks|keystore|gpg|asc|kdbx|kbx|agekey|ovpn)$/i",
  "10 .test(p),",
  "11 reason: 'Cryptographic key/certificate file blocked',",
  "12 },",
  "13 {",
  "14 id: 'ssh-key',",
  "15 test: (p) => /(^|\\/)id_(rsa|dsa|ecdsa|ed25519)(\\.pub)?$/.test(p),",
  "16 reason: 'SSH key file blocked',",
  "17 },",
  "18 {",
  "19 id: 'aws-creds',",
  "20 test: (p) => /(^|\\/)\\.aws\\/(credentials|config)$/.test(p),",
  "21 reason: 'AWS credentials/config blocked',",
  "22 },",
  "23 {",
  "24 id: 'netrc-pgpass',",
  "25 test: (p) => /(^|\\/)\\.(netrc|pgpass)$/.test(p),",
  "26 reason: '.netrc/.pgpass blocked',",
  "27 },",
  "28 {",
  "29 id: 'cloud-sa',",
  "30 test: (p) => /(service-account|firebase-adminsdk|gcp-key)[^/]*\\.json$/i.test(p),",
  "31 reason: 'Cloud service-account JSON blocked',",
  "32 },",
  "33 {",
  "34 id: 'tfstate',",
  "35 test: (p) => /\\.tfstate(\\.backup)?$|\\.terraform\\.tfstate\\.lock\\.info$/.test(p),",
  "36 reason: 'Terraform state file blocked (often contains plaintext secrets)',",
  "37 },",
  "38 {",
  "39 id: 'npmrc',",
  "40 test: (p) => /(^|\\/)\\.npmrc$/.test(p) && !p.includes('/node_modules/'),",
  "41 reason: '.npmrc blocked outside node_modules/ (may contain _authToken)',",
  "42 },",
  "43 {",
  "44 id: 'gitconfig',",
  "45 test: (p) => /(^|\\/)\\.gitconfig$/.test(p),",
  "46 reason: '.gitconfig blocked (may contain [credential] tokens or signing keys)',",
  "47 },",
  "48 {",
  "49 id: 'hook-log',",
  "50 test: (p) =>",
  "51 /(^|\\/)(?:guard-command|guard-secret|guard-write-secret|guard-mcp-write|transcript-backup)\\.log$/",
  "52 .test(p),",
  "53 reason: 'hook audit log blocked (would leak history of denied tool calls)',",
  "54 },",
  "55 {",
  "56 id: 'transcript-backup',",
  "57 test: (p) => /(^|\\/)\\.claude\\/transcripts(\\/|$)/.test(p),",
  "58 reason: 'transcript backup directory blocked (contains full session history)',",
  "59 },",
  "60 {",
  "61 id: 'secret-dir',",
  "62 test: (p) => /(^|\\/)(\\.?secrets|credentials)(\\/|$)/.test(p),",
  "63 reason: 'Path inside secrets/ or credentials/ directory blocked',",
  "64 },",
  "65 {",
  "66 id: 'ssh-dir',",
  "67 test: (p) => /(^|\\/)\\.ssh(\\/|$)/.test(p),",
  "68 reason: '.ssh directory blocked',",
  "69 },",
  "70 {",
  "71 id: 'gnupg-dir',",
  "72 test: (p) => /(^|\\/)\\.gnupg(\\/|$)/.test(p),",
  "73 reason: '.gnupg directory blocked',",
  "74 },",
  "75 ];",
  "76 export const ENV_WHITELIST = /(^|\\/)\\.env\\.(example|test)$/;",
];

describe("guards-digest: tamper lock — PATH_RULES, the predicate-shaped guard", () => {
  test("the extracted block is non-degenerate (bounds unique, block non-empty)", () => {
    // Runs the extraction on its own so a bound problem is reported as a bound
    // problem, not buried in a 77-line array diff.
    const digest = pathRulesSourceDigest();
    expect(digest.length).toBeGreaterThan(0);
    expect(digest[0]).toBe(`0 ${BLOCK_START}`);
  });

  test("the extracted text is the module the suite actually runs (ids match, in order)", () => {
    expect(idsDeclaredInSource()).toEqual(PATH_RULES.map((r) => r.id));
  });

  test("secret-rules.PATH_RULES source matches the frozen ordered digest (14 entries + ENV_WHITELIST)", () => {
    expect(pathRulesSourceDigest()).toEqual([...EXPECTED_PATH_RULES_SOURCE_DIGEST]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The git guard, the last of the three non-tabular structures this file
// locks. It is not one shape but three, and no `{ruleId, regex}` digest can
// see any of them:
//   • SAFE_GIT_SUBCOMMANDS — a Set of 31 auto-approved verbs (silent).
//   • GIT_BENIGN_PREFIXES  — a Set of 7 tokens tolerated in front of `git`.
//   • gitSubcommandNeedsConfirm — a chain of 15 `if (sub === …)` blocks covering
//     16 subcommands, deciding on the ARGUMENTS rather than on the verb.
//
// Two holes were measured on the suite as it stood before this lock, and
// they are the reason the task exists:
//
//   1. The only test that iterates SAFE_GIT_SUBCOMMANDS (command-rules.test
//      .ts, "benign: every SAFE_GIT_SUBCOMMANDS entry passes") LOOPS OVER THE
//      SET ITSELF. Delete an entry and it leaves the loop with it: the
//      assertion still passes, on a smaller allowlist. A lock that re-derives
//      its expectation from the structure it is checking proves nothing. The
//      frozen arrays below are therefore an INDEPENDENT second copy — the one
//      place in this file where duplicating the source is the point, not the
//      defect.
//   2. `nice` is a member of GIT_BENIGN_PREFIXES that no test exercised
//      (measured: the only `nice` in command-rules.test.ts drives the `sudo`
//      regex, an unrelated pattern that carries its own copy of the word).
//      Likewise the `config` read alternation had a vector for `--get` and
//      for none of its seven other branches.
//
// The frozen arrays were DERIVED by running these exact projections against
// the real module and printing the output, never hand-transcribed — the same
// discipline as the two locks above, for the same reason: a hand copy is a
// second source of truth for the same bytes and drifts in silence.
// ─────────────────────────────────────────────────────────────────────────

// Compared in DECLARATION order, not sorted. The order of a membership Set
// carries no evaluation meaning — `SAFE_GIT_SUBCOMMANDS.has(sub)` answers the
// same thing whatever the insertion sequence, unlike the rule tables of the
// ordered digest above where the first match wins and position is part of
// identity. Sorting was the alternative, and it was discarded on two counts.
// It buys tolerance to a pure reorder, which is a behaviour no-op — but it
// pays for that with an array a reviewer can no longer read against the diff
// of command-rules.ts, and this lock is a tripwire read IN the diff. And the
// tolerance is not needed: iteration order of a Set is insertion order by
// specification, so this projection is deterministic across runtimes — the
// exact property that `Function.prototype.toString()` lacked when that
// ordered digest measured it transpiling `return false` into `return !1;`.
// The accepted cost is stated plainly: a
// deliberate reorder of the source reddens this lock (measured, mutation G6),
// and the fix is to re-derive the array, not to sort it.
const EXPECTED_SAFE_GIT_SUBCOMMANDS: readonly string[] = [
  "status",
  "diff",
  "log",
  "show",
  "blame",
  "shortlog",
  "describe",
  "rev-parse",
  "ls-files",
  "cat-file",
  "grep",
  "add",
  "commit",
  "fetch",
  "ls-remote",
  "for-each-ref",
  "ls-tree",
  "check-ignore",
  "rev-list",
  "merge-base",
  "show-ref",
  "show-branch",
  "name-rev",
  "count-objects",
  "var",
  "range-diff",
  "cherry",
  "whatchanged",
  "diff-tree",
  "diff-index",
  "fsck",
];

// Same approach, same order argument. Seven entries; `proxy` is deliberately
// NOT among them (it is consumed by a special case that only fires right
// after `rtk`), which is why this set and the `sudo` rule's wrapper
// alternation cannot be folded into one another — they answer different
// questions (a benign prefix in front of `git` vs. a privilege-escalation
// tool name) and merging them would let `proxy` sneak into a context where
// it was never vetted.
const EXPECTED_GIT_BENIGN_PREFIXES: readonly string[] = [
  "rtk",
  "command",
  "exec",
  "env",
  "nice",
  "time",
  "builtin",
];

describe("guards-digest: tamper lock — the git guard's two membership sets", () => {
  test("SAFE_GIT_SUBCOMMANDS matches the frozen list, in declaration order (31 entries)", () => {
    expect([...SAFE_GIT_SUBCOMMANDS]).toEqual([...EXPECTED_SAFE_GIT_SUBCOMMANDS]);
  });

  // The count is asserted apart from the list. `toEqual` on the list already
  // fails when an entry disappears, but it reports a 31-line array diff; this
  // one line says "the allowlist changed size" in the first line of output,
  // which is the sentence a reviewer needs before reading the diff.
  test("SAFE_GIT_SUBCOMMANDS still holds exactly 31 entries", () => {
    expect(SAFE_GIT_SUBCOMMANDS.size).toBe(31);
  });

  test("GIT_BENIGN_PREFIXES matches the frozen list, in declaration order (7 entries)", () => {
    expect([...GIT_BENIGN_PREFIXES]).toEqual([...EXPECTED_GIT_BENIGN_PREFIXES]);
  });

  test("GIT_BENIGN_PREFIXES still holds exactly 7 entries", () => {
    expect(GIT_BENIGN_PREFIXES.size).toBe(7);
  });

  // Membership alone is not behaviour: an entry can sit in the set while the
  // parser stops consulting it. This vector goes through checkGit, so it
  // reddens both when `nice` leaves the set AND when extractGitSubcommand
  // stops honouring the set at all. It is the only assertion in the suite
  // that exercises `nice` as a git prefix (measured before writing it).
  test("a benign prefix is honoured end to end: nice git push still asks", () => {
    expect(checkGit("nice git push")?.ruleId).toBe("git-protected");
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The conditional chain: one row per subcommand, sixteen rows.
//
// Each row carries a READING form that must stay silent and a MUTATING form
// that must ask. Both columns are load-bearing and they catch opposite
// mutations, which is why neither can be dropped:
//   • Deleting a block entirely drops its subcommand to the catch-all `return
//     true`. The mutating form still asks — only the READING form reddens.
//   • Emptying a block's body to `return false` keeps the subcommand out of
//     the catch-all. The reading form still passes — only the MUTATING form
//     reddens.
// Measured as mutations G3 and G4 respectively.
//
// Equivalent vectors already exist as individual tests in
// tests/rules/command-rules.test.ts, and the redundancy is deliberate. Those
// tests demonstrate BEHAVIOUR: each names a real command a user types and
// says what the guard answers. This table is an EXHAUSTIVENESS lock: its rows
// are tied by `toEqual` to the subcommand list scraped out of the source
// below, so the chain and the table can no longer drift apart in either
// direction. Deleting a row from this table reddens the scrape; deleting a
// test from command-rules.test.ts reddens nothing, which is precisely the gap
// this table closes rather than replaces.
//
// The tests are registered by looping over this frozen table, which is NOT
// the self-reference criticised at the top of this section: the loop's source
// is a literal written here, cross-checked against the source file — not the
// runtime structure under test.
// ─────────────────────────────────────────────────────────────────────────

interface GitConditionalCase {
  /** The subcommand the chain tests with `sub === '…'`. */
  readonly sub: string;
  /** A form the guard must let through silently. */
  readonly reading: string;
  /** A form the guard must surface for confirmation. */
  readonly mutating: string;
}

const GIT_CONDITIONAL_MATRIX: readonly GitConditionalCase[] = [
  { sub: "branch", reading: "git branch --list", mutating: "git branch -D old-branch" },
  { sub: "tag", reading: "git tag v1.0", mutating: "git tag -d v1.0" },
  { sub: "stash", reading: "git stash list", mutating: "git stash drop" },
  { sub: "reflog", reading: "git reflog show", mutating: "git reflog expire --all" },
  { sub: "submodule", reading: "git submodule status", mutating: "git submodule update --init" },
  {
    sub: "remote",
    reading: "git remote -v",
    mutating: "git remote add origin https://example.test/x.git",
  },
  { sub: "config", reading: "git config --get user.name", mutating: "git config user.name x" },
  { sub: "bundle", reading: "git bundle verify b.pack", mutating: "git bundle create b.pack HEAD" },
  { sub: "symbolic-ref", reading: "git symbolic-ref HEAD", mutating: "git symbolic-ref -d HEAD" },
  { sub: "checkout", reading: "git checkout main", mutating: "git checkout -f" },
  { sub: "switch", reading: "git switch feat", mutating: "git switch --discard-changes" },
  { sub: "pull", reading: "git pull --ff-only", mutating: "git pull" },
  { sub: "merge", reading: "git merge --ff-only feat", mutating: "git merge feat" },
  { sub: "worktree", reading: "git worktree list", mutating: "git worktree remove w" },
  { sub: "apply", reading: "git apply --check p.diff", mutating: "git apply p.diff" },
  { sub: "restore", reading: "git restore --staged f.ts", mutating: "git restore f.ts" },
];

describe("guards-digest: tamper lock — the 16 conditional git subcommands", () => {
  for (const { sub, reading, mutating } of GIT_CONDITIONAL_MATRIX) {
    test(`git ${sub}: the reading form stays silent (${reading})`, () => {
      expect(checkGit(reading)).toBeNull();
    });

    test(`git ${sub}: the mutating form asks (${mutating})`, () => {
      expect(checkGit(mutating)?.ruleId).toBe("git-protected");
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// The `config` read alternation, eight branches, eight positives.
//
// Narrowing this alternation needs one vector PER branch to catch it: with a
// single `--get` vector, narrowing the alternation to its first two branches
// was measured to redden nothing at all. These eight are written as separate
// tests rather than one loop-free block so that the FAILING TEST NAME says
// which branch was lost — naming what moved is this lock's whole purpose,
// and a single test asserting eight commands would only report the first.
//
// They live in their own table rather than as extra rows of the matrix above,
// because that matrix is bound to exactly one row per subcommand: its row
// list is compared to the scraped subcommand list. Folding seven extra
// `config` rows into it would break that equation for the sake of grouping.
// ─────────────────────────────────────────────────────────────────────────

const GIT_CONFIG_READ_BRANCHES: readonly { readonly branch: string; readonly cmd: string }[] = [
  { branch: "--get", cmd: "git config --get user.name" },
  { branch: "--get-all", cmd: "git config --get-all user.name" },
  { branch: "--get-regexp", cmd: "git config --get-regexp ^user\\." },
  { branch: "--get-urlmatch", cmd: "git config --get-urlmatch http https://example.test" },
  { branch: "--list", cmd: "git config --list" },
  { branch: "-l", cmd: "git config -l" },
  { branch: "get", cmd: "git config get user.name" },
  { branch: "list", cmd: "git config list" },
];

describe("guards-digest: tamper lock — every branch of the config read alternation", () => {
  for (const { branch, cmd } of GIT_CONFIG_READ_BRANCHES) {
    test(`git config ${branch} is a read and stays silent`, () => {
      expect(checkGit(cmd)).toBeNull();
    });
  }

  // The counter-example that keeps the eight positives honest. Widen the
  // alternation to anything (`/^.*$/`) and all eight still pass while every
  // config write walks through; this one contradicts that mutant.
  test("git config user.name x is a write and still asks", () => {
    expect(checkGit("git config user.name x")?.ruleId).toBe("git-protected");
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The chain scraped from the SOURCE, constrained equal to the matrix.
//
// This is what makes the matrix more than a list of examples. Taking the
// expected count from `GIT_CONDITIONAL_MATRIX.length` would be circular:
// deleting a block AND its two rows would leave the suite green, the exact
// failure mode amendment A3 had to correct twice on this change. The
// expectation is therefore read out of command-rules.ts itself, so the two
// copies must agree.
//
// Bounds are the function's own signature and the NEXT function's signature,
// both measured unique with `grep -cF` on the file. `}` and `return true;`
// were the naive closing bounds and are rejected for the reason the
// PATH_RULES lock above rejected
// `];`: they occur many times, so they would silently pick the wrong span the
// day the chain is edited. A missing or ambiguous bound throws through
// `uniqueIndexOf` rather than yielding an empty extract that would compare
// clean.
// ─────────────────────────────────────────────────────────────────────────

const COMMAND_RULES_SOURCE = join(
  import.meta.dir,
  "..",
  "src",
  "command-rules.ts",
);

// Renamed from gitSubcommandNeedsAsk (ticket 05: the core speaks
// block/confirm/flag/observe now, not deny/ask, and the function name is
// no longer allowed to say otherwise). Only this bound string and the
// frozen signature line below changed — the chain's BODY (the 15
// `if (sub === …)` blocks and everything they decide) is byte-identical,
// so nothing else in this file needed recomputation.
const CHAIN_START = "export function gitSubcommandNeedsConfirm";
const CHAIN_END = "export function checkGit";

function gitChainSignificantLines(): string[] {
  const source = readFileSync(COMMAND_RULES_SOURCE, "utf8");
  const startIdx = uniqueIndexOf(source, CHAIN_START, COMMAND_RULES_SOURCE);
  const endIdx = uniqueIndexOf(source, CHAIN_END, COMMAND_RULES_SOURCE);
  if (endIdx <= startIdx) {
    throw new Error(
      `git chain bounds are inverted in ${COMMAND_RULES_SOURCE}: the closing bound appears before `
        + "the opening one. The lock cannot be evaluated.",
    );
  }
  // Comment lines are dropped here for correctness, not just for noise: the
  // chain's own comments quote subcommand names (`worktree list` reads; …),
  // and a scrape that counted them would report branches the code does not
  // have. `significantLines` is reused from the PATH_RULES lock above rather
  // than duplicated — same
  // trimming, same comment filter.
  const lines = significantLines(source.slice(startIdx, endIdx));
  if (lines.length === 0) {
    throw new Error(
      `the git chain extracted EMPTY from ${COMMAND_RULES_SOURCE}. Comparing two empty arrays `
        + "would pass — failing instead.",
    );
  }
  return lines;
}

// Every subcommand the chain compares `sub` against, in reading order. Sixteen
// of them, spread over fifteen blocks.
function gitChainSubcommandsInSource(): string[] {
  const chain = gitChainSignificantLines().join("\n");
  const subs = [...chain.matchAll(/\bsub === '([^']*)'/g)].map((m) => m[1]!);
  if (subs.length === 0) {
    throw new Error(
      `no \`sub === '…'\` comparison found in the git chain of ${COMMAND_RULES_SOURCE}. Either the `
        + "chain was rewritten in another shape or the bounds slipped — failing rather than "
        + "reporting an empty list as agreement.",
    );
  }
  return subs;
}

// Every line that OPENS a block, in reading order. Fifteen of them.
function gitChainBlockHeadsInSource(): string[] {
  return gitChainSignificantLines()
    .filter((line) => line.startsWith("if (sub === "))
    .map((line, i) => `${i} ${line}`);
}

// DERIVED by printing the projection above against the real file. Fifteen
// entries for sixteen subcommands, and the discrepancy is NOT an error to be
// tidied up: index 11 is `if (sub === 'pull' || sub === 'merge') {`, one block
// that answers for two verbs because both are governed by the same test
// (`--ff-only` cannot rewrite history). Freezing the heads as well as the
// subcommand list is what distinguishes the two numbers: splitting that block
// in two would leave the subcommand list byte-identical — same names, same
// order — and only this array would notice.
const EXPECTED_GIT_CHAIN_BLOCK_HEADS: readonly string[] = [
  "0 if (sub === 'branch') {",
  "1 if (sub === 'tag') {",
  "2 if (sub === 'stash') {",
  "3 if (sub === 'reflog') {",
  "4 if (sub === 'submodule') {",
  "5 if (sub === 'remote') {",
  "6 if (sub === 'config') {",
  "7 if (sub === 'bundle') {",
  "8 if (sub === 'symbolic-ref') {",
  "9 if (sub === 'checkout') {",
  "10 if (sub === 'switch') {",
  "11 if (sub === 'pull' || sub === 'merge') {",
  "12 if (sub === 'worktree') {",
  "13 if (sub === 'apply') {",
  "14 if (sub === 'restore') {",
];

describe("guards-digest: tamper lock — the conditional chain, scraped from its source", () => {
  test("the extracted chain is non-degenerate (bounds unique, extract non-empty)", () => {
    // Run apart from the comparisons so a bound problem is reported as a bound
    // problem instead of surfacing as a puzzling empty-array diff.
    const lines = gitChainSignificantLines();
    expect(lines.length).toBeGreaterThan(0);
    expect(lines[0]).toBe(
      "export function gitSubcommandNeedsConfirm(sub: string, rest: readonly string[]): boolean {",
    );
  });

  // The equation that makes the matrix non-circular, and it compares LISTS,
  // not sizes: `16 ≠ 15` names nothing, whereas a list diff says `worktree`
  // left the chain — naming what moved, not just that something did, is
  // this lock's whole purpose.
  test("the subcommands in the source are exactly the matrix's, in the same order (16)", () => {
    expect(gitChainSubcommandsInSource()).toEqual(GIT_CONDITIONAL_MATRIX.map((c) => c.sub));
  });

  test("the chain still opens exactly 15 blocks, pull/merge sharing one", () => {
    expect(gitChainBlockHeadsInSource()).toEqual([...EXPECTED_GIT_CHAIN_BLOCK_HEADS]);
  });

  // The two counts, stated out loud so the next reader does not "fix" the gap.
  // Sixteen subcommands, fifteen blocks; the difference is pull||merge.
  test("16 subcommands over 15 blocks — the difference is the shared pull/merge block", () => {
    expect(gitChainSubcommandsInSource()).toHaveLength(16);
    expect(gitChainBlockHeadsInSource()).toHaveLength(15);
    expect(EXPECTED_GIT_CHAIN_BLOCK_HEADS[11]).toContain("'pull' || sub === 'merge'");
  });
});

// ─────────────────────────────────────────────────────────────────────────
// MCP_READ_PREFIXES is the last of this file's locks. It is an allowlist
// rather than a rule table, so the named projection is `${index} ${prefix}`:
// an edit, addition, removal or reorder appears at its own index instead of
// collapsing to a count-only assertion.
//
// Declaration order does not change the authorization verdict: `.some()` is
// an OR over the same prefixes. Measured by swapping `get` and `list`, every
// read/write verdict stayed identical while their successful reads took two
// and one prefix comparisons instead of one and two. Sorting was therefore the
// tempting alternative, but it is rejected: it would hide a source reorder,
// and naming the input that moved is this tripwire's whole purpose. The
// accepted cost is a red digest for a performance-only reorder; re-derive
// the frozen array after reviewing such a deliberate change.
//
// The frozen array was DERIVED by running this exact projection against the
// loaded module and printing its output, never hand-transcribed from the
// source literal.
// ─────────────────────────────────────────────────────────────────────────

function mcpReadPrefixDigest(prefixes: readonly string[]): string[] {
  return prefixes.map((prefix, index) => `${index} ${prefix}`);
}

const EXPECTED_MCP_READ_PREFIX_DIGEST: readonly string[] = [
  "0 get",
  "1 list",
  "2 search",
  "3 fetch",
  "4 read",
  "5 query",
  "6 lookup",
  "7 describe",
  "8 view",
];

describe("guards-digest: tamper lock — the MCP read allowlist", () => {
  test("mcp-write-rules.MCP_READ_PREFIXES matches the frozen ordered digest (9 entries)", () => {
    expect(mcpReadPrefixDigest(MCP_READ_PREFIXES)).toEqual([
      ...EXPECTED_MCP_READ_PREFIX_DIGEST,
    ]);
  });
});
