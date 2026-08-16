// Command-guard rules: the destructive/exfiltration/escalation pattern
// table plus the git policy (structural tokenizer, ratified conditional
// grammars). Pure — no Bun/Node APIs, no harness protocol shapes — so any
// adapter (Claude Code today, any future harness) can call checkBash()
// with nothing but a command string.
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

import type { BashRule, Verdict } from './types.ts';

// ─── Tier 1 helper: rm -rf with dangerous target detection ───────────

// Dangerous absolute or special-form targets that destroy the system or
// the user's whole tree when paired with rm -rf.
export const DANGEROUS_RM_TARGETS: readonly RegExp[] = [
  /^\/$/, // /
  /^\/\*$/, // /*
  /^~\/?$/, // ~ or ~/
  /^~\/\*$/, // ~/*
  /^\$\{?HOME\}?\/?$/, // $HOME or ${HOME}/
  /^\$\{?HOME\}?\/\*$/, // $HOME/*
  /^\.\.\/?$/, // .. or ../
  /^\.\.\/\*$/, // ../*
  /^\*$/, // *
  /^\.\/?$/, // . or ./
  /^\/(etc|usr|var|bin|sbin|lib|sys|proc|boot|root|home|opt|srv|System|Library|Applications)(\/.*)?$/,
];

// Whitelist exposed for documentation and external introspection. NOTE:
// the runtime check (checkRmRf) deliberately ignores this list when the
// target is in DANGEROUS_RM_TARGETS — dangerous always wins. The list
// describes "common, safe rm -rf intents"; non-dangerous targets are
// already implicitly allowed because no rule fires.
export const RM_ALLOWED_TARGETS: readonly RegExp[] = [
  /(^|\/)node_modules(\/[^\s]*)?$/,
  /(^|\/)dist(\/[^\s]*)?$/,
  /(^|\/)\.next(\/[^\s]*)?$/,
  /(^|\/)\.turbo(\/[^\s]*)?$/,
  /(^|\/)coverage(\/[^\s]*)?$/,
  /(^|\/)\.cache(\/[^\s]*)?$/,
];

export function hasRmRf(segment: string): boolean {
  // Both -r/-R/--recursive AND -f/-F/--force must appear in the segment.
  const hasR = /-[a-zA-Z]*[rR][a-zA-Z]*\b|--recursive\b/.test(segment);
  const hasF = /-[a-zA-Z]*[fF][a-zA-Z]*\b|--force\b/.test(segment);
  return hasR && hasF;
}

export function isDangerousRmTarget(target: string): boolean {
  return DANGEROUS_RM_TARGETS.some((re) => re.test(target));
}

export function checkRmRf(cmd: string): Verdict | null {
  // Slice the command at command separators so we evaluate each rm
  // segment independently of surrounding pipes / chains.
  const rmSegments = cmd.match(/\brm\b[^;|&\n]*/g) ?? [];
  for (const seg of rmSegments) {
    if (!hasRmRf(seg)) continue;
    const tokens = seg.split(/\s+/).slice(1).filter((t) => t && !t.startsWith('-'));
    for (const target of tokens) {
      // Dangerous always wins; the allowlist is informative only and
      // cannot override system-path destruction (e.g. /etc/node_modules).
      if (isDangerousRmTarget(target)) {
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

export const PRIVILEGE_ESCALATION_COMMANDS: ReadonlySet<string> = new Set([
  'sudo',
  'doas',
  'pkexec',
  'runas',
  'please',
]);

const PRIVILEGE_ESCALATION_REASON =
  'Privilege escalation tool (sudo/doas/pkexec/runas/please) — confirm manually outside the agent session';

// ─── Tier 1, 2, 3 — pattern rules ────────────────────────────────────

export const BASH_RULES: readonly BashRule[] = [
  // Tier 1 — destruction
  {
    regex: /\bdd\s+[^|;&\n]*\bof=\/dev\//,
    ruleId: 'dd-device-write',
    reason: 'dd writing to a block device (/dev/...) — likely disk wipe',
  },
  {
    regex: /\bmkfs(\.\w+)?\b/,
    ruleId: 'mkfs',
    reason: 'mkfs reformats a filesystem — irreversible',
  },
  {
    regex: />\s*\/dev\/(sda|sdb|disk|nvme|hd|md|loop)\w*/,
    ruleId: 'device-redirect',
    reason: 'Shell redirection writing to a block device (potential disk corruption)',
  },
  {
    regex: /\btee\s+(?:-a\s+|--append\s+)?\/dev\/(sda|sdb|disk|nvme|hd|md|loop)\w*/,
    ruleId: 'device-redirect',
    reason: 'tee writing to a block device (potential disk corruption)',
  },
  {
    regex: /\bchmod\s+-R\s+0?[0-7]{1,4}\s+\/(?:\s|$)/,
    ruleId: 'chmod-root',
    reason: 'Recursive chmod on / — likely to break the system',
  },
  {
    regex: /\bchown\s+-R\s+\S+\s+\/(?:\s|$)/,
    ruleId: 'chown-root',
    reason: 'Recursive chown on / — likely to break the system',
  },

  // Tier 2 — exfiltration
  {
    // -d / --data / --data-binary / --data-raw / --data-urlencode use `@<path>`.
    // -F / --form uses `field=@<path>`.
    // -T / --upload-file take a bare path argument.
    regex:
      /\bcurl\b[^|;&\n]*?\s(?:(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\s+@\S+|(?:-F|--form)\s+\S*=@|(?:-T|--upload-file)\s+\S+)/,
    ruleId: 'curl-file-upload',
    reason: 'curl uploading a local file (potential exfiltration)',
  },
  {
    regex: /\bwget\b[^|;&\n]*--post-(?:file|data)=/,
    ruleId: 'wget-post-file',
    reason: 'wget posting a local file or data (potential exfiltration)',
  },
  {
    regex: /\bn(?:c|cat)\b[^|;&\n]*<\s*[^\s<]/,
    ruleId: 'nc-file-redirect',
    reason: 'netcat reading a file via stdin redirection (exfiltration)',
  },

  // Tier 3 — escalation / shell pollution
  {
    regex: /\bchmod\s+(?:[ugoa]*\+s|[0-7]?[2-7][0-7]{2,3})\b/,
    ruleId: 'setuid',
    reason: 'chmod setting setuid/setgid bit',
  },
  {
    regex: /(?:>|>>)\s*\/etc\/(sudoers|passwd|shadow|hosts|ssh\/sshd_config)\b/,
    ruleId: 'etc-write',
    reason: 'Writing to a critical /etc file (sudoers, passwd, shadow, hosts, sshd_config)',
  },
  {
    regex: /\btee\s+(?:-a\s+|--append\s+)?\/etc\/(sudoers|passwd|shadow|hosts|ssh\/sshd_config)\b/,
    ruleId: 'etc-write',
    reason: 'tee writing to a critical /etc file (sudoers, passwd, shadow, hosts, sshd_config)',
  },
  {
    regex: /\bkill(?:all)?\s+(?:-(?:9|KILL)\s+)?(?:-?-?\s*)?(?:1|init)\b/,
    ruleId: 'kill-init',
    reason: 'Killing PID 1 / init — system halt',
  },
  {
    regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    ruleId: 'fork-bomb',
    reason: 'Fork bomb pattern detected',
  },
  {
    regex: /(?:curl|wget)\b[^|;&\n]*\|\s*(?:sh|bash|zsh|ksh|fish|sudo)\b/,
    ruleId: 'download-exec',
    reason: 'Piping curl/wget output directly to a shell (download-and-execute)',
  },
  {
    // Matches both `eval $(curl ...)` and `eval `curl ...`` (backticks).
    regex: /\beval\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/,
    ruleId: 'eval-download',
    reason: 'eval of curl/wget output (download-and-execute)',
  },
  {
    regex: /\b(?:bash|sh|zsh|ksh)\s+<\s*\(\s*(?:curl|wget)\b/,
    ruleId: 'process-substitution-download',
    reason: 'Process substitution feeding curl/wget output to a shell (download-and-execute)',
  },
];

// ─── Git guard: ASK before history-rewriting / remote / destructive ops ──
//
// Maintainable by inversion: a small SAFE_GIT allowlist is auto-approved;
// every OTHER subcommand surfaces an interactive prompt ("ask"). New or
// unknown git subcommands therefore default to "ask" without editing this
// file — the open-ended dangerous set never has to be enumerated.

// Subcommands safe with any flags (read-only, or local-additive).
export const SAFE_GIT_SUBCOMMANDS: ReadonlySet<string> = new Set([
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
  // Pure reads (network reads included) — high false-positive volume in
  // real transcripts before they were allowlisted.
  'ls-remote',
  'for-each-ref',
  'ls-tree',
  'check-ignore',
  'rev-list',
  'merge-base',
  // Pure reads, second batch. NOTE: subcommands with writing variants
  // (worktree, apply, restore) do NOT belong here — they get conditional
  // forms in gitSubcommandNeedsConfirm.
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
]);

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
  let quote: '"' | "'" | null = null;
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
    if (ch === '"' || ch === "'") {
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
type GitCommand = { sub: string; rest: string[]; forceConfirm?: true };

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
    i = tokens.findIndex((token, index) =>
      index >= prefix.index && (token.value === 'git' || token.value.endsWith('/git'))
    );
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
): { readonly index: number; readonly ambiguous: boolean } {
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

export function checkPrivilegeEscalation(cmd: string): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const prefix = consumeCommandPrefixes(tokens, PRIVILEGE_BENIGN_PREFIXES);
    const index = prefix.ambiguous
      ? tokens.findIndex((token, tokenIndex) =>
        tokenIndex >= prefix.index
        && isCommandNamed(token.value, PRIVILEGE_ESCALATION_COMMANDS)
      )
      : prefix.index;
    if (
      index === -1
      || !isCommandNamed(tokens[index]?.value, PRIVILEGE_ESCALATION_COMMANDS)
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

const GIT_CONFIG_READ_MODES: ReadonlySet<string> = new Set([
  '--get',
  '--get-all',
  '--get-regexp',
  '--get-urlmatch',
  '--list',
  '-l',
  'get',
  'list',
]);

export function isGitConfigRead(cmdOrRest: string | readonly string[]): boolean {
  if (typeof cmdOrRest !== 'string') {
    return GIT_CONFIG_READ_MODES.has(cmdOrRest[0] ?? '');
  }

  const segments = tokenizeShellSegments(cmdOrRest);
  const configCommands = segments
    .map(extractGitSubcommandFromTokens)
    .filter((parsed): parsed is GitCommand => parsed?.sub === 'config');
  return configCommands.length > 0
    && configCommands.every((parsed) =>
      parsed.forceConfirm !== true && GIT_CONFIG_READ_MODES.has(parsed.rest[0] ?? '')
    );
}

const GIT_REMOTE_URL_KEY = /^remote\.[^\s]+\.url$/;

export function hasUnsafeGitConfigRemoteUrl(cmd: string): boolean {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const gitIndex = tokens.findIndex((token) =>
      token.value === 'git' || token.value.endsWith('/git')
    );
    if (
      gitIndex === -1
      || !tokens.slice(gitIndex + 1).some((token) => token.value === 'config')
    ) continue;
    if (!tokens.some((token) => GIT_REMOTE_URL_KEY.test(token.value))) continue;

    const parsed = extractGitSubcommandFromTokens(tokens);
    if (
      parsed?.sub !== 'config'
      || parsed.forceConfirm === true
      || !isGitConfigRead(parsed.rest)
    ) return true;
  }
  return false;
}

// Positional (non-flag) arguments, ignoring shell redirection tokens
// (`2>`, `2>/dev/null`, `>out`, `<in`) that survive segment splitting.
function positionalArgs(rest: readonly string[]): string[] {
  return rest.filter((t) => !t.startsWith('-') && !/[<>]/.test(t));
}

export function gitSubcommandNeedsConfirm(sub: string, rest: readonly string[]): boolean {
  if (SAFE_GIT_SUBCOMMANDS.has(sub)) return false;

  // Conditionally-safe: allow the read/additive form, ask on destructive flags.
  if (sub === 'branch') {
    return rest.some((t) => /^(-d|-D|--delete|-m|-M|--move|-f|--force)$/.test(t));
  }
  if (sub === 'tag') {
    return rest.some((t) => /^(-d|--delete)$/.test(t));
  }
  if (sub === 'stash') {
    return rest.length > 0 && /^(drop|clear)$/.test(rest[0]!);
  }
  if (sub === 'reflog') {
    // Fail closed: only the documented read forms are silent. New reflog
    // subcommands must be reviewed before joining this allowlist.
    return rest.length > 0 && !/^(show|list|exists)$/.test(rest[0]!);
  }
  if (sub === 'submodule') {
    return rest.length > 0 && !/^(status|summary)$/.test(rest[0]!);
  }
  if (sub === 'remote') {
    return rest.length > 0 && !/^(-v|--verbose|show|get-url)$/.test(rest[0]!);
  }
  if (sub === 'config') {
    // Reads only; positional reads (`config core.hooksPath`) still ask
    // because they are token-identical to `config key value` writes.
    return !isGitConfigRead(rest);
  }
  if (sub === 'bundle') {
    return !/^(verify|list-heads)$/.test(rest[0] ?? '');
  }
  if (sub === 'symbolic-ref') {
    if (rest.some((t) => /^(-d|--delete)$/.test(t))) return true;
    // One positional (`symbolic-ref [-q|--short] HEAD`) reads the ref;
    // two (`symbolic-ref HEAD refs/heads/x`) rewrites it.
    return positionalArgs(rest).length > 1;
  }
  if (sub === 'checkout') {
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
  if (sub === 'switch') {
    // Takes only branch names (never pathspecs) — safe unless forced.
    return rest.some((t) => /^(-C|--force-create|-f|--force|--discard-changes)$/.test(t));
  }
  if (sub === 'pull' || sub === 'merge') {
    // Only the two ratified grammars are silent. In particular,
    // `-m --ff-only` consumes the apparent marker as a message.
    const expectedLength = sub.startsWith('p') ? 1 : 2;
    return !(
      rest.length === expectedLength
      && rest[0] === '--ff-only'
      && (expectedLength === 1 || !rest[1]?.startsWith('-'))
    );
  }
  if (sub === 'worktree') {
    // `worktree list` reads; add/remove/prune/move/lock mutate the tree.
    return !/^list$/.test(rest[0] ?? '');
  }
  if (sub === 'apply') {
    // Only the ratified `--check [patch]` grammar is silent. Other options
    // may consume a marker-looking token or turn a reporting mode into apply.
    return !(
      rest[0] === '--check'
      && rest.length <= 2
      && (rest.length === 1 || !rest[1]?.startsWith('-'))
    );
  }
  if (sub === 'restore') {
    // Only the ratified index-only form is silent. A preceding option can
    // consume `--staged`, and any additional option needs explicit review.
    return !(
      rest.length === 2
      && rest[0] === '--staged'
      && !rest[1]?.startsWith('-')
    );
  }

  // Everything else (push, rebase, reset, clean, bisect, cherry-pick,
  // revert, gc, rm, filter-branch/filter-repo, …) requires confirmation.
  return true;
}

export function checkGit(cmd: string): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const parsed = extractGitSubcommandFromTokens(tokens);
    if (!parsed) continue;
    if (parsed.forceConfirm || gitSubcommandNeedsConfirm(parsed.sub, parsed.rest)) {
      return {
        verdict: 'confirm',
        ruleId: 'git-protected',
        reason:
          `git ${parsed.sub} can rewrite history, mutate a remote, or discard work — confirm before running`,
        target: cmd,
      };
    }
  }
  return null;
}

// Additive, log-only classification: identifies a git command allowed
// because a NAMED conditional rule decided it (e.g. `pull --ff-only`'s
// ratified grammar), as opposed to an unconditional SAFE_GIT_SUBCOMMANDS
// membership where no rule "fired" in any interesting sense. Never affects
// the permission decision — checkGit already returned null (allow) before a
// caller has any reason to call this. Exists purely so the adapter's audit
// log can record which conditional rules "silently earn their keep" and
// which never fire (spec User Story 10), without checkGit itself growing a
// third return shape that every existing caller and fixture would have to
// account for.
export function classifyGitAllow(cmd: string): Verdict | null {
  for (const tokens of tokenizeShellSegments(cmd)) {
    const parsed = extractGitSubcommandFromTokens(tokens);
    if (!parsed || parsed.forceConfirm) continue;
    if (gitSubcommandNeedsConfirm(parsed.sub, parsed.rest)) continue;
    if (SAFE_GIT_SUBCOMMANDS.has(parsed.sub)) continue;
    return {
      verdict: 'observe',
      ruleId: `git-conditional-${parsed.sub}`,
      reason: `git ${parsed.sub} matched its conditional allow grammar (safe form) — logged for audit`,
      target: cmd,
    };
  }
  return null;
}

export function checkBash(cmd: string): Verdict | null {
  if (!cmd) return null;

  // Special-cased: rm -rf needs allowlist logic before generic regex.
  const rmHit = checkRmRf(cmd);
  if (rmHit) return rmHit;

  const privilegeHit = checkPrivilegeEscalation(cmd);
  if (privilegeHit) return privilegeHit;

  // Hard-block rules take priority over the git "confirm" guard.
  for (const rule of BASH_RULES) {
    if (rule.regex.test(cmd)) {
      return { verdict: 'block', ruleId: rule.ruleId, reason: rule.reason, target: cmd };
    }
  }

  // Protected git operations → interactive prompt ("confirm").
  return checkGit(cmd);
}
