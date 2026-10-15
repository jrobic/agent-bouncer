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
// four declarative forms — ask_flags, safe_first_arg, safe_grammar,
// safe_flags — can express as data.
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
//   • Here-string: `bash <<< "rm -rf /"` (a `<<` heredoc keeps its
//     newline-delimited body segments)
//   • Download-then-exec split: `curl x>/tmp/s.sh && bash /tmp/s.sh`
//   • Native interpreters: `python -c "open('/etc/passwd').read()"`,
//     same for node, ruby, perl, etc.
//   • Renamed fork-bomb: `f(){f|f&};f` (signature-only match)
//   • Exported variable: `export GIT_EXTERNAL_DIFF=x && git diff` — the
//     `git-config-exec` rule reads only the assignments written in front of
//     the git command itself
//   • A command whose start the shared list does not know: a `case`
//     pattern, `bash -c "$cmd"`, `ssh`/`limactl shell`/`docker exec`,
//     `parallel` — docs/reference/policy.md § What counts as the start of a
//     command lists them all
//
// Treat this as protection against accidental destruction and the most
// obvious exfiltration patterns — not against an adversarial caller.

import { BASELINE } from './policy/baseline.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { CompiledRule } from './policy/match.ts';
import type {
  AskFlagsRule,
  CommandGitPolicy,
  CommandPolicy,
  SafeFirstArgRule,
  SafeFlagsRule,
  SafeGrammarRule,
  SafeGrammarToken,
} from './policy/schema.ts';
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

// The first dangerous target of one `rm` command's text, from `rm` on, when
// the command is recursive and forced.
function dangerousRmTarget(segment: string, dangerousTargets: readonly RegExp[]): string | null {
  if (!hasRmRf(segment)) return null;
  const targets = segment.split(/\s+/).slice(1).filter((t) => t && !t.startsWith('-'));
  // Dangerous always wins; the RM_ALLOWED_TARGETS documented in
  // policy/command.toml is informative only and cannot override
  // system-path destruction (e.g. /etc/node_modules).
  return targets.find((target) => isDangerousRmTarget(target, dangerousTargets)) ?? null;
}

const RM_COMMAND: ReadonlySet<string> = new Set(['rm']);

function checkRmRfWith(cmd: string, line: CommandLine, dangerousTargets: readonly RegExp[]): Verdict | null {
  // Every `rm` word of the line, sliced at the next command separator,
  // wherever it stands; then every command that starts with rm, which
  // reaches a target with a closer or a quote glued to it in the line
  // (`(rm -rf /)`, `bash -c "rm -rf /"`).
  const texts: string[] = cmd.match(/\brm\b[^;|&\n]*/g) ?? [];
  for (const command of line.commands) {
    const index = namedCommandIndex(command, RM_COMMAND);
    if (index !== -1) texts.push(commandText(command, index));
  }
  for (const text of texts) {
    const target = dangerousRmTarget(text, dangerousTargets);
    if (target !== null) {
      return {
        verdict: 'block',
        ruleId: 'rm-rf-dangerous',
        reason: `rm -rf targeting a dangerous path: ${target}`,
        target: cmd,
      };
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
// verdicts, and none of the four declarative git-conditional forms model
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

const SHELL_INTERPRETER_COMMANDS: Readonly<Record<string, true>> = {
  bash: true,
  sh: true,
  zsh: true,
  dash: true,
  ksh: true,
  fish: true,
};

type PatternOptionKind = 'pattern' | 'pattern-file' | 'scanned';

type PatternArgumentPolicy = {
  readonly flags: ReadonlySet<string>;
  readonly optionsWithArg: ReadonlySet<string>;
  readonly patternOptions: ReadonlySet<string>;
  readonly patternFileOptions: ReadonlySet<string>;
  readonly positionalPattern?: true;
};

const GREP_PATTERN_ARGUMENT_POLICY: PatternArgumentPolicy = {
  flags: new Set([
    '-r',
    '-R',
    '-i',
    '-l',
    '-L',
    '-c',
    '-v',
    '-w',
    '-x',
    '-n',
    '-h',
    '-H',
    '-o',
    '-q',
    '-s',
    '-E',
    '-F',
    '-P',
    '-G',
    '-a',
    '-z',
    '-I',
    '-b',
    '-T',
    '-U',
    '--color',
    '--line-buffered',
    '--null',
  ]),
  optionsWithArg: new Set([
    '-e',
    '--regexp',
    '--expression',
    '-f',
    '--file',
    '-A',
    '-B',
    '-C',
    '-m',
    '-d',
    '-D',
    '--color',
    '--include',
    '--exclude',
    '--exclude-dir',
  ]),
  patternOptions: new Set(['-e', '--regexp', '--expression']),
  patternFileOptions: new Set(['-f', '--file']),
  positionalPattern: true,
};

const SEARCH_PATTERN_ARGUMENT_POLICIES: Readonly<Record<string, PatternArgumentPolicy>> = {
  grep: GREP_PATTERN_ARGUMENT_POLICY,
  egrep: GREP_PATTERN_ARGUMENT_POLICY,
  fgrep: GREP_PATTERN_ARGUMENT_POLICY,
  rg: {
    flags: new Set([
      '-i',
      '-S',
      '-s',
      '-F',
      '-P',
      '-U',
      '-z',
      '-a',
      '-v',
      '-w',
      '-x',
      '-l',
      '-L',
      '-c',
      '-o',
      '-q',
      '-H',
      '-N',
      '-I',
      '-n',
      '--hidden',
      '--no-ignore',
      '--files-with-matches',
      '--count',
      '--no-heading',
      '--heading',
      '--line-number',
      '--no-line-number',
      '--json',
      '--trim',
      '--multiline',
      '--pcre2',
      '--fixed-strings',
      '--smart-case',
      '--case-sensitive',
      '--ignore-case',
      '--files',
      '--text',
      '--binary',
      '--no-messages',
      '--quiet',
      '--word-regexp',
      '--line-regexp',
      '--unrestricted',
      '--no-ignore-vcs',
      '--no-ignore-dot',
      '--one-file-system',
      '--crlf',
      '--null-data',
      '--passthru',
      '--no-config',
    ]),
    optionsWithArg: new Set([
      '-e',
      '--regexp',
      '-f',
      '--file',
      '-g',
      '--glob',
      '--iglob',
      '--pre',
      '-t',
      '--type',
      '-T',
      '--type-not',
      '-A',
      '-B',
      '-C',
      '-m',
      '-j',
      '-M',
      '-E',
      '-r',
      '--replace',
      '--max-depth',
      '--color',
      '--sort',
      '--sortr',
      '--context-separator',
      '--field-context-separator',
      '--engine',
      '--path-separator',
      '--threads',
      '--glob-case-insensitive',
      '--encoding',
    ]),
    patternOptions: new Set(['-e', '--regexp']),
    patternFileOptions: new Set(['-f', '--file']),
    positionalPattern: true,
  },
  ag: {
    flags: new Set(['-i', '-n', '-r', '-R', '-l', '-c', '-v', '-w', '-x', '-o', '-q', '-s', '-a', '-z', '-H', '-h']),
    optionsWithArg: new Set(['-e', '--regexp', '--expression', '-G', '--file-search-regex', '-m', '--max-count', '--depth']),
    patternOptions: new Set(['-e', '--regexp', '--expression']),
    patternFileOptions: new Set(),
    positionalPattern: true,
  },
  ack: {
    flags: new Set(['-i', '-n', '-r', '-R', '-l', '-c', '-v', '-w', '-x', '-o', '-q', '-s', '-a', '-H', '-h']),
    optionsWithArg: new Set(['-e', '--regexp', '--expression', '-g', '--files-from', '--ignore-file', '--type', '--type-set']),
    patternOptions: new Set(['-e', '--regexp', '--expression']),
    patternFileOptions: new Set(),
    positionalPattern: true,
  },
  sed: {
    flags: new Set(['-n', '--quiet', '--silent', '--posix', '--sandbox', '--debug']),
    optionsWithArg: new Set(['-e', '--expression', '-f', '--file']),
    patternOptions: new Set(['-e', '--expression']),
    patternFileOptions: new Set(['-f', '--file']),
    positionalPattern: true,
  },
  awk: {
    flags: new Set(['--posix', '--traditional', '--lint', '--re-interval', '--non-decimal-data']),
    optionsWithArg: new Set(['-f', '--file', '-v', '--assign', '-F', '--field-separator']),
    patternOptions: new Set(),
    patternFileOptions: new Set(['-f', '--file']),
    positionalPattern: true,
  },
  gawk: {
    flags: new Set(['--posix', '--traditional', '--lint', '--re-interval', '--non-decimal-data']),
    optionsWithArg: new Set(['-f', '--file', '-v', '--assign', '-F', '--field-separator']),
    patternOptions: new Set(),
    patternFileOptions: new Set(['-f', '--file']),
    positionalPattern: true,
  },
  perl: {
    flags: new Set(['-n', '-p', '-c', '-w', '-W']),
    optionsWithArg: new Set(['-e']),
    patternOptions: new Set(['-e']),
    patternFileOptions: new Set(),
  },
};

function excludedSearchPatternTokens(
  tokens: readonly ShellToken[],
  policy: PatternArgumentPolicy,
): ShellToken[] | null {
  const excluded: ShellToken[] = [];
  let hasPattern = policy.positionalPattern !== true;
  let optionsEnded = false;

  for (let i = 0; i < tokens.length;) {
    const token = tokens[i]!;
    const value = token.value;
    if (!optionsEnded && value === '--') {
      optionsEnded = true;
      i++;
      continue;
    }

    if (!optionsEnded && value.startsWith('-') && value !== '-') {
      let option: string | undefined;
      let argument: ShellToken | undefined;
      let nextIndex = i + 1;

      if (value.startsWith('--')) {
        const equalsIndex = value.indexOf('=');
        option = equalsIndex === -1 ? value : value.slice(0, equalsIndex);
        if (equalsIndex === -1 && policy.flags.has(option)) {
          i++;
          continue;
        }
        if (!policy.optionsWithArg.has(option)) return null;
        argument = equalsIndex === -1 ? tokens[i + 1] : token;
        nextIndex = equalsIndex === -1 ? i + 2 : i + 1;
      } else {
        for (let shortIndex = 1; shortIndex < value.length; shortIndex++) {
          const shortOption = `-${value[shortIndex]!}`;
          if (policy.flags.has(shortOption)) continue;
          if (!policy.optionsWithArg.has(shortOption)) return null;
          option = shortOption;
          argument = shortIndex === value.length - 1 ? tokens[i + 1] : token;
          nextIndex = shortIndex === value.length - 1 ? i + 2 : i + 1;
          break;
        }
        if (option === undefined) {
          i++;
          continue;
        }
      }

      if (argument === undefined) return null;
      const kind: PatternOptionKind = policy.patternOptions.has(option)
        ? 'pattern'
        : policy.patternFileOptions.has(option)
        ? 'pattern-file'
        : 'scanned';
      if (kind === 'pattern') excluded.push(argument);
      if (kind !== 'scanned') hasPattern = true;
      i = nextIndex;
      continue;
    }

    if (!hasPattern) {
      excluded.push(token);
      hasPattern = true;
    }
    i++;
  }

  return excluded;
}

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
  '--config-env',
]);

// A `NAME=value` or `NAME+=value` word in front of a command: an environment
// assignment. bash passes the appended form to the command as well; its name
// keeps the `+`, so it matches no allow-list entry.
const ENV_ASSIGNMENT = /^\w+\+?=/;

const GIT_SHA = /^[0-9a-f]{7,64}$/i;

// Canonical structural tokenizer for the git and privilege guards. Quotes
// and escapes preserve the resulting literal token value, while their
// contents never gain separator/comment/operator syntax. An unquoted `#`
// starts a comment only at a shell word boundary. A recognized `<<` heredoc
// records its body source range and its body lines remain ordinary,
// newline-delimited segments; only the secret path scan consults those
// ranges. `hasQuotedWhitespace` distinguishes prose candidates from
// quoted single-word paths.
type SourceRange = Readonly<{
  start: number;
  end: number;
}>;

type ShellRedirection = Readonly<{
  target: string | null;
  consumesFollowingToken: boolean;
  output: boolean;
}>;

type ShellRedirections = Readonly<{
  arguments: readonly string[];
  redirections: readonly ShellRedirection[];
  ambiguous?: true;
}>;

export type ShellToken =
  & SourceRange
  & Readonly<{
    value: string;
    pathCandidates?: readonly string[];
    braceExpansionExceeded?: true;
    kind: 'word' | 'bang-operator';
    hasLiteralizingSyntax: boolean;
    hasQuotedWhitespace: boolean;
    hasUnterminatedQuote: boolean;
    commandSubstitutions?: readonly SourceRange[];
    redirections?: ShellRedirections;
  }>;

type CommandPrefix = Readonly<{
  index: number;
  ambiguous: boolean;
}>;

type TokenizedShell = Readonly<{
  segments: readonly ShellToken[][];
  heredocBodies: readonly SourceRange[];
  hasUnquotedShellOperator: boolean;
}>;

export type ShellTokenizeOptions = Readonly<{
  pathCandidates?: true;
}>;

type HeredocDelimiter = Readonly<{
  value: string;
  stripTabs: boolean;
}>;

function namesPath(value: string): boolean {
  return value.includes('/') || value.startsWith('~');
}

type RedirectionSyntax = Readonly<{
  start: number;
  end: number;
  output: boolean;
  descriptor: boolean;
  kind: 'regular' | 'heredoc' | 'process-substitution';
}>;

type RedirectionSearch = Readonly<{
  syntax: RedirectionSyntax;
  substitutionIndex: number;
}>;

function unquotedRedirectionSyntax(
  source: string,
  start: number,
  tokenStart: number,
  substitutions: readonly SourceRange[] | undefined,
  substitutionIndex: number,
): RedirectionSearch | null {
  let quote: '"' | '\'' | null = null;

  for (let index = start; index < source.length; index++) {
    while (
      substitutions?.[substitutionIndex] !== undefined
      && substitutions[substitutionIndex]!.end <= tokenStart + index
    ) substitutionIndex++;
    const substitution = substitutions?.[substitutionIndex];
    if (substitution?.start === tokenStart + index) {
      index = substitution.end - tokenStart - 1;
      substitutionIndex++;
      continue;
    }

    const character = source[index]!;
    if (quote !== null) {
      if (character === '\\' && quote === '"') {
        const escaped = source[index + 1];
        if (escaped !== undefined && /[$`"\\\n]/.test(escaped)) index++;
        continue;
      }
      if (character === quote) quote = null;
      continue;
    }
    if (character === '\\') {
      if (source[index + 1] !== undefined) index++;
      continue;
    }
    if (character === '"' || character === '\'') {
      quote = character;
      continue;
    }

    if (character === '&' && source[index + 1] === '>') {
      return {
        syntax: {
          start: index,
          end: source[index + 2] === '>' ? index + 3 : index + 2,
          output: true,
          descriptor: false,
          kind: 'regular',
        },
        substitutionIndex,
      };
    }
    if (character !== '<' && character !== '>') continue;

    const redirectionStart = /^\d+$/.test(source.slice(0, index)) ? 0 : index;
    if (character === '<' && source[index + 1] === '(') {
      return {
        syntax: { start: redirectionStart, end: index + 2, output: false, descriptor: false, kind: 'process-substitution' },
        substitutionIndex,
      };
    }
    if (character === '<' && source[index + 1] === '<') {
      const end = source[index + 2] === '<' || source[index + 2] === '-' ? index + 3 : index + 2;
      return {
        syntax: { start: redirectionStart, end, output: false, descriptor: false, kind: 'heredoc' },
        substitutionIndex,
      };
    }

    let end = index + 1;
    if (character === '>' && source[end] === '>') end++;
    if (character === '>' && source[end] === '|') end++;
    const descriptor = source[end] === '&';
    if (descriptor) end++;
    return {
      syntax: { start: redirectionStart, end, output: character === '>', descriptor, kind: 'regular' },
      substitutionIndex,
    };
  }

  return null;
}

function shellWordValue(source: string): string | null {
  const tokenized = tokenizeShellSegments(source);
  if (
    tokenized.hasUnquotedShellOperator
    || tokenized.segments.length !== 1
    || tokenized.segments[0]?.length !== 1
  ) return null;
  return tokenized.segments[0]![0]!.value;
}

function shellRedirections(
  source: string,
  tokenStart: number,
  substitutions: readonly SourceRange[] | undefined,
): ShellRedirections | null {
  let cursor = 0;
  let substitutionIndex = 0;
  let current = unquotedRedirectionSyntax(source, cursor, tokenStart, substitutions, substitutionIndex);
  if (current === null) return null;
  const parsedArguments: string[] = [];
  const redirections: ShellRedirection[] = [];

  for (;;) {
    const { syntax } = current;
    substitutionIndex = current.substitutionIndex;
    const precedingSource = source.slice(cursor, syntax.start);
    if (precedingSource) {
      const argument = shellWordValue(precedingSource);
      if (argument === null) return { arguments: parsedArguments, redirections, ambiguous: true };
      parsedArguments.push(argument);
    }
    if (syntax.kind === 'process-substitution') {
      return { arguments: parsedArguments, redirections, ambiguous: true };
    }

    const next = unquotedRedirectionSyntax(source, syntax.end, tokenStart, substitutions, substitutionIndex);
    const targetSource = source.slice(syntax.end, next?.syntax.start ?? source.length);
    if (syntax.kind === 'heredoc') {
      redirections.push({
        target: null,
        consumesFollowingToken: targetSource.length === 0,
        output: false,
      });
    } else if (!targetSource) {
      if (next !== null) return { arguments: parsedArguments, redirections, ambiguous: true };
      redirections.push({ target: null, consumesFollowingToken: true, output: syntax.output });
    } else {
      const target = shellWordValue(targetSource);
      if (target === null) return { arguments: parsedArguments, redirections, ambiguous: true };
      redirections.push({
        target: syntax.descriptor && /^(?:\d+|-)$/.test(target) ? null : target,
        consumesFollowingToken: false,
        output: syntax.output,
      });
    }

    if (next === null) return { arguments: parsedArguments, redirections };
    cursor = next.syntax.start;
    current = next;
  }
}

function heredocDelimiters(cmd: string, tokens: readonly ShellToken[]): readonly HeredocDelimiter[] | null {
  const delimiters: HeredocDelimiter[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!;
    const source = cmd.slice(token.start, token.end);
    if (!source.startsWith('<<') || source.startsWith('<<<')) continue;

    const stripTabs = source.startsWith('<<-');
    let delimiter = token.value.slice(stripTabs ? 3 : 2);
    if (!delimiter) {
      const next = tokens[i + 1];
      if (next === undefined) return null;
      delimiter = next.value;
      i++;
    }
    delimiters.push({ value: delimiter, stripTabs });
  }
  return delimiters;
}

function consumeHeredocBodies(
  cmd: string,
  start: number,
  delimiters: readonly HeredocDelimiter[],
): readonly SourceRange[] | null {
  const bodies: SourceRange[] = [];
  let cursor = start;

  for (const { value, stripTabs } of delimiters) {
    const bodyStart = cursor;
    for (;;) {
      const lineEnd = cmd.indexOf('\n', cursor);
      const line = cmd.slice(cursor, lineEnd === -1 ? cmd.length : lineEnd);
      const candidate = stripTabs ? line.replace(/^\t+/, '') : line;
      if (candidate === value) {
        bodies.push({ start: bodyStart, end: cursor });
        cursor = lineEnd === -1 ? cmd.length : lineEnd + 1;
        break;
      }
      if (lineEnd === -1) return null;
      cursor = lineEnd + 1;
    }
  }

  return bodies;
}

function nonPathTokenRanges(
  cmd: string,
  ranges: readonly SourceRange[],
  pathToken: RegExp,
): readonly SourceRange[] {
  const nonPathTokens: SourceRange[] = [];
  for (const range of ranges) {
    const source = cmd.slice(range.start, range.end);
    for (const match of source.matchAll(pathToken)) {
      const value = match[0];
      if (namesPath(value)) continue;
      const start = range.start + match.index!;
      nonPathTokens.push({ start, end: start + value.length });
    }
  }
  return nonPathTokens;
}

function isInsideHeredocBody(position: number, bodies: readonly SourceRange[]): boolean {
  return bodies.some((body) => body.start <= position && position < body.end);
}

const MAX_BRACE_ALTERNATIVES = 64;

type PathCandidateExpansion = Readonly<{
  candidates: readonly string[];
  braceExpansionExceeded?: true;
}>;

type ShellExpansionFragment = Readonly<{
  value: string;
  environment: boolean;
  brace: boolean;
}>;

function expandEnvironmentFragment(
  fragment: ShellExpansionFragment,
  witnesses: ReadonlyMap<string, string> | undefined,
): string {
  if (!fragment.environment || witnesses === undefined) return fragment.value;
  return fragment.value.replace(/\$\{([A-Z][A-Z0-9_]*)\}|\$([A-Z][A-Z0-9_]*)/g, (match, braced, bare) => {
    const witness = witnesses.get(braced ?? bare);
    return witness ?? match;
  });
}

// Expands only policy-declared environment variables and one non-nested,
// comma-separated brace expression. A path whose expansion exceeds the cap
// deliberately exposes no candidates: the protected-write caller confirms it
// rather than scanning an unbounded synthetic path set.
function expandPathTokenCandidates(
  fragments: readonly ShellExpansionFragment[],
  witnesses: ReadonlyMap<string, string> | undefined,
): PathCandidateExpansion {
  let candidates = [''];
  let expandedBrace = false;

  for (const fragment of fragments) {
    const value = expandEnvironmentFragment(fragment, witnesses);
    const brace = !expandedBrace && fragment.brace
      ? value.match(/^([^{}]*)\{([^{}]+)\}([^{}]*)$/)
      : null;
    if (brace === null || !brace[2]!.includes(',')) {
      candidates = candidates.map((candidate) => `${candidate}${value}`);
      continue;
    }
    const alternatives = brace[2]!.split(',');
    if (alternatives.some((alternative) => alternative.length === 0)) {
      candidates = candidates.map((candidate) => `${candidate}${value}`);
      continue;
    }
    if (candidates.length * alternatives.length > MAX_BRACE_ALTERNATIVES) {
      return { candidates: [], braceExpansionExceeded: true };
    }
    candidates = candidates.flatMap((candidate) => alternatives.map((alternative) => `${candidate}${brace[1]!}${alternative}${brace[3]!}`));
    expandedBrace = true;
  }

  return { candidates };
}

export function expandedPathTokenCandidates(
  value: string,
  witnesses?: ReadonlyMap<string, string>,
): readonly string[] {
  return expandPathTokenCandidates([{ value, environment: true, brace: true }], witnesses).candidates;
}

// The optional witnesses are policy data, never the process environment.
// This keeps tokenization deterministic while allowing protected-write to
// recognize a harness's declared configuration directory.
export function tokenizeShellSegments(
  cmd: string,
  witnesses?: ReadonlyMap<string, string>,
  options?: ShellTokenizeOptions,
): TokenizedShell {
  const segments: ShellToken[][] = [];
  const heredocBodies: SourceRange[] = [];
  let hasUnquotedShellOperator = false;
  const scan = (start: number, rangeEnd: number): void => {
    let tokens: ShellToken[] = [];
    let token = '';
    let tokenStart = 0;
    let tokenStarted = false;
    let tokenHasLiteralizingSyntax = false;
    let tokenHasQuotedWhitespace = false;
    let tokenCommandSubstitutions: SourceRange[] | undefined;
    let unquotedRedirectionOperator: '<' | '>' | null = null;
    let fragments: ShellExpansionFragment[] = [];
    let fragment = '';
    let fragmentEnvironment = true;
    let fragmentBrace = true;
    let quote: '"' | '\'' | null = null;
    let comment = false;

    const flushFragment = (): void => {
      if (!fragment) return;
      fragments.push({ value: fragment, environment: fragmentEnvironment, brace: fragmentBrace });
      fragment = '';
    };
    const append = (value: string, unquoted = false): void => {
      token += value;
      fragment += value;
      unquotedRedirectionOperator = unquoted && (value === '<' || value === '>') ? value : null;
    };
    const appendLiteral = (value: string): void => {
      flushFragment();
      token += value;
      fragments.push({ value, environment: false, brace: false });
      unquotedRedirectionOperator = null;
    };
    const setFragmentSyntax = (environment: boolean, brace: boolean): void => {
      flushFragment();
      fragmentEnvironment = environment;
      fragmentBrace = brace;
      unquotedRedirectionOperator = null;
    };

    const flushToken = (end: number): void => {
      if (!tokenStarted) return;
      flushFragment();
      const expansion = options?.pathCandidates === true && (token.includes('$') || token.includes('{'))
        ? expandPathTokenCandidates(fragments, witnesses)
        : undefined;
      const candidates = expansion?.candidates;
      const redirections = token.includes('>') || token.includes('<')
        ? shellRedirections(cmd.slice(tokenStart, end), tokenStart, tokenCommandSubstitutions)
        : null;
      tokens.push({
        value: token,
        kind: token === '!' && !tokenHasLiteralizingSyntax ? 'bang-operator' : 'word',
        start: tokenStart,
        end,
        hasLiteralizingSyntax: tokenHasLiteralizingSyntax,
        hasQuotedWhitespace: tokenHasQuotedWhitespace,
        hasUnterminatedQuote: quote !== null,
        ...(tokenCommandSubstitutions === undefined ? {} : { commandSubstitutions: tokenCommandSubstitutions }),
        ...(redirections === null ? {} : { redirections }),
        ...(candidates === undefined || (candidates.length === 1 && candidates[0] === token)
          ? {}
          : { pathCandidates: candidates }),
        ...(expansion?.braceExpansionExceeded === true ? { braceExpansionExceeded: true } : {}),
      });
      token = '';
      tokenStart = 0;
      tokenStarted = false;
      tokenHasLiteralizingSyntax = false;
      tokenHasQuotedWhitespace = false;
      tokenCommandSubstitutions = undefined;
      fragments = [];
      fragment = '';
      fragmentEnvironment = true;
      fragmentBrace = true;
      unquotedRedirectionOperator = null;
    };
    const flushSegment = (end: number): ShellToken[] => {
      flushToken(end);
      const segment = tokens;
      if (segment.length > 0) segments.push(segment);
      tokens = [];
      return segment;
    };
    const finishLine = (end: number): void => {
      const segment = flushSegment(end);
      if (isInsideHeredocBody(end, heredocBodies)) return;

      const delimiters = heredocDelimiters(cmd, segment);
      if (delimiters === null || delimiters.length === 0) return;
      const bodies = consumeHeredocBodies(cmd, end + 1, delimiters);
      if (bodies !== null) heredocBodies.push(...bodies);
    };

    for (let i = start; i < rangeEnd; i++) {
      const ch = cmd[i]!;
      if (comment) {
        if (ch === '\n') {
          comment = false;
          finishLine(i);
        }
        continue;
      }

      if (quote !== '\'' && ch === '$' && cmd[i + 1] === '(' && cmd[i + 2] !== '(') {
        const substitutionEnd = commandSubstitutionEnd(cmd, i + 2);
        if (substitutionEnd !== null && substitutionEnd < rangeEnd) {
          hasUnquotedShellOperator = true;
          if (!tokenStarted) tokenStart = i;
          tokenStarted = true;
          tokenCommandSubstitutions ??= [];
          tokenCommandSubstitutions.push({ start: i, end: substitutionEnd + 1 });
          scan(i + 2, substitutionEnd);
          appendLiteral(cmd.slice(i, substitutionEnd + 1));
          i = substitutionEnd;
          continue;
        }
      }

      if (quote !== null) {
        if (ch === '\\' && quote === '"') {
          const escaped = cmd[i + 1];
          if (escaped !== undefined && /[$`"\\\n]/.test(escaped)) {
            if (escaped !== '\n') appendLiteral(escaped);
            i++;
          } else {
            append('\\');
          }
          continue;
        }
        if (ch === quote) {
          setFragmentSyntax(true, true);
          quote = null;
          continue;
        }
        if (/\s/.test(ch)) tokenHasQuotedWhitespace = true;
        append(ch);
        continue;
      }

      if (ch === '\\') {
        const escaped = cmd[i + 1];
        if (escaped === '\n') {
          i++;
          continue;
        }
        if (!tokenStarted) tokenStart = i;
        tokenStarted = true;
        tokenHasLiteralizingSyntax = true;
        if (escaped === undefined) appendLiteral('\\');
        else {
          appendLiteral(escaped);
          i++;
        }
        continue;
      }
      if (ch === '"' || ch === '\'') {
        setFragmentSyntax(ch === '"', false);
        quote = ch;
        if (!tokenStarted) tokenStart = i;
        tokenStarted = true;
        tokenHasLiteralizingSyntax = true;
        continue;
      }
      if (';&|<>(){}'.includes(ch) || ch === '`') hasUnquotedShellOperator = true;
      if (ch === '#' && !tokenStarted) {
        comment = true;
        continue;
      }
      if (/\s/.test(ch) && ch !== '\n') {
        flushToken(i);
        continue;
      }
      const descriptorDuplication = ch === '&' && unquotedRedirectionOperator !== null;
      const combinedOutputRedirection = ch === '&' && cmd[i + 1] === '>';
      if (
        ch === ';'
        || (ch === '&' && !descriptorDuplication && !combinedOutputRedirection)
        || (ch === '|' && unquotedRedirectionOperator !== '>')
      ) {
        flushSegment(i);
        continue;
      }
      if (ch === '\n') {
        finishLine(i);
        continue;
      }
      if (!tokenStarted) tokenStart = i;
      tokenStarted = true;
      append(ch, true);
    }
    flushSegment(rangeEnd);
  };
  scan(0, cmd.length);
  return { segments, heredocBodies, hasUnquotedShellOperator };
}

// Tokenizer body moved above so the optional policy witnesses can enrich
// path-bearing tokens without changing structural command parsing.

const PROSE_COMMANDS: Readonly<Record<string, true>> = {
  echo: true,
  printf: true,
};

function normalizedTokens(tokens: readonly ShellToken[], start = 0): string {
  let normalized = '';
  for (let index = start; index < tokens.length; index++) {
    if (index > start) normalized += ' ';
    normalized += tokens[index]!.value;
  }
  return normalized;
}

function shellCommandSource(tokens: readonly ShellToken[], commandIndex: number): string | null {
  for (let index = commandIndex + 1; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (token.value === '--') return null;
    if (token.value === '-c' || token.value === '--command' || /^-[^-]*c[^-]*$/.test(token.value)) {
      return tokens[index + 1]?.value ?? '';
    }
  }
  return null;
}

function commandSubstitutionEnd(source: string, start: number): number | null {
  let depth = 1;
  let quote: '"' | '\'' | null = null;

  for (let index = start; index < source.length; index++) {
    const character = source[index]!;
    if (quote === '\'') {
      if (character === '\'') quote = null;
      continue;
    }
    if (character === '\\') {
      index++;
      continue;
    }
    if (quote === '"') {
      if (character === '"') quote = null;
      continue;
    }
    if (character === '"' || character === '\'') {
      quote = character;
      continue;
    }
    if (character === '(') {
      depth++;
      continue;
    }
    if (character === ')') {
      depth--;
      if (depth === 0) return index;
    }
  }

  return null;
}

function backtickSubstitutionEnd(source: string, start: number): number | null {
  for (let index = start; index < source.length; index++) {
    if (source[index] === '\\') {
      index++;
      continue;
    }
    if (source[index] === '`') return index;
  }
  return null;
}

function dockerSubstitutionCandidates(source: string): string[] {
  const candidates: string[] = [];
  let quote: '"' | '\'' | null = null;

  for (let index = 0; index < source.length; index++) {
    const character = source[index]!;
    if (quote === '\'') {
      if (character === '\'') quote = null;
      continue;
    }
    if (character === '\\') {
      index++;
      continue;
    }
    if (character === '"') {
      quote = quote === '"' ? null : '"';
      continue;
    }
    if (character === '\'') {
      if (quote !== '"') quote = '\'';
      continue;
    }

    const end = character === '$' && source[index + 1] === '('
      ? commandSubstitutionEnd(source, index + 2)
      : character === '`'
      ? backtickSubstitutionEnd(source, index + 1)
      : undefined;
    if (end === undefined) continue;
    if (end === null) {
      candidates.push(source.slice(index));
      return candidates;
    }

    const contentStart = character === '$' ? index + 2 : index + 1;
    candidates.push(...dockerDestructiveCandidates(source.slice(contentStart, end)));
    index = end;
  }

  return candidates;
}

function dockerSegmentCandidates(
  command: string,
  tokens: readonly ShellToken[],
  isolatedDisplay: boolean,
): string[] {
  const candidates: string[] = [];
  const prefix = consumeCommandPrefixes(tokens);
  if (prefix.ambiguous || tokens.some((token) => token.hasUnterminatedQuote)) {
    candidates.push(normalizedTokens(tokens));
    return candidates;
  }

  let commandIndex = prefix.index;
  const controlKeyword = tokens[commandIndex]?.value;
  if (
    controlKeyword === 'then'
    || controlKeyword === 'do'
    || controlKeyword === 'else'
    || controlKeyword === 'elif'
  ) commandIndex++;
  if (commandIndex >= tokens.length) return candidates;

  const commandName = tokens[commandIndex]!.value;
  const executableName = commandName.slice(commandName.lastIndexOf('/') + 1);
  if (executableName === 'docker' || executableName === 'docker-compose') {
    candidates.push(normalizedTokens(tokens, commandIndex));
    return candidates;
  }

  if (commandName === 'eval') {
    candidates.push(...dockerDestructiveCandidates(normalizedTokens(tokens, commandIndex + 1)));
    return candidates;
  }

  if (Object.hasOwn(SHELL_INTERPRETER_COMMANDS, executableName)) {
    const source = shellCommandSource(tokens, commandIndex);
    if (source === null) candidates.push(normalizedTokens(tokens, commandIndex));
    else candidates.push(...dockerDestructiveCandidates(source));
    return candidates;
  }

  if (commandName === 'cmux') {
    const sendIndex = tokens.findIndex((token, index) => index > commandIndex && token.value === 'send');
    if (sendIndex !== -1) {
      const first = tokens[commandIndex]!;
      const last = tokens[tokens.length - 1]!;
      candidates.push(command.slice(first.start, last.end));
      return candidates;
    }
  }

  if (Object.hasOwn(PROSE_COMMANDS, commandName) && isolatedDisplay) return candidates;
  candidates.push(normalizedTokens(tokens, commandIndex));
  return candidates;
}

function isIsolatedDisplay(tokenized: TokenizedShell): boolean {
  if (
    tokenized.segments.length !== 1
    || tokenized.heredocBodies.length !== 0
    || tokenized.hasUnquotedShellOperator
  ) return false;

  const tokens = tokenized.segments[0]!;
  const prefix = consumeCommandPrefixes(tokens);
  const commandName = tokens[prefix.index]?.value;
  return !prefix.ambiguous
    && commandName !== undefined
    && Object.hasOwn(PROSE_COMMANDS, commandName);
}

function dockerDestructiveCandidates(command: string): string[] {
  const candidates = dockerSubstitutionCandidates(command);
  const tokenized = tokenizeShellSegments(command);
  const isolatedDisplay = isIsolatedDisplay(tokenized);
  if (!isolatedDisplay) candidates.push(command);
  for (const tokens of tokenized.segments) {
    candidates.push(...dockerSegmentCandidates(command, tokens, isolatedDisplay));
  }
  return candidates;
}

function dockerDestructiveMatches(rule: CompiledRule, command: string): boolean {
  return dockerDestructiveCandidates(command).some(
    (candidate) => rule.re.test(candidate) && !rule.exceptRe?.test(candidate),
  );
}

// Find the git subcommand in a single command segment, tolerating wrappers
// (`command git …`), env assignments (`GIT_SEQUENCE_EDITOR=… git …`), and global
// options (`git -C <path> …`). Returns null when the segment is not a git
// command (so `echo git push` is ignored — git is an argument, not the verb).
// `globals` holds the global options written before the subcommand, each with
// the value it took from the next token; `assignments` the `NAME=value` words
// written before `git`.
type GitGlobalOption = { option: string; value?: string; };
type GitCommand = { sub: string; rest: string[]; globals?: GitGlobalOption[]; assignments?: string[]; forceConfirm?: true; };

type RedirectionFilteredTokens = Readonly<{
  tokens: readonly ShellToken[];
  forceConfirm: boolean;
}>;

function withoutShellRedirections(tokens: readonly ShellToken[]): RedirectionFilteredTokens {
  let filtered: ShellToken[] | undefined;
  let forceConfirm = false;

  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    const redirections = token.redirections;
    if (redirections === undefined) {
      filtered?.push(token);
      continue;
    }

    filtered ??= tokens.slice(0, index);
    if (redirections.ambiguous) {
      forceConfirm = true;
      continue;
    }
    for (const argument of redirections.arguments) {
      filtered.push({ ...token, value: argument });
    }
    if (redirections.redirections.some((redirection) => redirection.consumesFollowingToken)) {
      index++;
      if (index >= tokens.length || tokens[index]!.redirections !== undefined) forceConfirm = true;
    }
  }

  return { tokens: filtered ?? tokens, forceConfirm };
}

export function extractGitSubcommand(segment: string): GitCommand | null {
  const tokens = tokenizeShellSegments(segment).segments[0] ?? [];
  return extractGitSubcommandFromTokens(tokens);
}

// The `NAME=value` words among the first `end` tokens: what stands in front of
// the command once the wrappers are consumed.
function assignmentsBefore(tokens: readonly ShellToken[], end: number): string[] {
  const assignments: string[] = [];
  for (let index = 0; index < end; index++) {
    const value = tokens[index]!.value;
    if (ENV_ASSIGNMENT.test(value)) assignments.push(value);
  }
  return assignments;
}

export function extractGitSubcommandFromTokens(
  tokens: readonly ShellToken[],
): GitCommand | null {
  const filtered = withoutShellRedirections(tokens);
  return gitCommandAt(filtered.tokens, consumeCommandPrefixes(filtered.tokens), filtered.forceConfirm);
}

// The git command whose words `tokens` are, once `prefix` has passed what
// stands before the command name; `forceConfirm` when a redirection among the
// words could not be read; `inherited`, the assignments written before the
// shell that runs it.
function gitCommandAt(
  tokens: readonly ShellToken[],
  prefix: CommandPrefix,
  forceConfirm: boolean,
  inherited: readonly string[] = [],
): GitCommand | null {
  let i = prefix.index;
  if (prefix.ambiguous) {
    i = tokens.findIndex((token, index) => index >= prefix.index && (token.value === 'git' || token.value.endsWith('/git')));
    if (i === -1) return null;
  }
  if (i >= tokens.length) return null;
  const head = tokens[i]!.value;
  if (head !== 'git' && !head.endsWith('/git')) return null;
  i++;
  const globals: GitGlobalOption[] = [];
  while (i < tokens.length && tokens[i]!.value.startsWith('-')) {
    const option = tokens[i]!.value;
    if (GIT_OPTS_WITH_ARG.has(option)) {
      const value = tokens[i + 1]?.value;
      globals.push(value === undefined ? { option } : { option, value });
      i += 2;
    } else {
      globals.push({ option });
      i++;
    }
  }
  if (i >= tokens.length) return null;
  const assignments = prefix.index > 0 ? [...inherited, ...assignmentsBefore(tokens, prefix.index)] : [...inherited];
  return {
    sub: tokens[i]!.value,
    rest: tokens.slice(i + 1).map((token) => token.value),
    ...(globals.length > 0 ? { globals } : {}),
    ...(assignments.length > 0 ? { assignments } : {}),
    ...(prefix.ambiguous || forceConfirm ? { forceConfirm: true as const } : {}),
  };
}

export function consumeCommandPrefixes(
  tokens: readonly ShellToken[],
  benignPrefixes: ReadonlySet<string> = GIT_BENIGN_PREFIXES,
): CommandPrefix {
  let i = 0;

  const consumeBangOperators = (): void => {
    while (tokens[i]?.kind === 'bang-operator') i++;
  };

  consumeBangOperators();
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === undefined) break;
    if (ENV_ASSIGNMENT.test(token.value)) {
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
      if (policy.acceptsAssignments && ENV_ASSIGNMENT.test(option.value)) {
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

// ─── Where a command starts ──────────────────────────────────────────────
// The one definition of the start of a command for git, privilege
// escalation and rm -rf: docs/reference/policy.md § What counts as the start
// of a command, pinned by the forms of tests/command-start-forms.ts. Those
// three families read each segment with consumeCommandPrefixes first, then
// each command this reading finds, and the first reading that asks answers:
// a command the segment reading asks for keeps that rule and reason. The
// path scans (protected-write, secret masking, docker) read with
// consumeCommandPrefixes alone.

// The argument of a shell's `-c`, of `eval`, of `env -S`, and the words
// `watch` runs with `sh -c` are read again as a command line: down to this
// many levels below the line. A substitution body is read at the depth of
// its line, as the tokenizer reads `$( … )`.
const MAX_NESTED_READS = 3;

// Words that come before a command without being one: shell keywords and
// groupings (`!` is the tokenizer's bang operator). A Set, as an object with
// a `then` key would be thenable.
const COMMAND_START_HEADS: ReadonlySet<string> = new Set([
  '!',
  '(',
  '()',
  '{',
  'if',
  'then',
  'elif',
  'else',
  'while',
  'until',
  'do',
]);

// `name()` or `name(){`: the head of a function definition, whose body
// starts a command.
const FUNCTION_DEFINITION = /^[\w.:-]+\(\)\{?$/;

export type CommandStartWrapper = Readonly<{
  // Options that take no value: `-0`, `--null`.
  flags: ReadonlySet<string>;
  // Options that take a value: the next word, the rest of a group of short
  // options (`-n1`), or `=value` after a long one.
  optionsWithArg: ReadonlySet<string>;
  // Long options whose value, when there is one, is written `--name=value`.
  optionalArg?: ReadonlySet<string>;
  // Words read after the options and before the command: timeout's duration.
  operands?: number;
  acceptsAssignments?: true;
  // Options whose value is a command line: `env -S`.
  commandLineOptions?: ReadonlySet<string>;
  // The operands are run by `sh -c` unless one of these options is given.
  shellOperandsUnless?: ReadonlySet<string>;
}>;

// Tokenizer grammar like WRAPPER_OPTION_POLICIES, from which the prefixes
// come with their options (`proxy` is read only after `rtk`), `env` gaining
// `-S`; then the wrappers, each with the shape of its arguments. `--` ends
// the options of every one. An option not listed makes the start ambiguous:
// each family then looks for its command name among the words that follow,
// as with consumeCommandPrefixes.
export const COMMAND_START_WRAPPERS: Readonly<Record<string, CommandStartWrapper>> = {
  ...Object.fromEntries(Object.entries(WRAPPER_OPTION_POLICIES).filter(([name]) => name !== 'proxy')),
  env: {
    ...WRAPPER_OPTION_POLICIES.env!,
    optionsWithArg: new Set([...WRAPPER_OPTION_POLICIES.env!.optionsWithArg, '-S']),
    commandLineOptions: new Set(['-S']),
  },
  timeout: {
    flags: new Set(['--foreground', '--preserve-status']),
    optionsWithArg: new Set(['-k', '--kill-after', '-s', '--signal']),
    operands: 1,
  },
  xargs: {
    flags: new Set(['-0', '--null', '-r', '--no-run-if-empty', '-t', '--verbose']),
    optionsWithArg: new Set(['-n', '--max-args', '-I', '-P', '--max-procs', '-L', '-d', '--delimiter', '-E', '-s', '--max-chars']),
    optionalArg: new Set(['--replace', '--max-lines', '--eof']),
  },
  nohup: { flags: new Set(), optionsWithArg: new Set() },
  watch: {
    flags: new Set(['-d', '-t', '--no-title', '-x', '--exec', '-c', '--color', '-g', '--chgexit', '-e', '--errexit', '-p', '--precise']),
    optionsWithArg: new Set(['-n', '--interval']),
    optionalArg: new Set(['--differences']),
    shellOperandsUnless: new Set(['-x', '--exec']),
  },
};

// The shells that read the argument of `-c` as a command line, also when
// started by a path (`/bin/bash`).
const COMMAND_LINE_SHELLS: Readonly<Record<string, true>> = { bash: true, sh: true, zsh: true, dash: true };
const SHELL_OPTIONS_WITH_ARG: Readonly<Record<string, true>> = {
  '-o': true,
  '+o': true,
  '-O': true,
  '+O': true,
  '--rcfile': true,
  '--init-file': true,
};

// Where a command's name stands among its words, past the prefixes and
// wrappers; or, when the words hand a command line to a shell (`bash -c`,
// `eval`, `watch`, `env -S`), that line and the assignments written before
// it, which every command of the line inherits: the words then have no
// command name of their own.
type CommandStart =
  | CommandPrefix & Readonly<{ kind: 'name'; }>
  | Readonly<{ kind: 'line'; line: string; assignments: readonly string[]; }>;

function consumeCommandStart(tokens: readonly ShellToken[], source: string): CommandStart {
  let i = 0;
  while (i < tokens.length) {
    const word = tokens[i]!.value;
    if (ENV_ASSIGNMENT.test(word)) {
      i++;
      continue;
    }
    // A prefix or a wrapper may be started by a path: `/usr/bin/env`.
    const wrapper = word.slice(word.lastIndexOf('/') + 1);
    if (!Object.hasOwn(COMMAND_START_WRAPPERS, wrapper)) break;
    i++;
    if (wrapper === 'rtk' && tokens[i]?.value === 'proxy') i++;
    const options = consumeWrapperOptions(tokens, i, COMMAND_START_WRAPPERS[wrapper]!, source);
    if (options.kind === 'line' || options.ambiguous) return options;
    i = options.index;
    if (wrapper === 'time') {
      while (tokens[i]?.kind === 'bang-operator') i++;
    }
  }

  const name = tokens[i]?.value;
  if (name === 'eval') {
    // eval joins its arguments with spaces.
    return { kind: 'line', line: tokens.slice(i + 1).map((token) => token.value).join(' '), assignments: assignmentsBefore(tokens, i) };
  }
  if (name !== undefined && Object.hasOwn(COMMAND_LINE_SHELLS, name.slice(name.lastIndexOf('/') + 1))) {
    const line = shellCommandLine(tokens, i);
    if (line !== null) return { kind: 'line', line, assignments: assignmentsBefore(tokens, i) };
  }
  return { kind: 'name', index: i, ambiguous: false };
}

// The argument a shell named at `index` reads as its command line after a
// `-c` option, also in a group (`-lc`, `-euc`); null when it reads a script
// or its input, or when `-c` has no argument.
function shellCommandLine(tokens: readonly ShellToken[], index: number): string | null {
  let readsCommandLine = false;
  for (let i = index + 1; i < tokens.length; i++) {
    const word = tokens[i]!.value;
    if (word === '--') return readsCommandLine ? (tokens[i + 1]?.value ?? null) : null;
    if (Object.hasOwn(SHELL_OPTIONS_WITH_ARG, word)) {
      i++;
      continue;
    }
    if (word.startsWith('--')) continue;
    if (!/^[-+][A-Za-z]+$/.test(word)) return readsCommandLine ? word : null;
    if (word.startsWith('-') && word.includes('c')) readsCommandLine = true;
    // `-o` and `-O` take the next word, also at the end of a group (`-eo pipefail`).
    if (/[oO]/.test(word)) i++;
  }
  return null;
}

type WrapperOption = Readonly<{
  names: readonly string[];
  valued?: Readonly<{ name: string; value: string; }>;
  next: number;
}>;

function consumeWrapperOptions(
  tokens: readonly ShellToken[],
  start: number,
  wrapper: CommandStartWrapper,
  source: string,
): CommandStart {
  let i = start;
  let execs = false;
  while (i < tokens.length) {
    const word = tokens[i]!.value;
    if (wrapper.acceptsAssignments === true && ENV_ASSIGNMENT.test(word)) {
      i++;
      continue;
    }
    if (word === '--') {
      i++;
      break;
    }
    if (!word.startsWith('-') || word === '-') break;
    const option = wrapperOption(tokens, i, wrapper);
    if (option === null) return { kind: 'name', index: i, ambiguous: true };
    if (option.valued !== undefined && wrapper.commandLineOptions?.has(option.valued.name) === true) {
      // `env -S` splits its value into words that come before the rest.
      const rest = tokens[option.next];
      const line = rest === undefined
        ? option.valued.value
        : `${option.valued.value} ${source.slice(rest.start, tokens[tokens.length - 1]!.end)}`;
      return { kind: 'line', line, assignments: assignmentsBefore(tokens, i) };
    }
    if (option.names.some((name) => wrapper.shellOperandsUnless?.has(name) === true)) execs = true;
    i = option.next;
  }
  i = Math.min(i + (wrapper.operands ?? 0), tokens.length);
  // watch joins its operands with spaces and runs them with `sh -c`.
  if (wrapper.shellOperandsUnless !== undefined && !execs) {
    return { kind: 'line', line: tokens.slice(i).map((token) => token.value).join(' '), assignments: assignmentsBefore(tokens, i) };
  }
  return { kind: 'name', index: i, ambiguous: false };
}

// The option at `index`, read as getopt reads it: a long option (`--name`,
// `--name=value`, `--name value`) or a group of short ones (`-0r`, `-n1`,
// `-n 1`); null when the wrapper does not list it.
function wrapperOption(tokens: readonly ShellToken[], index: number, wrapper: CommandStartWrapper): WrapperOption | null {
  const word = tokens[index]!.value;
  const valueFromNextWord = (name: string, names: readonly string[]): WrapperOption | null => {
    const value = tokens[index + 1];
    return value === undefined ? null : { names, valued: { name, value: value.value }, next: index + 2 };
  };

  if (word.startsWith('--')) {
    const equals = word.indexOf('=');
    const name = equals === -1 ? word : word.slice(0, equals);
    if (equals === -1 && wrapper.flags.has(name)) return { names: [name], next: index + 1 };
    if (wrapper.optionalArg?.has(name) === true) return { names: [name], next: index + 1 };
    if (!wrapper.optionsWithArg.has(name)) return null;
    if (equals !== -1) return { names: [name], valued: { name, value: word.slice(equals + 1) }, next: index + 1 };
    return valueFromNextWord(name, [name]);
  }

  const names: string[] = [];
  for (let at = 1; at < word.length; at++) {
    const name = `-${word[at]}`;
    names.push(name);
    if (wrapper.flags.has(name)) continue;
    if (!wrapper.optionsWithArg.has(name)) return null;
    const glued = word.slice(at + 1);
    return glued === '' ? valueFromNextWord(name, names) : { names, valued: { name, value: glued }, next: index + 1 };
  }
  return { names, next: index + 1 };
}

// How many `)` and `}` end the word without being opened in it, outside
// quotes: the closers of a grouping glued to its last word (`push)`).
function unopenedClosers(token: ShellToken, source: string): number {
  const last = source[token.end - 1];
  if (last !== ')' && last !== '}') return 0;
  const text = source.slice(token.start, token.end);
  let parens = 0;
  let braces = 0;
  let quote: '"' | '\'' | null = null;
  for (let i = 0; i < text.length; i++) {
    const character = text[i]!;
    if (quote !== null) {
      if (character === quote) quote = null;
      else if (character === '\\' && quote === '"') i++;
      continue;
    }
    if (character === '\\') i++;
    else if (character === '"' || character === '\'') quote = character;
    else if (character === '(') parens++;
    else if (character === ')') parens--;
    else if (character === '{') braces++;
    else if (character === '}') braces--;
  }
  let closers = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    if (text[i] === ')' && parens < 0) parens++;
    else if (text[i] === '}' && braces < 0) braces++;
    else break;
    closers++;
  }
  return closers;
}

// `token` cut to the source range [start, end): the characters cut are
// unquoted parentheses or braces, so its value is cut the same way, and its
// redirections are read again from what is left (`2>/dev/null)` names
// `/dev/null` once the `)` is cut).
function cutToken(token: ShellToken, source: string, start: number, end: number): ShellToken {
  const value = token.value.slice(start - token.start, token.value.length - (token.end - end));
  const redirections = /[<>]/.test(value) ? shellRedirections(source.slice(start, end), start, token.commandSubstitutions) : null;
  return {
    value,
    kind: token.kind,
    start,
    end,
    hasLiteralizingSyntax: token.hasLiteralizingSyntax,
    hasQuotedWhitespace: token.hasQuotedWhitespace,
    hasUnterminatedQuote: token.hasUnterminatedQuote,
    ...(token.commandSubstitutions === undefined ? {} : { commandSubstitutions: token.commandSubstitutions }),
    ...(redirections === null ? {} : { redirections }),
  };
}

// The words of a segment from its first command word on (points 2 and 3 of
// the list): the keywords, groupings and function heads before it are taken
// off, with a `(` glued to it, and so are the closers that end a grouping and
// whatever follows them. Empty when the segment holds no command.
function commandWords(segment: readonly ShellToken[], source: string): readonly ShellToken[] {
  let first = 0;
  let head: ShellToken | null = null;
  while (head === null && first < segment.length) {
    const token = segment[first]!;
    const word = token.kind === 'bang-operator' ? '!' : token.hasLiteralizingSyntax ? null : token.value;
    if (word !== null && (COMMAND_START_HEADS.has(word) || FUNCTION_DEFINITION.test(word))) {
      first++;
      continue;
    }
    if (word === 'function') {
      first += 2;
      continue;
    }
    let opened = 0;
    while (opened < token.value.length && token.value[opened] === '(' && source[token.start + opened] === '(') opened++;
    if (opened === token.value.length) first++;
    else head = opened === 0 ? token : cutToken(token, source, token.start + opened, token.end);
  }
  if (head === null) return [];

  for (let index = first; index < segment.length; index++) {
    const token = index === first ? head : segment[index]!;
    const closers = unopenedClosers(token, source);
    if (closers === 0) continue;
    const before = index === first ? [] : [head, ...segment.slice(first + 1, index)];
    return closers === token.end - token.start ? before : [...before, cutToken(token, source, token.start, token.end - closers)];
  }
  return first === 0 && head === segment[0] ? segment : [head, ...segment.slice(first + 1)];
}

// The delimiter of a heredoc whose `<<` ends at `start`, and where its word
// ends; null when no word follows that could be one.
function heredocAt(source: string, start: number): Readonly<{ delimiter: HeredocDelimiter; end: number; }> | null {
  let i = start;
  const stripTabs = source[i] === '-';
  if (stripTabs) i++;
  while (source[i] === ' ' || source[i] === '\t') i++;
  // A delimiter is a word: `1 << 2` in an arithmetic expression is a shift.
  if (!/^[\w'"\\]/.test(source[i] ?? '') || /\d/.test(source[i]!)) return null;
  let value = '';
  let quote: string | null = null;
  for (; i < source.length; i++) {
    const character = source[i]!;
    if (quote !== null) {
      if (character === quote) quote = null;
      else value += character;
    } else if (character === '"' || character === '\'') {
      quote = character;
    } else if (character === '\\') {
      value += source[i + 1] ?? '';
      i++;
    } else if (/[\s;&|<>()]/.test(character)) {
      break;
    } else {
      value += character;
    }
  }
  return value === '' ? null : { delimiter: { value, stripTabs }, end: i };
}

type SubstitutionScan = Readonly<{
  // What each backtick and process substitution runs.
  bodies: readonly string[];
  // The heredoc bodies the tokenizer did not record: inside a `$( … )` it
  // could not close, or never closed.
  heredocs: readonly SourceRange[];
}>;

// The body of an open process substitution: where it starts, how far its
// text is taken, and the text taken so far.
type ProcessBody = { start: number; cursor: number; pieces: string[]; };

// A `$( … )` or a process substitution the scan is inside: the quote and the
// parentheses open around it, and for a process substitution its body.
type ScanFrame = Readonly<{ quote: '"' | null; parens: number; body: ProcessBody | null; }>;

// The backtick and process substitutions (`<( … )`, `>( … )`) of a line
// (point 4 of the list), outside single quotes, comments and heredoc bodies,
// in one pass however deep they nest: the body of a process substitution is
// cut of the substitutions nested in it (`cat <(x <(y))` gives `x <()` and
// `y`), which are bodies of their own. `$( … )` is not listed: the tokenizer
// reads its words as segments of the line already; it is followed here for
// its quotes and its heredocs, whose body may hold a quote that hides its end
// from the tokenizer (`git commit -m "$(cat <<'EOF' … EOF )"`). A heredoc body
// the tokenizer recorded (`recorded`, by start) is skipped without being read
// again.
function scanSubstitutions(source: string, recorded: ReadonlyMap<number, number>): SubstitutionScan {
  const bodies: string[] = [];
  const heredocs: SourceRange[] = [];
  const frames: ScanFrame[] = [];
  // The bodies of the open process substitutions, innermost last.
  const processes: ProcessBody[] = [];
  let quote: '"' | '\'' | null = null;
  let parens = 0;
  // The heredocs announced on the current line: their bodies start after it.
  let announced: HeredocDelimiter[] = [];

  // Takes [start, end) out of the innermost open process substitution body.
  const cut = (start: number, end: number): void => {
    const body = processes[processes.length - 1];
    if (body === undefined) return;
    body.pieces.push(source.slice(body.cursor, start));
    body.cursor = end;
  };
  // Leaves the innermost frame at `end`, its closing parenthesis.
  const close = (end: number): void => {
    const frame = frames.pop()!;
    quote = frame.quote;
    parens = frame.parens;
    if (frame.body === null) return;
    processes.pop();
    frame.body.pieces.push(source.slice(frame.body.cursor, end));
    bodies.push(frame.body.pieces.join(''));
    cut(frame.body.start, end);
  };

  for (let i = 0; i < source.length; i++) {
    const character = source[i]!;
    if (quote === '\'') {
      if (character === '\'') quote = null;
      continue;
    }
    if (character === '\\') {
      i++;
      continue;
    }
    if (character === '`') {
      // An unclosed backtick runs to the end of the line.
      const end = backtickSubstitutionEnd(source, i + 1) ?? source.length;
      bodies.push(source.slice(i + 1, end).replace(/\\([$`\\])/g, '$1'));
      cut(i + 1, end);
      i = end;
      continue;
    }
    if (character === '$' && source[i + 1] === '(' && source[i + 2] !== '(') {
      frames.push({ quote, parens, body: null });
      quote = null;
      parens = 0;
      i++;
      continue;
    }
    if (quote === '"') {
      if (character === '"') quote = null;
      continue;
    }
    if (character === '"' || character === '\'') {
      quote = character;
    } else if (character === '\n' && announced.length > 0) {
      const recordedEnd = announced.length === 1 ? recorded.get(i + 1) : undefined;
      const read = recordedEnd === undefined ? consumeHeredocBodies(source, i + 1, announced) : [];
      announced = [];
      if (read === null) {
        heredocs.push({ start: i + 1, end: source.length });
        break;
      }
      heredocs.push(...read);
      i = (recordedEnd ?? read[read.length - 1]!.end) - 1;
    } else if (character === '#' && (i === 0 || /[\s;&|]/.test(source[i - 1]!))) {
      const newline = source.indexOf('\n', i);
      if (newline === -1) break;
      i = newline - 1;
    } else if (character === '<' && source[i + 1] === '<') {
      const heredoc = source[i + 2] === '<' ? null : heredocAt(source, i + 2);
      if (heredoc !== null) announced.push(heredoc.delimiter);
      i = heredoc === null ? i + 1 : heredoc.end - 1;
    } else if ((character === '<' || character === '>') && source[i + 1] === '(') {
      const body: ProcessBody = { start: i + 2, cursor: i + 2, pieces: [] };
      frames.push({ quote, parens, body });
      processes.push(body);
      quote = null;
      parens = 0;
      i++;
    } else if (character === '(') {
      parens++;
    } else if (character === ')') {
      if (parens > 0) parens--;
      else if (frames.length > 0) close(i);
    }
  }
  // An unclosed process substitution runs to the end of the line.
  while (frames.length > 0) close(source.length);
  return { bodies, heredocs };
}

// One command of a line, as the families judge it.
type FoundCommand = Readonly<{
  // Its words from the first one, without the redirections.
  tokens: readonly ShellToken[];
  // Where its name stands among them.
  start: CommandPrefix;
  // A redirection among the words could not be read.
  forceConfirm: boolean;
  // The line the token ranges point into.
  source: string;
  // The assignments written before the shells that run it, outermost first.
  inherited: readonly string[];
}>;

// The text of a command from its word at `index` to its last word.
function commandText({ tokens, source }: FoundCommand, index: number): string {
  return source.slice(tokens[index]!.start, tokens[tokens.length - 1]!.end);
}

type CommandLine = Readonly<{
  // The segments as consumeCommandPrefixes reads them.
  segments: readonly ShellToken[][];
  // Every command whose start the list finds: in the line, then in each
  // command line and substitution body read again.
  commands: readonly FoundCommand[];
}>;

function readCommandLine(cmd: string): CommandLine {
  const tokenized = tokenizeShellSegments(cmd);
  const commands: FoundCommand[] = [];
  collectCommands(cmd, tokenized, 0, [], commands);
  return { segments: tokenized.segments, commands };
}

// Whether a position falls in one of `ranges`, found by bisection over the
// ranges sorted by start and the furthest end reached up to each of them: a
// long line checks each of its segments against each of its heredoc bodies.
function insideAnyRange(ranges: readonly SourceRange[]): (position: number) => boolean {
  const sorted = ranges.toSorted((a, b) => a.start - b.start);
  const reach: number[] = [];
  for (const range of sorted) reach.push(Math.max(range.end, reach[reach.length - 1] ?? 0));
  return (position) => {
    let low = 0;
    let high = sorted.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (sorted[middle]!.start <= position) low = middle + 1;
      else high = middle;
    }
    return low > 0 && reach[low - 1]! > position;
  };
}

// The commands of a line read `depth` levels below the outer one, which
// inherit the assignments `inherited`; the substitutions of the line inherit
// them too, while those written before one of its commands reach that
// command only. A substitution body is read at the depth of its line; only
// a command line handed to a shell goes one level down.
function collectCommands(
  source: string,
  tokenized: TokenizedShell,
  depth: number,
  inherited: readonly string[],
  commands: FoundCommand[],
): void {
  const scan = scanSubstitutions(source, new Map(tokenized.heredocBodies.map((body) => [body.start, body.end])));
  // A heredoc body is data: its lines keep only the segment reading.
  const insideHeredoc = insideAnyRange([...tokenized.heredocBodies, ...scan.heredocs]);
  const nested: { line: string; inherited: readonly string[]; }[] = [];
  for (const segment of tokenized.segments) {
    if (insideHeredoc(segment[0]!.start)) continue;
    const filtered = withoutShellRedirections(commandWords(segment, source));
    if (filtered.tokens.length === 0) continue;
    const start = consumeCommandStart(filtered.tokens, source);
    if (start.kind === 'line') {
      nested.push({ line: start.line, inherited: start.assignments.length === 0 ? inherited : [...inherited, ...start.assignments] });
    } else {
      commands.push({ tokens: filtered.tokens, start, forceConfirm: filtered.forceConfirm, source, inherited });
    }
  }
  // The scan has cut each body of the substitutions nested in it, so reading
  // the bodies goes no deeper than the backticks a body still holds.
  for (const body of scan.bodies) collectCommands(body, tokenizeShellSegments(body), depth, inherited, commands);
  if (depth === MAX_NESTED_READS) return;
  for (const { line, inherited: lineInherited } of nested) {
    collectCommands(line, tokenizeShellSegments(line), depth + 1, lineInherited, commands);
  }
}

// The index of the command's name when it is one of `names`, -1 otherwise.
// An ambiguous start is searched for the name, like the segment reading does.
function namedCommandIndex({ tokens, start }: FoundCommand, names: ReadonlySet<string>): number {
  if (!start.ambiguous) return isCommandNamed(tokens[start.index]?.value, names) ? start.index : -1;
  return tokens.findIndex((token, index) => index >= start.index && isCommandNamed(token.value, names));
}

function retainsQuotedTokenScan(
  tokens: readonly ShellToken[],
  prefix: CommandPrefix,
): boolean {
  if (prefix.ambiguous) return true;
  const command = tokens[prefix.index]?.value;
  return command === 'eval' || (command !== undefined && Object.hasOwn(SHELL_INTERPRETER_COMMANDS, command));
}

function literalTokenRanges(token: ShellToken): readonly SourceRange[] {
  if (token.commandSubstitutions === undefined) return [token];
  const ranges: SourceRange[] = [];
  let start = token.start;
  for (const substitution of token.commandSubstitutions) {
    if (start < substitution.start) ranges.push({ start, end: substitution.start });
    start = substitution.end;
  }
  if (start < token.end) ranges.push({ start, end: token.end });
  return ranges;
}

// Masks declared search-pattern arguments plus quoted prose and heredoc
// bodies that cannot name a path before a path-token scan.
export function maskSearchPatternArguments(
  cmd: string,
  pathToken: RegExp,
  maskedHeads?: Readonly<Record<string, true>>,
): string {
  const tokenized = tokenizeShellSegments(cmd);
  const excluded: SourceRange[] = [];
  excluded.push(...nonPathTokenRanges(cmd, tokenized.heredocBodies, pathToken));

  for (const tokens of tokenized.segments) {
    const prefix = consumeCommandPrefixes(tokens);
    if (!retainsQuotedTokenScan(tokens, prefix)) {
      const quotedProse = tokens.filter((token) => token.hasQuotedWhitespace && !token.hasUnterminatedQuote);
      excluded.push(...nonPathTokenRanges(cmd, quotedProse.flatMap(literalTokenRanges), pathToken));
    }

    if (prefix.ambiguous) continue;
    const tool = tokens[prefix.index]?.value;
    if (tool === undefined) continue;
    const policy = Object.hasOwn(SEARCH_PATTERN_ARGUMENT_POLICIES, tool)
      ? SEARCH_PATTERN_ARGUMENT_POLICIES[tool]!
      : undefined;
    if (policy === undefined) continue;
    if (maskedHeads !== undefined && !Object.hasOwn(maskedHeads, tool)) continue;
    const patternTokens = excludedSearchPatternTokens(tokens.slice(prefix.index + 1), policy);
    if (patternTokens !== null) excluded.push(...patternTokens.flatMap(literalTokenRanges));
  }

  if (excluded.length === 0) return cmd;
  const ranges = excluded.toSorted((a, b) => a.start - b.start || a.end - b.end);
  let masked = '';
  let offset = 0;
  for (const range of ranges) {
    const start = Math.max(offset, range.start);
    if (start >= range.end) continue;
    masked += cmd.slice(offset, start);
    masked += cmd.slice(start, range.end).replace(/[^\r\n]/g, ' ');
    offset = range.end;
  }
  return masked + cmd.slice(offset);
}

function isCommandNamed(token: string | undefined, names: ReadonlySet<string>): boolean {
  if (token === undefined) return false;
  const basename = token.slice(token.lastIndexOf('/') + 1);
  return names.has(basename);
}

function checkPrivilegeEscalationWith(cmd: string, line: CommandLine, privilegeCommands: ReadonlySet<string>): Verdict | null {
  const escalates = line.segments.some((tokens) => {
    const prefix = consumeCommandPrefixes(tokens, PRIVILEGE_BENIGN_PREFIXES);
    const index = prefix.ambiguous
      ? tokens.findIndex((token, tokenIndex) =>
        tokenIndex >= prefix.index
        && isCommandNamed(token.value, privilegeCommands)
      )
      : prefix.index;
    return index !== -1 && isCommandNamed(tokens[index]?.value, privilegeCommands);
  }) || line.commands.some((command) => namedCommandIndex(command, privilegeCommands) !== -1);
  if (!escalates) return null;
  return {
    verdict: 'block',
    ruleId: 'sudo',
    reason: PRIVILEGE_ESCALATION_REASON,
    target: cmd,
  };
}

export function isGitConfigRead(cmdOrRest: string | readonly string[], configReadModes: readonly string[]): boolean {
  if (typeof cmdOrRest !== 'string') {
    return configReadModes.includes(cmdOrRest[0] ?? '');
  }

  const segments = tokenizeShellSegments(cmdOrRest).segments;
  const configCommands = segments
    .map(extractGitSubcommandFromTokens)
    .filter((parsed): parsed is GitCommand => parsed?.sub === 'config');
  return configCommands.length > 0
    && configCommands.every((parsed) => parsed.forceConfirm !== true && configReadModes.includes(parsed.rest[0] ?? ''));
}

const GIT_REMOTE_URL_KEY = /^remote\.[^\s]+\.url$/;

export function hasUnsafeGitConfigRemoteUrl(cmd: string, configReadModes: readonly string[]): boolean {
  for (const tokens of tokenizeShellSegments(cmd).segments) {
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

const CHECKOUT_DESTRUCTIVE_FLAGS: readonly string[] = [
  '-f',
  '--force',
  '-B',
  '--ours',
  '--theirs',
  '-p',
  '--patch',
];

// Checkout and restore remain documented engine exceptions; see the module header.

function checkGitCheckoutNeedsConfirm(rest: readonly string[]): boolean {
  // Branch switching and branch creation are safe (git refuses to clobber
  // a dirty tree); the PATHSPEC form overwrites local edits and asks.
  if (rest.some((t) => t === '--' || askFlagMatches(CHECKOUT_DESTRUCTIVE_FLAGS, t))) {
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

// The interpreter for the four declarative git-conditional forms (see
// policy/schema.ts). `checkout` and `restore` fall through to the two
// named engine functions above; every other subcommand not in
// `safe_subcommands` and not covered by any declarative entry is the
// catch-all — push, rebase, reset, clean, bisect, cherry-pick, revert, gc,
// rm, filter-branch/filter-repo, … — and always needs confirmation.

function safeGrammarTokenMatches(token: SafeGrammarToken, value: string): boolean {
  if (typeof token !== 'string') return GIT_SHA.test(value);
  return token === '*' ? !value.startsWith('-') : token === value;
}

// `safe_flags` is read lexically (ADR-0001): no git call, no filesystem
// read. Token semantics: SafeFlagsRule in policy/schema.ts.
function safeFlagsNeedConfirm(rule: SafeFlagsRule, rest: readonly string[]): boolean {
  let positionals = 0;
  for (let index = 0; index < rest.length; index++) {
    const token = rest[index]!;
    if (!token.startsWith('-')) {
      positionals++;
      continue;
    }
    if (rule.flags.includes(token)) continue;
    if (rule.value_flags.includes(token)) {
      const value = rest[index + 1];
      if (value === undefined || value.startsWith('-')) return true;
      index++;
      continue;
    }
    const equals = token.indexOf('=');
    if (token.startsWith('--') && equals > 2 && equals < token.length - 1 && rule.value_flags.includes(token.slice(0, equals))) {
      continue;
    }
    return true;
  }
  return positionals > rule.max_positionals;
}

// A bare number as a short group (`-12`): git's `-<n>` shorthand, not letters.
const NUMERIC_SHORT_GROUP = /^-\d+$/;

// Whether `token` is one of an ask_flags entry's `flags`, read the way git
// reads options. Token semantics: AskFlagsRule.flags in policy/schema.ts.
function askFlagMatches(flags: readonly string[], token: string): boolean {
  if (flags.includes(token)) return true;
  if (!token.startsWith('-')) return false;
  const equals = token.indexOf('=');

  if (token.startsWith('--')) {
    const name = equals === -1 ? token : token.slice(0, equals);
    if (equals !== -1 && flags.includes(name)) return true;
    if (name.length <= 2) return false;
    return flags.some((flag) => flag.length > name.length && flag.startsWith(name));
  }

  if (NUMERIC_SHORT_GROUP.test(token)) return false;
  const end = equals === -1 ? token.length : equals;
  return flags.some((flag) => {
    if (flag.length !== 2 || flag[0] !== '-' || flag[1] === '-') return false;
    const at = token.indexOf(flag[1]!, 1);
    return at !== -1 && at < end;
  });
}

function hasOnlyChdirGlobals(globals: readonly GitGlobalOption[]): boolean {
  return globals.every(({ option }) => option === '-C');
}

function gitSubcommandNeedsConfirm({ sub, rest, globals }: GitCommand, git: CommandGitPolicy): boolean {
  if (git.safe_subcommands.includes(sub)) return false;

  const askFlags = git.ask_flags.find((e: AskFlagsRule) => e.sub === sub);
  if (askFlags) {
    if (rest.some((t) => askFlagMatches(askFlags.flags, t))) return true;
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
      return seq.every((token, index) => safeGrammarTokenMatches(token, rest[index]!));
    });
    return !matches;
  }

  const safeFlags = git.safe_flags.find((e: SafeFlagsRule) => e.sub === sub);
  if (safeFlags) return !hasOnlyChdirGlobals(globals ?? []) || safeFlagsNeedConfirm(safeFlags, rest);

  if (sub === 'checkout') return checkGitCheckoutNeedsConfirm(rest);
  if (sub === 'restore') return checkGitRestoreNeedsConfirm(rest);

  return true;
}

// One entry of `allowed_config` or `allowed_env`, split once when the checker
// is built. Entry grammar: CommandGitPolicy.allowed_config. `name` is folded to
// lower case in a list compared without regard to case, and loses its `*` in a
// prefix entry; a `*` only means something at the end of an entry without a
// value.
type AllowEntry = Readonly<{ name: string; value: string | null; prefix: boolean; }>;
// `pairNames` are the names listed only with a value, to tell "listed, but not at
// this value" from "not listed" when a setting is refused.
type AllowList = Readonly<{ entries: readonly AllowEntry[]; foldCase: boolean; pairNames: ReadonlySet<string>; }>;

// The three `git-config-exec` lists, ready to be read for every command.
type ConfigExecLists = Readonly<{
  globalOptions: ReadonlySet<string>;
  config: AllowList;
  env: AllowList;
}>;

function compileAllowList(entries: readonly string[], foldCase: boolean): AllowList {
  const fold = (text: string): string => (foldCase ? text.toLowerCase() : text);
  const compiled = entries.map((entry): AllowEntry => {
    const equals = entry.indexOf('=');
    if (equals !== -1) return { name: fold(entry.slice(0, equals)), value: entry.slice(equals + 1), prefix: false };
    const name = fold(entry);
    return name.endsWith('*') ? { name: name.slice(0, -1), value: null, prefix: true } : { name, value: null, prefix: false };
  });
  return {
    foldCase,
    entries: compiled,
    pairNames: new Set(compiled.filter((entry) => entry.value !== null).map((entry) => entry.name)),
  };
}

function compileConfigExecLists(git: CommandGitPolicy): ConfigExecLists {
  return {
    globalOptions: new Set(git.allowed_global_options),
    config: compileAllowList(git.allowed_config, true),
    env: compileAllowList(git.allowed_env, false),
  };
}

// Whether `name` is on an allow-list, for a setting of that `value` (null when
// it has none, or when it is only known at run time).
function onAllowList({ entries, foldCase }: AllowList, name: string, value: string | null): boolean {
  const subject = foldCase ? name.toLowerCase() : name;
  return entries.some((entry) => {
    if (entry.value !== null) return entry.value === value && subject === entry.name;
    return entry.prefix ? subject.startsWith(entry.name) : subject === entry.name;
  });
}

// Why `name` is refused by `list`: listed, but only at harmless values, or not
// listed and so able to make git run any program. `subject` is how the reason
// introduces it.
function refusal(list: AllowList, name: string, subject: string): string {
  const listedOnlyAtValues = list.pairNames.has(list.foldCase ? name.toLowerCase() : name);
  return listedOnlyAtValues
    ? `${subject} is listed only at harmless values`
    : `${subject} can make git run an arbitrary program and is not on the git-config-exec allow-list`;
}

// What, in the words written around `git`, the policy does not list: the first
// environment assignment, then the first global option, `-c` or `--config-env`
// setting, as the verdict's reason; null when every one is allowed. The reason
// names a variable, a key or an option, never a value. Read lexically, like the
// rest of the git policy — git is not called and no file is read.
function gitConfigExecOffender({ globals, assignments }: GitCommand, lists: ConfigExecLists): string | null {
  for (const assignment of assignments ?? []) {
    const equals = assignment.indexOf('=');
    const name = assignment.slice(0, equals);
    if (!onAllowList(lists.env, name, assignment.slice(equals + 1))) {
      return refusal(lists.env, name, `environment variable ${name}`);
    }
  }

  for (const { option, value: nextToken } of globals ?? []) {
    const equals = option.indexOf('=');
    // Only a long option is `--name=value`; a glued short one stays a single token.
    const name = equals !== -1 && option.startsWith('--') ? option.slice(0, equals) : option;

    if (name === '-c' || name === '--config-env') {
      // `-c` and a separate `--config-env` take their setting from the next token.
      const setting = equals === -1 ? (nextToken ?? '') : option.slice(equals + 1);
      const settingEquals = setting.indexOf('=');
      const key = settingEquals === -1 ? setting : setting.slice(0, settingEquals);
      // `--config-env=key=VAR` reads the value from VAR when git runs.
      const value = name === '-c' && settingEquals !== -1 ? setting.slice(settingEquals + 1) : null;
      if (!onAllowList(lists.config, key, value)) return refusal(lists.config, key, `${name} ${key}`);
      continue;
    }

    if (!lists.globalOptions.has(name)) {
      const shown = equals === -1 ? option : option.slice(0, equals);
      return `global option ${shown} is not on the git-config-exec allow-list`;
    }
  }
  return null;
}

// Every git command of the line: each segment through consumeCommandPrefixes,
// then each command the shared start of a command finds.
function* gitCommands(line: CommandLine): Generator<GitCommand> {
  for (const tokens of line.segments) {
    const parsed = extractGitSubcommandFromTokens(tokens);
    if (parsed !== null) yield parsed;
  }
  for (const { tokens, start, forceConfirm, inherited } of line.commands) {
    const parsed = gitCommandAt(tokens, start, forceConfirm, inherited);
    if (parsed !== null) yield parsed;
  }
}

function checkGitWith(cmd: string, line: CommandLine, git: CommandGitPolicy, lists: ConfigExecLists): Verdict | null {
  for (const parsed of gitCommands(line)) {
    if (parsed.forceConfirm || gitSubcommandNeedsConfirm(parsed, git)) {
      return {
        verdict: 'confirm',
        ruleId: 'git-protected',
        reason: `git ${parsed.sub} can rewrite history, mutate a remote, or discard work — confirm before running`,
        target: cmd,
      };
    }
    // Judged after the subcommand, so that a subcommand that asks keeps
    // `git-protected` and this rule only turns an allow into a confirm.
    const offender = gitConfigExecOffender(parsed, lists);
    if (offender !== null) {
      return {
        verdict: 'confirm',
        ruleId: 'git-config-exec',
        reason: `${offender} — confirm before running`,
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
  for (const parsed of gitCommands(readCommandLine(cmd))) {
    if (parsed.forceConfirm) continue;
    if (gitSubcommandNeedsConfirm(parsed, git)) continue;
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
  const specials = {
    docker_destructive: dockerDestructiveMatches,
  };
  const dangerousTargets = policy.rm_rf.dangerous_targets.map((pattern) => new RegExp(pattern));
  const privilegeCommands = new Set(policy.privilege_escalation.commands);
  const git = policy.git;
  const configExecLists = compileConfigExecLists(git);

  const checkGit = (cmd: string): Verdict | null => checkGitWith(cmd, readCommandLine(cmd), git, configExecLists);
  const classifyGitAllow = (cmd: string): Verdict | null => classifyGitAllowWith(cmd, git);

  const checkBash = (cmd: string): Verdict | null => {
    if (!cmd) return null;
    const line = readCommandLine(cmd);

    // Special-cased: rm -rf needs allowlist logic before generic regex.
    const rmHit = checkRmRfWith(cmd, line, dangerousTargets);
    if (rmHit) return rmHit;

    const privilegeHit = checkPrivilegeEscalationWith(cmd, line, privilegeCommands);
    if (privilegeHit) return privilegeHit;

    // Hard-block rules take priority over the git "confirm" guard.
    const hit = firstMatch(compiledBash, cmd, 'block', specials);
    if (hit) return hit;
    // Protected git operations → interactive prompt ("confirm").
    return checkGitWith(cmd, line, git, configExecLists);
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
  return checkRmRfWith(cmd, readCommandLine(cmd), BASELINE.rules.command.rm_rf.dangerous_targets.map((p) => new RegExp(p)));
}
export function checkPrivilegeEscalation(cmd: string): Verdict | null {
  return checkPrivilegeEscalationWith(cmd, readCommandLine(cmd), new Set(BASELINE.rules.command.privilege_escalation.commands));
}

/** The embedded baseline's unconditionally-safe git subcommands. */
export const SAFE_GIT_SUBCOMMANDS: ReadonlySet<string> = new Set(BASELINE.rules.command.git.safe_subcommands);
/** The embedded baseline's privilege-escalation tool names. */
export const PRIVILEGE_ESCALATION_COMMANDS: ReadonlySet<string> = new Set(
  BASELINE.rules.command.privilege_escalation.commands,
);
