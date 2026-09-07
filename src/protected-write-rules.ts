import { canonicalizePath } from './adapter/paths.ts';
import {
  consumeCommandPrefixes,
  extractGitSubcommandFromTokens,
  maskSearchPatternArguments,
  type ShellToken,
  tokenizeShellSegments,
} from './command-rules.ts';
import { harnessEnvWitnesses } from './policy/harness.ts';
import { compileRules, firstMatch } from './policy/match.ts';
import type { HarnessDeclaration, RegexRule } from './policy/schema.ts';
import { BASH_PATH_TOKEN, globPathReadings } from './secret-rules.ts';
import { type Verdict, VERDICT_SEVERITY } from './types.ts';

const READ_ONLY_COMMANDS: Readonly<Record<string, true>> = {
  cat: true,
  less: true,
  more: true,
  head: true,
  tail: true,
  grep: true,
  rg: true,
  ag: true,
  diff: true,
  cmp: true,
  jq: true,
  stat: true,
  wc: true,
  file: true,
  bat: true,
  shasum: true,
  sha1sum: true,
  sha256sum: true,
  sha512sum: true,
  md5sum: true,
  ls: true,
  find: true,
  fd: true,
  tree: true,
  cd: true,
  pushd: true,
  test: true,
  '[': true,
  source: true,
  '.': true,
  echo: true,
  printf: true,
  bouncer: true,
};

// These Git subcommands may mutate Git metadata or network state, but they do
// not write the named filesystem paths in their arguments. Keep their prose
// out of the conservative unknown-head fallback.
const GIT_SUBCOMMANDS_WITHOUT_PATH_TARGETS: Readonly<Record<string, true>> = {
  diff: true,
  show: true,
  log: true,
  blame: true,
  status: true,
  'ls-files': true,
  'cat-file': true,
  grep: true,
  commit: true,
  add: true,
  push: true,
  fetch: true,
  'rev-parse': true,
  branch: true,
  tag: true,
  remote: true,
};

const LAST_OPERAND_WRITERS: Readonly<Record<string, true>> = {
  cp: true,
  install: true,
  rsync: true,
  ln: true,
};

const EVERY_OPERAND_WRITERS: Readonly<Record<string, true>> = {
  mv: true,
  rm: true,
  unlink: true,
  shred: true,
  truncate: true,
  touch: true,
  chmod: true,
  chown: true,
  chattr: true,
  patch: true,
};

const TARGET_DIRECTORY_WRITERS: Readonly<Record<string, true>> = {
  cp: true,
  install: true,
  ln: true,
  mv: true,
};

const WRITER_OPTIONS_WITH_ARGUMENT: Readonly<Record<string, Readonly<Record<string, true>>>> = {
  cp: {
    '-S': true,
    '--suffix': true,
    '--backup': true,
    '--preserve': true,
    '--no-preserve': true,
    '--sparse': true,
    '--reflink': true,
    '-Z': true,
    '--context': true,
  },
  install: {
    '-m': true,
    '--mode': true,
    '-o': true,
    '--owner': true,
    '-g': true,
    '--group': true,
    '-S': true,
    '--suffix': true,
    '--backup': true,
    '--strip-program': true,
    '-Z': true,
    '--context': true,
  },
  ln: {
    '-S': true,
    '--suffix': true,
    '--backup': true,
    '-Z': true,
    '--context': true,
  },
  patch: {
    '-i': true,
    '-d': true,
    '-D': true,
    '-B': true,
    '-z': true,
    '-r': true,
    '--input': true,
    '--directory': true,
  },
  touch: {
    '-r': true,
    '-d': true,
    '-t': true,
    '--date': true,
    '--reference': true,
  },
  truncate: {
    '-s': true,
    '-r': true,
    '--size': true,
    '--reference': true,
  },
  mv: { '-S': true, '--suffix': true },
  chmod: { '--reference': true },
  chown: { '--from': true, '--reference': true },
  shred: { '-n': true, '-s': true },
  rsync: {
    '-e': true,
    '--rsh': true,
    '-f': true,
    '--filter': true,
    '--exclude': true,
    '--include': true,
    '--exclude-from': true,
    '--include-from': true,
    '--files-from': true,
    '--log-file': true,
    '-T': true,
    '--temp-dir': true,
    '-B': true,
    '--block-size': true,
    '--bwlimit': true,
    '--timeout': true,
    '--port': true,
    '--chmod': true,
    '--chown': true,
    '--backup-dir': true,
    '--suffix': true,
    '--compare-dest': true,
    '--copy-dest': true,
    '--link-dest': true,
    '--partial-dir': true,
    '--max-size': true,
    '--min-size': true,
    '--max-delete': true,
    '--usermap': true,
    '--groupmap': true,
    '--address': true,
    '--sockopts': true,
    '--password-file': true,
    '--rsync-path': true,
  },
};

const OUTPUT_OPTIONS: Readonly<Record<string, Readonly<Record<string, true>>>> = {
  patch: { '-o': true, '--output': true },
};

// A head that can write through its pattern argument is never opted in here.
const PROTECTED_WRITE_MASKED_HEADS: Readonly<Record<string, true>> = {
  grep: true,
  egrep: true,
  fgrep: true,
  rg: true,
  ag: true,
  ack: true,
};

const REDIRECTION_OPERATOR = /^(?:&>>|&>|>>|\d*>\||\d+>>?|>)$/;

type RedirectionOperand = Readonly<{
  precedingOperand: string | null;
  target: string | null;
  consumesFollowingToken: boolean;
}>;

type ParsedWriterOperands = Readonly<{
  operands: readonly string[];
  targetDirectories: readonly string[];
  outputTargets: readonly string[];
}>;

type StructuralWriteTargets = Readonly<{
  targets: readonly string[];
  sedScriptTargets: readonly string[];
  recognized: boolean;
  head: string | null;
}>;

type BashPathMechanism = 'structural' | 'sed-script' | 'fallback';

function strictestPathHit(first: Verdict | null, second: Verdict | null): Verdict | null {
  if (first === null) return second;
  if (second === null) return first;
  return VERDICT_SEVERITY[second.verdict] > VERDICT_SEVERITY[first.verdict] ? second : first;
}

type UnquotedRedirection = Readonly<{
  offset: number;
  operator: string;
}>;

function unquotedRedirection(source: string): UnquotedRedirection | null {
  let quote: '"' | '\'' | null = null;

  for (let index = 0; index < source.length; index++) {
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
      const escaped = source[index + 1];
      if (escaped !== undefined) index++;
      continue;
    }
    if (character === '"' || character === '\'') {
      quote = character;
      continue;
    }

    const operator = source.slice(index).match(/^(?:&>>|&>|>>|\d*>\||\d+>>?|>)/)?.[0];
    if (operator !== undefined) return { offset: index, operator };
  }
  return null;
}

function redirectionOperand(token: ShellToken, command: string): RedirectionOperand | null {
  const source = command.slice(token.start, token.end);
  if (REDIRECTION_OPERATOR.test(source)) {
    return { precedingOperand: null, target: null, consumesFollowingToken: true };
  }

  const redirection = unquotedRedirection(source);
  if (redirection === null) return null;
  const precedingOperand = tokenizeShellSegments(source.slice(0, redirection.offset)).segments[0]?.[0]?.value ?? null;
  const target = tokenizeShellSegments(source.slice(redirection.offset + redirection.operator.length)).segments[0]?.[0]?.value ?? '';
  return {
    precedingOperand,
    target,
    consumesFollowingToken: false,
  };
}

function inputRedirectionConsumesFollowingToken(token: ShellToken, command: string): boolean {
  const source = command.slice(token.start, token.end);
  return /^\d*<$/.test(source);
}

function isAttachedInputRedirection(token: ShellToken, command: string): boolean {
  const source = command.slice(token.start, token.end);
  return /^\d*</.test(source);
}

type WriterOptionArgument = Readonly<{
  kind: 'target-directory' | 'output' | 'option';
  value: string | undefined;
  consumesFollowingToken: boolean;
}>;

function writerOptionArgument(
  value: string,
  next: ShellToken | undefined,
  supportsTargetDirectory: boolean,
  outputOptions: Readonly<Record<string, true>>,
  optionsWithArgument: Readonly<Record<string, true>>,
): WriterOptionArgument | null {
  const kindFor = (option: string): WriterOptionArgument['kind'] | null => {
    if (supportsTargetDirectory && (option === '-t' || option === '--target-directory')) return 'target-directory';
    if (Object.hasOwn(outputOptions, option)) return 'output';
    return Object.hasOwn(optionsWithArgument, option) ? 'option' : null;
  };
  const read = (kind: WriterOptionArgument['kind'], attached: string | undefined): WriterOptionArgument => ({
    kind,
    value: attached ?? next?.value,
    consumesFollowingToken: attached === undefined && next !== undefined,
  });

  if (value.startsWith('--')) {
    const equals = value.indexOf('=');
    const option = equals < 0 ? value : value.slice(0, equals);
    const kind = kindFor(option);
    return kind === null ? null : read(kind, equals < 0 ? undefined : value.slice(equals + 1));
  }

  for (let index = 1; index < value.length; index++) {
    const kind = kindFor(`-${value[index]!}`);
    if (kind !== null) return read(kind, value.slice(index + 1) || undefined);
  }
  return null;
}

function parseWriterOperands(
  tokens: readonly ShellToken[],
  command: string,
  head: string,
): ParsedWriterOperands {
  const operands: string[] = [];
  const targetDirectories: string[] = [];
  const outputTargets: string[] = [];
  const optionsWithArgument = WRITER_OPTIONS_WITH_ARGUMENT[head] ?? {};
  const outputOptions = OUTPUT_OPTIONS[head] ?? {};
  const supportsTargetDirectory = Object.hasOwn(TARGET_DIRECTORY_WRITERS, head);
  let parseOptions = true;

  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    const next = tokens[index + 1];
    const outputRedirect = redirectionOperand(token, command);
    if (outputRedirect !== null) {
      if (outputRedirect.precedingOperand !== null) operands.push(outputRedirect.precedingOperand);
      if (outputRedirect.consumesFollowingToken) index++;
      continue;
    }
    if (inputRedirectionConsumesFollowingToken(token, command)) {
      index++;
      continue;
    }
    if (isAttachedInputRedirection(token, command)) continue;

    const value = token.value;
    if (parseOptions && value === '--') {
      parseOptions = false;
      continue;
    }
    if (!parseOptions || value === '-' || !value.startsWith('-')) {
      operands.push(value);
      continue;
    }

    const optionArgument = writerOptionArgument(
      value,
      next,
      supportsTargetDirectory,
      outputOptions,
      optionsWithArgument,
    );
    if (optionArgument === null) continue;
    if (optionArgument.kind === 'target-directory' && optionArgument.value !== undefined) {
      targetDirectories.push(optionArgument.value);
    }
    if (optionArgument.kind === 'output' && optionArgument.value !== undefined) {
      outputTargets.push(optionArgument.value);
    }
    if (optionArgument.consumesFollowingToken) index++;
  }

  return { operands, targetDirectories, outputTargets };
}

function basename(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  const slash = trimmed.lastIndexOf('/');
  return slash < 0 ? trimmed : trimmed.slice(slash + 1);
}

function targetDirectoryEntries(targetDirectories: readonly string[], sources: readonly string[]): readonly string[] {
  const targets: string[] = [];
  for (const directory of targetDirectories) {
    targets.push(directory);
    const normalizedDirectory = directory.replace(/\/+$/, '');
    for (const source of sources) {
      const name = basename(source);
      if (name) targets.push(`${normalizedDirectory}/${name}`);
    }
  }
  return targets;
}

function positionalDestinationEntries(operands: readonly string[]): readonly string[] {
  const destination = operands.at(-1);
  return destination === undefined ? [] : targetDirectoryEntries([destination], operands.slice(0, -1));
}

function sedTargets(tokens: readonly ShellToken[], command: string, inPlace: boolean): StructuralWriteTargets {
  const fileOperands: string[] = [];
  const sedScriptTargets: string[] = [];
  let scriptSeen = false;
  let parseOptions = true;

  const recordScript = (script: string): void => {
    scriptSeen = true;
    sedScriptTargets.push(...(script.match(BASH_PATH_TOKEN) ?? []));
  };

  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    const next = tokens[index + 1];
    const outputRedirect = redirectionOperand(token, command);
    if (outputRedirect !== null) {
      if (outputRedirect.precedingOperand !== null) {
        if (scriptSeen) fileOperands.push(outputRedirect.precedingOperand);
        else recordScript(outputRedirect.precedingOperand);
      }
      if (outputRedirect.consumesFollowingToken) index++;
      continue;
    }
    if (inputRedirectionConsumesFollowingToken(token, command)) {
      index++;
      continue;
    }
    if (isAttachedInputRedirection(token, command)) continue;

    const value = token.value;
    if (parseOptions && value === '--') {
      parseOptions = false;
      continue;
    }
    if (!parseOptions || value === '-' || !value.startsWith('-')) {
      if (!scriptSeen) recordScript(value);
      else fileOperands.push(value);
      continue;
    }

    if (value === '-e' || value === '--expression') {
      if (next !== undefined) recordScript(next.value);
      index++;
      continue;
    }
    if (value.startsWith('--expression=')) {
      recordScript(value.slice('--expression='.length));
      continue;
    }
    if (value === '-f' || value === '--file') {
      scriptSeen = true;
      index++;
      continue;
    }
    if (value.startsWith('--file=')) continue;
  }

  return {
    targets: inPlace ? fileOperands : [],
    sedScriptTargets,
    recognized: true,
    head: 'sed',
  };
}

function hasSedInPlaceFlag(tokens: readonly ShellToken[]): boolean {
  return tokens.some((token) =>
    token.value.startsWith('-i')
    || token.value === '--in-place'
    || token.value.startsWith('--in-place=')
  );
}

function hasPerlInPlaceFlag(tokens: readonly ShellToken[]): boolean {
  return tokens.some((token) =>
    /^-(?![IeEM])[a-zA-Z]*i/.test(token.value)
    || token.value === '--in-place'
    || token.value.startsWith('--in-place=')
  );
}

function redirectTargets(tokens: readonly ShellToken[], command: string): readonly string[] {
  const targets: string[] = [];
  for (let index = 0; index < tokens.length; index++) {
    const outputRedirect = redirectionOperand(tokens[index]!, command);
    if (outputRedirect === null) continue;
    if (outputRedirect.target !== null) {
      targets.push(outputRedirect.target);
      continue;
    }

    const next = tokens[index + 1];
    if (next !== undefined) targets.push(next.value);
  }
  return targets;
}

function structuralWriteTargets(tokens: readonly ShellToken[], command: string): StructuralWriteTargets {
  const prefix = consumeCommandPrefixes(tokens);
  const redirects = redirectTargets(tokens, command);
  if (prefix.ambiguous) return { targets: redirects, sedScriptTargets: [], recognized: false, head: null };

  const head = tokens[prefix.index]?.value;
  if (head === undefined) return { targets: redirects, sedScriptTargets: [], recognized: false, head: null };
  const operands = tokens.slice(prefix.index + 1);
  if (head === 'sed') {
    const sed = sedTargets(operands, command, hasSedInPlaceFlag(operands));
    return { ...sed, targets: [...redirects, ...sed.targets] };
  }

  const parsed = parseWriterOperands(operands, command, head);
  if (head === 'tee') {
    return { targets: [...redirects, ...parsed.operands], sedScriptTargets: [], recognized: true, head };
  }
  if (Object.hasOwn(LAST_OPERAND_WRITERS, head)) {
    const targets = parsed.targetDirectories.length > 0
      ? targetDirectoryEntries(parsed.targetDirectories, parsed.operands)
      : positionalDestinationEntries(parsed.operands);
    return { targets: [...redirects, ...parsed.outputTargets, ...targets], sedScriptTargets: [], recognized: true, head };
  }
  if (Object.hasOwn(EVERY_OPERAND_WRITERS, head)) {
    const targetDirectories = targetDirectoryEntries(parsed.targetDirectories, parsed.operands);
    const positionalDestinations = head === 'mv' ? positionalDestinationEntries(parsed.operands) : [];
    return {
      targets: [...redirects, ...parsed.outputTargets, ...parsed.operands, ...targetDirectories, ...positionalDestinations],
      sedScriptTargets: [],
      recognized: true,
      head,
    };
  }
  if (head === 'perl' && hasPerlInPlaceFlag(operands)) {
    return { targets: [...redirects, ...parsed.operands], sedScriptTargets: [], recognized: true, head };
  }
  if (head === 'dd') {
    const targets = operands.flatMap((token) => {
      const outputRedirect = redirectionOperand(token, command);
      const value = outputRedirect?.precedingOperand ?? token.value;
      return value.startsWith('of=') ? [value.slice(3)] : [];
    });
    return {
      targets: [...redirects, ...targets],
      sedScriptTargets: [],
      recognized: true,
      head,
    };
  }
  return { targets: redirects, sedScriptTargets: [], recognized: false, head };
}

function isKnownReader(tokens: readonly ShellToken[]): boolean {
  const prefix = consumeCommandPrefixes(tokens);
  if (prefix.ambiguous) return false;

  const head = tokens[prefix.index]?.value;
  if (head === 'git' || head?.endsWith('/git')) {
    const git = extractGitSubcommandFromTokens(tokens);
    return git !== null && Object.hasOwn(GIT_SUBCOMMANDS_WITHOUT_PATH_TARGETS, git.sub);
  }
  return head !== undefined && Object.hasOwn(READ_ONLY_COMMANDS, head);
}

function fallbackPathCandidates(token: ShellToken, masked: string): readonly string[] {
  if (/^\w+=/.test(token.value)) return [];
  const candidates = masked.slice(token.start, token.end).match(BASH_PATH_TOKEN) ?? [];
  const expanded = token.pathCandidates;
  const hasPathCandidate = candidates.some((candidate) => candidate.includes('/') || candidate.startsWith('~'));
  if (!token.hasQuotedWhitespace || !hasPathCandidate) {
    return expanded === undefined ? candidates : [...candidates, ...expanded];
  }
  return expanded === undefined ? [...candidates, token.value] : [...candidates, token.value, ...expanded];
}

function bashPathHit(
  pathHit: Verdict,
  command: string,
  mechanism: BashPathMechanism,
  head: string | null,
): Verdict {
  const reason = mechanism === 'fallback'
    ? `Bash command with an unrecognized write form (${head ?? 'unknown'}) names a path protected by ${pathHit.ruleId}: ${pathHit.reason}`
    : mechanism === 'sed-script'
    ? `sed script names a protected path: ${pathHit.reason}`
    : `Bash write target protected by ${pathHit.ruleId}: ${pathHit.reason}`;
  return {
    verdict: pathHit.verdict,
    ruleId: `bash-${pathHit.ruleId}`,
    reason,
    target: command,
  };
}

function braceExpansionCapHit(command: string): Verdict {
  return {
    verdict: 'confirm',
    ruleId: 'bash-brace-expansion-cap',
    reason: 'brace expansion exceeds the cap',
    target: command,
  };
}

export interface ProtectedWriteChecker {
  readonly checkPath: (path: string) => Promise<Verdict | null>;
  readonly checkBashWrites: (command: string) => Promise<Verdict | null>;
}

export function createProtectedWriteChecker(
  rules: readonly RegexRule[],
  harnesses: readonly HarnessDeclaration[],
): ProtectedWriteChecker {
  const compiled = compileRules(rules);
  const witnesses = harnesses.length === 0 ? undefined : harnessEnvWitnesses(harnesses);

  const checkPath = async (path: string): Promise<Verdict | null> => {
    if (!path) return null;
    const raw = firstMatch(compiled, path, 'confirm');
    const canonical = await canonicalizePath(path);
    if (canonical === path) return raw;
    return strictestPathHit(raw, firstMatch(compiled, canonical, 'confirm'));
  };

  const checkPathReadings = async (path: string, sourceToken?: ShellToken): Promise<Verdict | null> => {
    const tokenizedPath = sourceToken === undefined
      ? tokenizeShellSegments(path, witnesses, { pathCandidates: true })
      : undefined;
    const segment = tokenizedPath?.segments[0];
    const candidates = sourceToken !== undefined
      ? sourceToken.pathCandidates ?? [path]
      : tokenizedPath!.segments.length === 1 && segment?.length === 1
      ? segment[0]?.pathCandidates ?? [path]
      : [path];
    const readings = candidates.flatMap((candidate) => globPathReadings(candidate) ?? [candidate]);
    const hits = await Promise.all(readings.map((reading) => checkPath(reading)));
    return hits.reduce<Verdict | null>((strictest, hit) => strictestPathHit(strictest, hit), null);
  };

  const checkBashWrites = async (command: string): Promise<Verdict | null> => {
    if (!command) return null;
    const tokenized = tokenizeShellSegments(command, witnesses, { pathCandidates: true });
    const masked = maskSearchPatternArguments(command, BASH_PATH_TOKEN, PROTECTED_WRITE_MASKED_HEADS);

    for (const tokens of tokenized.segments) {
      if (tokens.length === 0) continue;
      if (tokens.every((token) => tokenized.heredocBodies.some((body) => body.start <= token.start && token.end <= body.end))) continue;
      const structural = structuralWriteTargets(tokens, command);
      if (tokens.some((token) => token.braceExpansionExceeded === true)) {
        if (structural.recognized || !isKnownReader(tokens)) return braceExpansionCapHit(command);
        continue;
      }
      for (const target of structural.targets) {
        // Preserve shell order and avoid canonicalizing targets after the
        // first protected write in this command.
        // oxlint-disable-next-line no-await-in-loop
        const hit = await checkPathReadings(target, tokens.find((token) => token.value === target));
        if (hit) return bashPathHit(hit, command, 'structural', structural.head);
      }
      for (const target of structural.sedScriptTargets) {
        // Script paths are write-capable sed operands, not search patterns.
        // oxlint-disable-next-line no-await-in-loop
        const hit = await checkPathReadings(target, tokens.find((token) => token.value === target));
        if (hit) return bashPathHit(hit, command, 'sed-script', structural.head);
      }
      if (structural.recognized || isKnownReader(tokens)) continue;

      for (const token of tokens) {
        const candidates = fallbackPathCandidates(token, masked);
        for (const candidate of candidates) {
          // Preserve shell order and stop at the first protected candidate.
          // oxlint-disable-next-line no-await-in-loop
          const hit = await checkPathReadings(candidate, candidate === token.value ? token : undefined);
          if (hit) return bashPathHit(hit, command, 'fallback', structural.head);
        }
      }
    }
    return null;
  };

  return { checkPath, checkBashWrites };
}
