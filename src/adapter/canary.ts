export const CANARY_REASON = 'bouncer-canary: bouncer cannot run (missing, not executable, or policy failed to load) — failing closed';
const CANARY_SCRIPT = 'if ! "$0" ping; then printf "%s\\n" "$1"; fi';
const CANARY_OUTPUT = JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'deny',
    permissionDecisionReason: CANARY_REASON,
  },
});

function quoteForPosixShell(value: string): string {
  const escaped = value.replaceAll('\'', '\'"\'"\'');
  return `'${escaped}'`;
}

const CANARY_SCRIPT_WORD = quoteForPosixShell(CANARY_SCRIPT);
const CANARY_OUTPUT_WORD = quoteForPosixShell(CANARY_OUTPUT);

/** Builds the POSIX shell command installed as the fail-closed PreToolUse canary. */
export function buildCanaryCommand(binaryPath: string): string {
  return ['sh', '-c', CANARY_SCRIPT_WORD, quoteForPosixShell(binaryPath), CANARY_OUTPUT_WORD].join(' ');
}

/**
 * Splits just enough POSIX shell syntax to inspect hook commands without
 * mistaking quoted text for an executable token. It deliberately does not
 * execute or expand any shell syntax.
 */
function shellWords(command: string): string[] | null {
  const words: string[] = [];
  let word = '';
  let hasWord = false;
  let quote: 'single' | 'double' | undefined;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index]!;
    if (quote === 'single') {
      if (character === '\'') quote = undefined;
      else word += character;
      continue;
    }
    if (quote === 'double') {
      if (character === '"') quote = undefined;
      else if (character === '\\') {
        const escaped = command[index + 1];
        if (escaped === undefined) return null;
        word += escaped;
        index += 1;
      } else word += character;
      continue;
    }

    if (/\s/.test(character)) {
      if (hasWord) words.push(word);
      word = '';
      hasWord = false;
    } else if (character === '\'') {
      quote = 'single';
      hasWord = true;
    } else if (character === '"') {
      quote = 'double';
      hasWord = true;
    } else if (character === '\\') {
      const escaped = command[index + 1];
      if (escaped === undefined) return null;
      word += escaped;
      index += 1;
      hasWord = true;
    } else {
      word += character;
      hasWord = true;
    }
  }
  if (quote !== undefined) return null;
  if (hasWord) words.push(word);
  return words;
}

export type InspectedCanaryCommand =
  | { readonly kind: 'canonical'; readonly binaryPath: string; }
  | { readonly kind: 'ping-probe'; readonly binaryPath: string; }
  | { readonly kind: 'other'; };

/**
 * Classifies known canary-shaped hook commands by shell tokens. A command
 * merely containing the word "ping" is deliberately not a liveness probe.
 */
export function inspectCanaryCommand(command: unknown): InspectedCanaryCommand {
  if (typeof command !== 'string') return { kind: 'other' };
  const words = shellWords(command);
  if (words === null || words[0] !== 'sh' || words[1] !== '-c') return { kind: 'other' };

  const [, , script, binaryPath, output] = words;
  if (
    words.length === 5
    && script === CANARY_SCRIPT
    && binaryPath !== undefined
    && output === CANARY_OUTPUT
  ) return { kind: 'canonical', binaryPath };

  const scriptWords = script === undefined ? null : shellWords(script);
  if (
    words.length >= 4
    && binaryPath !== undefined
    && scriptWords?.length === 2
    && scriptWords[0] === '$0'
    && scriptWords[1] === 'ping'
  ) return { kind: 'ping-probe', binaryPath };

  return { kind: 'other' };
}

/** Accepts only the generated canary grammar, with whitespace flexibility between shell words. */
export function isCanonicalCanaryCommand(command: unknown, binaryPath: string): boolean {
  const inspected = inspectCanaryCommand(command);
  return inspected.kind === 'canonical' && inspected.binaryPath === binaryPath;
}
