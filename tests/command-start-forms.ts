// The shared list of what counts as the start of a command
// (docs/reference/policy.md § What counts as the start of a command), written
// once as forms around a command X. Every family below is replayed on every
// form: fixtures/command.json carries the result as its `command-start-*`
// cases, and tests/command-start-forms.test.ts fails when the two differ.
// After changing a form or a family, rewrite the cases with
// `bun tests/command-start-forms.ts`.
//
// A family is a command with the verdict it gets on its own. Another family
// (the env rows' `env`, for one) joins by adding an entry to
// COMMAND_START_FAMILIES; the forms stay as they are.

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ExpectedVerdict, FixtureCase, FixtureFile } from './fixture-runner.ts';

export const COMMAND_START_CASE_PREFIX = 'command-start-';

export type CommandStartForm = Readonly<{
  id: string;
  wrap: (command: string) => string;
}>;

// A form whose X starts a command: X gets the verdict it has on its own.
export const COMMAND_START_FORMS: readonly CommandStartForm[] = [
  // 1. Separators.
  { id: 'after-semicolon', wrap: (x) => `true; ${x}` },
  { id: 'after-and', wrap: (x) => `true && ${x}` },
  { id: 'after-or', wrap: (x) => `false || ${x}` },
  { id: 'after-pipe', wrap: (x) => `true | ${x}` },
  { id: 'after-background', wrap: (x) => `true & ${x}` },
  { id: 'after-newline', wrap: (x) => `true\n${x}` },
  // 2. Groupings, glued or spaced, with the closer removed.
  { id: 'subshell', wrap: (x) => `(${x})` },
  { id: 'subshell-spaced', wrap: (x) => `( ${x} )` },
  { id: 'subshell-after-cd', wrap: (x) => `( cd /tmp && ${x} )` },
  { id: 'subshell-nested', wrap: (x) => `( (${x}) )` },
  { id: 'brace-group', wrap: (x) => `{ ${x}; }` },
  { id: 'function-body', wrap: (x) => `f() { ${x}; }` },
  // 3. Shell keywords.
  { id: 'bang', wrap: (x) => `! ${x}` },
  { id: 'if-condition', wrap: (x) => `if ${x}; then true; fi` },
  { id: 'then', wrap: (x) => `if true; then ${x}; fi` },
  { id: 'elif-condition', wrap: (x) => `if false; then true; elif ${x}; then true; fi` },
  { id: 'else', wrap: (x) => `if false; then true; else ${x}; fi` },
  { id: 'while-body', wrap: (x) => `while false; do ${x}; done` },
  { id: 'until-condition', wrap: (x) => `until ${x}; do true; done` },
  { id: 'for-body', wrap: (x) => `for x in a; do ${x}; done` },
  // 4. Substitutions.
  { id: 'dollar-substitution', wrap: (x) => `echo $(${x})` },
  { id: 'backtick', wrap: (x) => `echo \`${x}\`` },
  { id: 'process-input', wrap: (x) => `cat <(${x})` },
  { id: 'process-output', wrap: (x) => `tee >(${x})` },
  { id: 'assignment-of-substitution', wrap: (x) => `OUT=$(${x} | wc -l)` },
  // 5. A shell or eval at the start of a command reads its argument again.
  { id: 'bash-c', wrap: (x) => `bash -c "${x}"` },
  { id: 'sh-c', wrap: (x) => `sh -c '${x}'` },
  { id: 'zsh-c', wrap: (x) => `zsh -c '${x}'` },
  { id: 'dash-c', wrap: (x) => `dash -c '${x}'` },
  { id: 'bash-lc', wrap: (x) => `bash -lc "${x}"` },
  { id: 'bash-euc', wrap: (x) => `bash -euc '${x}'` },
  { id: 'bash-option-before-c', wrap: (x) => `bash -o pipefail -c '${x}'` },
  { id: 'bash-by-path', wrap: (x) => `/bin/bash -c "${x}"` },
  { id: 'eval', wrap: (x) => `eval "${x}"` },
  { id: 'eval-unquoted', wrap: (x) => `eval ${x}` },
  { id: 'bash-c-eval', wrap: (x) => `bash -c "eval '${x}'"` },
  // 6. Prefixes already recognised.
  { id: 'assignment', wrap: (x) => `A=1 ${x}` },
  { id: 'rtk', wrap: (x) => `rtk ${x}` },
  { id: 'rtk-proxy', wrap: (x) => `rtk proxy ${x}` },
  { id: 'command', wrap: (x) => `command ${x}` },
  { id: 'exec', wrap: (x) => `exec ${x}` },
  { id: 'nice', wrap: (x) => `nice -n 5 ${x}` },
  { id: 'time', wrap: (x) => `time ${x}` },
  { id: 'builtin', wrap: (x) => `builtin ${x}` },
  { id: 'prefix-by-path', wrap: (x) => `/usr/bin/env ${x}` },
  // 7. Wrappers, with the shape of their arguments.
  { id: 'timeout', wrap: (x) => `timeout 5 ${x}` },
  { id: 'timeout-options', wrap: (x) => `timeout -k 2 -s KILL 5 ${x}` },
  { id: 'timeout-long-options', wrap: (x) => `timeout --signal=KILL --preserve-status 5s ${x}` },
  { id: 'nohup', wrap: (x) => `nohup ${x}` },
  { id: 'env-ignore-environment', wrap: (x) => `env -i ${x}` },
  { id: 'env-unset-and-assignment', wrap: (x) => `env -u FOO BAR=1 ${x}` },
  { id: 'env-split-string', wrap: (x) => `env -S '${x}'` },
  { id: 'xargs', wrap: (x) => `xargs ${x}` },
  { id: 'xargs-options', wrap: (x) => `xargs -0 -n 1 ${x}` },
  { id: 'xargs-glued-values', wrap: (x) => `xargs -0r -n1 -I{} ${x}` },
  { id: 'watch', wrap: (x) => `watch -n 1 ${x}` },
  { id: 'watch-quoted', wrap: (x) => `watch -n 1 '${x}'` },
  { id: 'wrapper-by-path', wrap: (x) => `/usr/bin/timeout 5 ${x}` },
  { id: 'watch-unknown-option', wrap: (x) => `watch -b '${x}'` },
  // Nestings.
  { id: 'subshell-in-then', wrap: (x) => `if true; then (${x}); fi` },
  { id: 'subshell-in-bash-c', wrap: (x) => `bash -c "(${x})"` },
  { id: 'bash-c-in-subshell', wrap: (x) => `(bash -c '${x}')` },
  { id: 'bash-c-after-timeout', wrap: (x) => `timeout 5 bash -c '${x}'` },
  { id: 'bash-c-in-for', wrap: (x) => `for x in a; do bash -c "${x}"; done` },
  { id: 'backtick-in-bash-c', wrap: (x) => `bash -c 'echo \`${x}\`'` },
  { id: 'sh-c-after-xargs', wrap: (x) => `xargs -I {} sh -c '${x}'` },
  { id: 'brace-group-in-eval', wrap: (x) => `eval '{ ${x}; }'` },
  { id: 'wrapper-in-brace-group', wrap: (x) => `{ timeout 5 ${x}; }` },
  { id: 'third-nested-reading', wrap: (x) => `bash -c "eval 'eval ${x}'"` },
  // A substitution body is read at the depth of its line, like `$( … )`.
  { id: 'fourth-nested-process-substitution', wrap: (x) => `cat <(cat <(cat <(cat <(${x}))))` },
  { id: 'substitution-in-third-nested-reading', wrap: (x) => `bash -c "eval 'eval \\"cat <(${x})\\"'"` },
];

export type CommandStartLimit = CommandStartForm & Readonly<{ reason: string; }>;

// A form whose X is not judged: the list documents each one as a known limit.
export const COMMAND_START_LIMITS: readonly CommandStartLimit[] = [
  { id: 'ssh', wrap: (x) => `ssh h '${x}'`, reason: 'a command sent to another machine is not judged: only the command on this one is' },
  {
    id: 'limactl-shell',
    wrap: (x) => `limactl shell vm -- bash -c '${x}'`,
    reason: 'a command run in a virtual machine is not judged: bash is an argument of limactl, not the start of a command',
  },
  {
    id: 'docker-exec',
    wrap: (x) => `docker exec c sh -c '${x}'`,
    reason: 'a command run in a container is not judged: sh is an argument of docker, not the start of a command',
  },
  {
    id: 'case-pattern',
    wrap: (x) => `case x in a) ${x};; esac`,
    reason: 'a case pattern is not read as a command start: the command after `a)` is not judged',
  },
  {
    id: 'fourth-nested-reading',
    wrap: (x) => `bash -c "eval 'eval \\"eval ${x}\\"'"`,
    reason: 'a command line is read again three levels deep at most: the fourth eval argument is not read',
  },
];

export type CommandStartFamily = Readonly<{
  id: string;
  command: string;
  // The verdict of the command on its own, and of every form that starts it.
  expected: readonly ExpectedVerdict[];
  // Forms where another reading answers instead, with the reason in a comment.
  exceptions?: Readonly<Record<string, readonly ExpectedVerdict[]>>;
  // Whether the known limits are replayed on the family: a command that is
  // allowed on its own has no limit to show.
  limits: boolean;
}>;

const GIT_PROTECTED: readonly ExpectedVerdict[] = [{ verdict: 'confirm', ruleId: 'git-protected' }];
const SUDO: readonly ExpectedVerdict[] = [{ verdict: 'block', ruleId: 'sudo' }];
const RM_RF_DANGEROUS: readonly ExpectedVerdict[] = [{ verdict: 'block', ruleId: 'rm-rf-dangerous' }];
const GIT_CONFIG_EXEC: readonly ExpectedVerdict[] = [{ verdict: 'confirm', ruleId: 'git-config-exec' }];
const XARGS_DESTRUCTIVE: readonly ExpectedVerdict[] = [{ verdict: 'confirm', ruleId: 'xargs-destructive' }];

export const COMMAND_START_FAMILIES: readonly CommandStartFamily[] = [
  {
    id: 'git-push',
    command: 'git push',
    expected: GIT_PROTECTED,
    // The `xargs-destructive` row of the Bash table, read before git, asks
    // first for `xargs … git push`.
    exceptions: { xargs: XARGS_DESTRUCTIVE, 'xargs-options': XARGS_DESTRUCTIVE, 'xargs-glued-values': XARGS_DESTRUCTIVE },
    limits: true,
  },
  { id: 'sudo', command: 'sudo ls', expected: SUDO, limits: true },
  {
    id: 'rm-rf',
    command: 'rm -rf /',
    expected: RM_RF_DANGEROUS,
    // The rm -rf rule also reads every `rm` word of the line, wherever it
    // stands, so the case pattern does not hide it.
    exceptions: { 'case-pattern': RM_RF_DANGEROUS },
    limits: true,
  },
  {
    id: 'git-status',
    command: 'git status',
    expected: [],
    // A variable written in front of git that git-config-exec does not list;
    // an option watch does not list, which asks whatever the command.
    exceptions: {
      assignment: GIT_CONFIG_EXEC,
      'env-unset-and-assignment': GIT_CONFIG_EXEC,
      'watch-unknown-option': GIT_PROTECTED,
    },
    limits: false,
  },
];

// Commands that do not fit a form around X, and malformed lines.
const LITERAL_CASES: readonly FixtureCase[] = [
  bashCase('literal-assignment-of-substitution-is-not-a-prefix', 'STRAY=$(rtk git status --short | wc -l)', []),
  bashCase('literal-for-body-reads-a-safe-subcommand', 'for f in a b; do git log -1 "$f"; done', []),
  // An assignment written before a shell reaches the environment of every
  // command the shell runs, the substitutions of its line included; one
  // written before a command does not reach that command's own substitutions.
  bashCase('literal-assignment-before-bash-c', 'GIT_SSH_COMMAND=x bash -c \'git fetch\'', GIT_CONFIG_EXEC),
  bashCase('literal-assignment-before-eval', 'GIT_SSH_COMMAND=x eval \'git fetch\'', GIT_CONFIG_EXEC),
  bashCase('literal-listed-assignment-before-bash-c', 'LC_ALL=C bash -c \'git status\'', []),
  bashCase('literal-env-assignment-before-bash-c', 'env GIT_SSH_COMMAND=x bash -c \'git fetch\'', GIT_CONFIG_EXEC),
  bashCase('literal-assignment-before-env-split-string', 'GIT_SSH_COMMAND=x env -S \'git fetch\'', GIT_CONFIG_EXEC),
  bashCase('literal-assignment-before-watch', 'GIT_SSH_COMMAND=x watch \'git fetch\'', GIT_CONFIG_EXEC),
  bashCase('literal-assignment-reaches-substitution-in-bash-c', 'GIT_SSH_COMMAND=x bash -c \'echo $(git fetch)\'', GIT_CONFIG_EXEC),
  bashCase('literal-assignment-misses-own-substitution', 'GIT_SSH_COMMAND=x echo $(git fetch)', []),
  // A prefix or a wrapper is recognised by its name, also started by a path.
  bashCase('literal-env-by-path-before-bash-c', '/usr/bin/env bash -c \'sudo ls\'', SUDO),
  bashCase('literal-xargs-by-path', '/usr/bin/xargs sudo ls', SUDO),
  {
    ...bashCase('literal-dynamic-shell-command', 'cmd="git push"; bash -c "$cmd"', []),
    knownLimit: true,
    knownLimitReason: 'the argument of bash -c is a variable: the command it names is only known when the shell runs',
  },
  {
    ...bashCase('literal-xargs-stdin-arguments', 'echo -D | xargs git branch x', []),
    knownLimit: true,
    knownLimitReason: 'xargs adds the words it reads on standard input: `git branch x` is judged without the -D',
  },
  {
    // Each segment is read through the prefixes alone first, a reading that
    // takes the glued `)` for part of the subcommand, which no grammar allows.
    ...bashCase('literal-glued-closer-keeps-the-segment-reading', '(cd /tmp && git status)', GIT_PROTECTED),
    knownLimit: true,
    knownLimitReason: 'the segment reading, kept so that no verdict loosens, reads `status)` as an unknown git subcommand',
  },
  // A heredoc body is the input of a command, not a command line.
  bashCase('literal-quoted-heredoc-body-is-data', 'cat <<\'EOF\'\nRun `sudo ls`, then (git push)\nif git push fails\nEOF', []),
  // The apostrophe hides the end of the substitution from the tokenizer.
  bashCase(
    'literal-heredoc-in-substitution-is-data',
    'git commit -m "$(cat <<\'EOF\'\nfix: it\'s `sudo ls`, then `git push`\nEOF\n)"',
    [],
  ),
  // bash reads an unclosed heredoc body to the end of its input.
  bashCase('literal-unclosed-heredoc-body-is-data', 'cat <<\'EOF\'\nsee `sudo ls`', []),
  // A redirection with the subshell's closer glued to it still names its file.
  bashCase('literal-glued-closer-after-redirection', '(git ls-files | xargs git grep -l x 2>/dev/null)', []),
  {
    ...bashCase('literal-unquoted-heredoc-substitution', 'cat <<EOF\n`git push`\nEOF', []),
    knownLimit: true,
    knownLimitReason:
      'bash runs a backtick in an unquoted heredoc body; heredoc bodies keep the segment reading, which does not read substitutions',
  },
  // Malformed lines get a verdict.
  bashCase('literal-unclosed-quote-in-bash-c', 'bash -c "git push', GIT_PROTECTED),
  bashCase('literal-bash-c-without-argument', 'bash -c', []),
  bashCase('literal-bash-c-empty-argument', 'bash -c \'\'', []),
  bashCase('literal-eval-without-argument', 'eval', []),
  bashCase('literal-env-split-string-without-value', 'env -S', []),
  bashCase('literal-timeout-without-duration', 'timeout', []),
  bashCase('literal-xargs-option-without-value', 'xargs -n', []),
  bashCase('literal-watch-without-command', 'watch', []),
  bashCase('literal-lone-opening-parenthesis', '(', []),
  bashCase('literal-empty-brace-group', '{ }', []),
  bashCase('literal-lone-backtick', 'echo `', []),
  bashCase('literal-unclosed-backtick', 'echo `git push', GIT_PROTECTED),
  bashCase('literal-lone-process-substitution', 'cat <(', []),
  bashCase('literal-unclosed-process-substitution', 'cat <(git push', GIT_PROTECTED),
  // A command line is read again three levels down at most.
  bashCase('literal-third-eval', 'eval eval eval git push', GIT_PROTECTED),
  {
    ...bashCase('literal-fourth-eval', 'eval eval eval eval git push', []),
    knownLimit: true,
    knownLimitReason: 'a command line is read again three levels deep at most: the fourth eval argument is not read',
  },
];

function bashCase(id: string, command: string, expected: readonly ExpectedVerdict[]): FixtureCase {
  return { id: `${COMMAND_START_CASE_PREFIX}${id}`, toolName: 'Bash', toolInput: { command }, expected };
}

/** The `command-start-*` cases of fixtures/command.json, in order. */
export function commandStartCases(): FixtureCase[] {
  const cases: FixtureCase[] = [];
  for (const family of COMMAND_START_FAMILIES) {
    for (const form of COMMAND_START_FORMS) {
      cases.push(bashCase(`${family.id}-${form.id}`, form.wrap(family.command), family.exceptions?.[form.id] ?? family.expected));
    }
    if (!family.limits) continue;
    for (const limit of COMMAND_START_LIMITS) {
      const exception = family.exceptions?.[limit.id];
      const fixture = bashCase(`${family.id}-${limit.id}`, limit.wrap(family.command), exception ?? []);
      cases.push(exception === undefined ? { ...fixture, knownLimit: true, knownLimitReason: limit.reason } : fixture);
    }
  }
  return [...cases, ...LITERAL_CASES];
}

const COMMAND_FIXTURES = join(import.meta.dir, '..', 'fixtures', 'command.json');

// Rewrites fixtures/command.json: every other case keeps its place, the
// `command-start-*` cases are replaced by the current list, at the end.
function writeCommandStartCases(): void {
  const file = JSON.parse(readFileSync(COMMAND_FIXTURES, 'utf8')) as FixtureFile;
  const others = file.cases.filter((fixture) => !fixture.id.startsWith(COMMAND_START_CASE_PREFIX));
  writeFileSync(COMMAND_FIXTURES, `${JSON.stringify({ ...file, cases: [...others, ...commandStartCases()] }, null, 2)}\n`);
}

if (import.meta.main) writeCommandStartCases();
