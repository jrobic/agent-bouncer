// Shared regex fragments of the baseline `secret.bash` rows.
// Pure: no Bun/Node APIs, no harness shapes.
//
// A baseline row spells a fragment `{{name}}` in its `regex` or `except`;
// src/policy/baseline.ts fills it in ONCE at load time (same precedent as the
// git `config_read_modes` list), so what a rule matches is written once and
// `bouncer rules list`, the frozen digest and the engine all see the expanded
// regex. Rows that repeat a long alternation (the reference forms, the
// command-position lead-in, jq's builtin) share it instead of copying it.
//
// Placeholders belong to the BASELINE: an overlay row writes its own whole
// regex (layers add rows, never data into a row) and lint rejects a `{{…}}`
// there; a placeholder that survives the fill in the baseline itself is a
// typo that would silently disable its rule, so the baseline refuses to load.

import { PROTECTED_NAME_SOURCE } from '../protected-names.ts';

/** How a placeholder looks — any `{{…}}` — for the load guard and for lint. */
export const FRAGMENT_PLACEHOLDER = /\{\{[^{}]*\}\}/;
const FRAGMENT_PLACEHOLDER_GLOBAL = /\{\{([^{}]*)\}\}/g;

// A word the lead-in reads (an option value, an assignment value) holds at
// most 256 characters: a `{` or a backtick inside a word starts a command of
// its own, so a word without a bound would be scanned again from each of
// them. A quoted value stays unbounded: it closes at the next quote of its
// kind, so no two starts scan the same quoted span.
const WORD_CHAR = String.raw`[^\s;&|()<>]`;
const COMMAND_WORD = `${WORD_CHAR}{1,256}`;
// The first 257 characters of a word past that bound.
const LONG_WORD = `${WORD_CHAR}{257}`;
const COMMAND_PATH = String.raw`(?:[\w./~-]*/)?`;
// An assignment option of env (and of `env -S`): a value that opens with a
// quote is that quoted string alone, so one word is never read two ways.
const COMMAND_ASSIGNMENT = String
  .raw`[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\x27[^\x27]*\x27|[^\s;&|()<>"\x27]${WORD_CHAR}{0,255})?`;
// An assignment written before a command: one word, quotes included.
const PREFIX_ASSIGNMENT = String.raw`[A-Za-z_][A-Za-z0-9_]*=${WORD_CHAR}{0,256}`;
const QUOTE = String.raw`["\x27]`;

// The options of env. As a wrapper, env reads its assignments after its
// options (`env -i A=1 cmd`), and those are the assignment prefixes of the
// wrapper sequence, so each word has one reading.
const ENV_OPTION = String
  .raw`(?:-[i0v]+|--(?:ignore-environment|null|debug)|-u[ \t]*${COMMAND_WORD}|--unset(?:=|[ \t]+)${COMMAND_WORD}|-C[ \t]*${COMMAND_WORD}|--chdir(?:=|[ \t]+)${COMMAND_WORD}|--)`;
// The wrapper and command names below follow one COMMAND_PATH that their
// group reads once, so a failed start costs one scan of the word, not one
// per name. The env wrapper and `env -S` share one reading of env's options.
// A wrapper's options are each read with the blank after them: a word cut
// short then fails inside its own option, instead of ending the run and
// trying what follows it once per shorter length of each word.
const ENV_HEAD = String.raw`env[ \t]+(?:${ENV_OPTION}[ \t]+){0,8}`;
const ENV_SPLIT = String.raw`(?:-S|--split-string)(?:=|[ \t]+)`;

// A leading hyphen is an option, never a timeout duration.
const TIMEOUT_DURATION = String.raw`[^\s;&|()<>-]${WORD_CHAR}{0,255}`;
const TIMEOUT_OPTION = String
  .raw`(?:-k(?:${TIMEOUT_DURATION}|[ \t]+${TIMEOUT_DURATION})|--kill-after(?:=${TIMEOUT_DURATION}|[ \t]+${TIMEOUT_DURATION})|-s(?:${COMMAND_WORD}|[ \t]+${COMMAND_WORD})|--signal(?:=${COMMAND_WORD}|[ \t]+${COMMAND_WORD})|--foreground|--preserve-status)`;
const XARGS_OPTION = String
  .raw`(?:--(?:null|no-run-if-empty|verbose)|--(?:max-args|max-procs|max-chars|delimiter)(?:=${COMMAND_WORD}|[ \t]+${COMMAND_WORD})|--(?:replace|max-lines|eof)(?:=${COMMAND_WORD})?|-[0rt]+|-(?:[0rt]*)(?:n|I|P|L|d|E|s)(?:${COMMAND_WORD}|[ \t]+${COMMAND_WORD}))`;
const WATCH_OPTION = String
  .raw`(?:--(?:no-title|exec|color|chgexit|errexit|precise)|--(?:interval)(?:=${COMMAND_WORD}|[ \t]+${COMMAND_WORD})|--differences(?:=${COMMAND_WORD})?|-[dtxcgep]+|-n(?:${COMMAND_WORD}|[ \t]+${COMMAND_WORD})|--)`;
const UNKNOWN_WRAPPER_OPTION = String.raw`[ \t]+-${COMMAND_WORD}[ \t]+(?:${COMMAND_WORD}[ \t]+){0,8}`;

// Prefixes and wrappers that run the words after their own arguments, and
// never open a quote. Every run in this lead-in is bounded (eight
// prefixes and wrappers, eight options each, 256 characters a word): a run
// without a bound is read again from each command start inside it (a `{` or
// a backtick in a value, a `-sh` option), so a long line would go quadratic.
const PLAIN_WRAPPER_NAME = String
  .raw`(?:rtk(?:[ \t]+proxy)?[ \t]+|(?:command|exec|builtin|proxy)[ \t]+|nice[ \t]+(?:-n(?:${COMMAND_WORD}|[ \t]+${COMMAND_WORD})[ \t]+)?|time(?:[ \t]+-p)?[ \t]+|nohup[ \t]+|timeout[ \t]+(?:${TIMEOUT_OPTION}[ \t]+){0,8}${TIMEOUT_DURATION}[ \t]+|xargs[ \t]+(?:${XARGS_OPTION}[ \t]+){0,8}(?:--[ \t]+)?)`;
// Wrappers that read their argument again as a command line (`eval`,
// `env -S`, `watch`), up to the quote that may open that argument.
const WATCH_HEAD = String.raw`watch[ \t]+(?:${WATCH_OPTION}[ \t]+){0,8}`;
const REREAD_WRAPPER_NAME = String.raw`(?:eval[ \t]+|${ENV_HEAD}${ENV_SPLIT}|${WATCH_HEAD})`;
// After an option it does not list, the words of timeout, xargs or watch are
// read up to the command; this single fallback ends the wrapper sequence.
const UNKNOWN_WRAPPER_NAME = String.raw`(?:timeout|xargs|watch)${UNKNOWN_WRAPPER_OPTION}`;
// env runs a command next (`\b` replaces the unsupported look-ahead with a
// zero-width word boundary), or reads its `-S` string.
const COMMAND_WRAPPER = String
  .raw`(?:![ \t]+|${PREFIX_ASSIGNMENT}[ \t]+|${COMMAND_PATH}(?:${PLAIN_WRAPPER_NAME}|${ENV_HEAD}(?:${COMMAND_PATH}\b|${ENV_SPLIT}${QUOTE}?)|(?:eval[ \t]+|${WATCH_HEAD})${QUOTE}?))`;
// Up to eight `(` open the command. A `{` needs no place here: it already
// starts a command of its own (COMMAND_HEAD), and leaving it out keeps a run
// of braces from being retried at every brace.
const GROUPING = String.raw`(?:\([ \t]*){0,8}`;
const COMMAND_WRAPPER_SEQUENCE = String
  .raw`${GROUPING}(?:${COMMAND_WRAPPER}){0,8}(?:${COMMAND_PATH}${UNKNOWN_WRAPPER_NAME}${QUOTE}?)?`;

// Ordinary commands start at COMMAND_HEAD. The environment lead-in also
// reads the argument of every shell `-c`, wherever it stands (local
// launchers and container commands included).
const COMMAND_HEAD = String.raw`(?:^|[;\n{\x60]|\$\(|[<>]\(|[ \t]\|\|?|\b(?:then|do|else|elif|if|while|until)[ \t]|&&?)`;
// `\b` anchors the shell name at the start of a word, a path prefix ending
// just before it (`/bin/bash`). Only `-o`/`-O`, `--rcfile` and `--init-file`
// take a value, and a value never starts with `-`, so every option word is
// read one way. Up to eight options: `-sh` is itself a shell name, so an
// unbounded run would be read again from each one.
const SHELL_OPTION_VALUE = String.raw`[^\s;&|()<>-]${WORD_CHAR}{0,255}`;
const SHELL_OPTION = String
  .raw`(?:--(?:rcfile|init-file)[ \t]+${SHELL_OPTION_VALUE}|-[a-zA-Z]*[oO][ \t]+${SHELL_OPTION_VALUE}|-[a-zA-Z]+)`;
const SHELL_NAME = String.raw`\b(?:ba|z|da|k)?sh`;
const SHELL_C = String.raw`${SHELL_NAME}[ \t]+(?:${SHELL_OPTION}[ \t]+){0,8}-[a-zA-Z]*c[ \t]+`;

const COMMAND_POSITION = String
  .raw`(?:${COMMAND_HEAD}[ \t]*|${SHELL_C}(?:${QUOTE}[ \t]*)?)${COMMAND_WRAPPER_SEQUENCE}[ \t]*`;
// The last wrapper of a command position, when it is `eval`, `env -S`,
// `watch` or the unknown-option fallback and opens a quote: a command read
// inside that quote may end at the closing quote.
const REREAD_OPEN = String
  .raw`${COMMAND_PATH}(?:${REREAD_WRAPPER_NAME}|${UNKNOWN_WRAPPER_NAME})${QUOTE}[ \t]*${COMMAND_WRAPPER_SEQUENCE}`;
// The quoted argument of a shell `-c`, wherever the shell stands: a command
// read inside it ends at the closing quote, whatever follows the quote
// (`sh -c 'env' arg0` sets `$0`).
const SHELL_C_OPEN = String.raw`${SHELL_C}${QUOTE}[ \t]*${COMMAND_WRAPPER_SEQUENCE}`;

// A value past the 256-character bound, where the lead-in reads one: an
// assignment before a command (a blank follows the value, or a `{` or a
// backtick the bound kept from being read; a lone assignment runs nothing),
// an option value or an assignment of env, an option value or the duration
// of timeout, an option value of xargs, watch or nice.
const LONG_PREFIX_VALUE = String.raw`[A-Za-z_][A-Za-z0-9_]*=${LONG_WORD}[^\s;&|()<>{\x60]*[ \t{\x60]`;
const LONG_OPTION_VALUE = String
  .raw`(?:env[ \t]+(?:(?:${ENV_OPTION}|${COMMAND_ASSIGNMENT})[ \t]+){0,8}(?:-[uC][ \t]*|--(?:unset|chdir)(?:=|[ \t]+)|(?:${ENV_SPLIT}${QUOTE}(?:${COMMAND_ASSIGNMENT}[ \t]+){0,7})?[A-Za-z_][A-Za-z0-9_]*=)|timeout[ \t]+(?:${TIMEOUT_OPTION}[ \t]+){0,8}(?:-[ks][ \t]*|--(?:kill-after|signal)(?:=|[ \t]+))?|xargs[ \t]+(?:${XARGS_OPTION}[ \t]+){0,8}(?:-[0rt]*[nIPLdEs][ \t]*|--(?:max-args|max-procs|max-chars|delimiter)(?:=|[ \t]+)|--(?:replace|max-lines|eof)=)|watch[ \t]+(?:${WATCH_OPTION}[ \t]+){0,8}(?:-n[ \t]*|--interval(?:=|[ \t]+)|--differences=)|nice[ \t]+-n[ \t]*)${LONG_WORD}`;

// Where the lead-in stops reading: at a command position, a ninth prefix or
// wrapper, a ninth option of env, timeout, xargs or watch, or a value past
// its bound; anywhere, a ninth option of a shell or an option value past its
// bound. The rows above cannot judge the command behind it. Each count is
// bounded at nine and each value read at 257 characters, so a long run costs
// a bounded number of steps per start.
const UNJUDGED_COMMAND = String
  .raw`(?:(?:${COMMAND_HEAD}[ \t]*|${SHELL_C}(?:${QUOTE}[ \t]*)?)${GROUPING}(?:(?:${COMMAND_WRAPPER}){9}|(?:${COMMAND_WRAPPER}){0,8}(?:${COMMAND_PATH}(?:env(?:[ \t]+(?:${ENV_OPTION}|${COMMAND_ASSIGNMENT})){9}|timeout(?:[ \t]+${TIMEOUT_OPTION}){9}|xargs(?:[ \t]+${XARGS_OPTION}){9}|watch(?:[ \t]+${WATCH_OPTION}){9}|${LONG_OPTION_VALUE})|${LONG_PREFIX_VALUE}))|${SHELL_NAME}(?:(?:[ \t]+${SHELL_OPTION}){9}|[ \t]+(?:${SHELL_OPTION}[ \t]+){0,8}(?:--(?:rcfile|init-file)|-[a-zA-Z]*[oO])[ \t]+${LONG_WORD}))`;

// The commands that print the whole environment, and the end of such a
// command. A lone `}` is not an end: `{ env }` passes `}` to env as a command.
// The options of env stay bounded: a value (`-u NAME`, `VAR=x`) may hold a
// `{` or a backtick, which start a command.
// No bound on the printenv/export/declare flag runs: each flag reads one way and holds no command start, so the match stays linear.
const ENV_DUMP_COMMAND = String
  .raw`(?:${COMMAND_PATH}(?:env(?:(?:[ \t]+(?:${ENV_OPTION}|${COMMAND_ASSIGNMENT})){0,8}|[ \t]+(?:-S|--split-string)(?:=|[ \t]+)${QUOTE}(?:${COMMAND_ASSIGNMENT}(?:[ \t]+${COMMAND_ASSIGNMENT}){0,7})?${QUOTE})|printenv(?:[ \t]+(?:-0|--null))*)|export(?:[ \t]+-p)*|(?:declare|typeset)(?:[ \t]+-[a-oq-wyzA-Z]*[xp][a-zA-Z]*)*|set)[ \t]*`;
const ENV_DUMP_END = String.raw`(?:$|[;&|)\x60\n#<>]|\d[<>])`;

// A line handed whole to another machine: `ssh` or `limactl shell`, then a
// blank, and no character that the local shell would expand or use to start
// another local command (`$`, a backtick, `<`, `>`, `;`, `&`, `|`, a newline).
// Nor the word `command` in any letter case: the ssh options `ProxyCommand`
// and `LocalCommand` run a command on this machine, and every spelling of them
// holds that word. The dialect has no look-ahead, so the line is read as
// characters other than `c`, and runs that start at a `c` and stop before
// `command` is complete (no `c` inside `ommand` can restart it, so each run
// reads one way).
// A line character that is none of `letters`.
const lineCharBut = (letters: string): string => String.raw`[^$\x60<>;&|\n${letters}]`;
// The letters of `ommand`, the rest of the word after its `c`. SHORT: begun
// and not finished. BROKEN: begun, then a character that neither continues
// it nor is a `c`.
const OMMAND = ['Oo', 'Mm', 'Mm', 'Aa', 'Nn'] as const;
const OMMAND_SHORT = OMMAND.reduceRight((rest: string, letter) => `(?:[${letter}]${rest})?`, '');
const OMMAND_BROKEN = OMMAND.reduceRight(
  (rest: string, letter) => `(?:${lineCharBut(`Cc${letter}`)}|[${letter}]${rest})`,
  lineCharBut('CcDd'),
);
const REMOTE_LINE_TEXT = `(?:${lineCharBut('Cc')}|(?:[Cc]${OMMAND_SHORT})*[Cc]${OMMAND_BROKEN})*(?:[Cc]${OMMAND_SHORT})*`;
const REMOTE_COMMAND_LINE = String.raw`^[ \t]*(?:ssh|limactl[ \t]+shell)[ \t]${REMOTE_LINE_TEXT}$`;

// The environment OBJECT in the languages that have one, and the CALLS that
// read one variable by name. `os.getenv` and `os.Getenv` are not listed: the
// generic `getenv` alternative already covers them, `\b` falling between the
// dot and the `g`.
const ENV_OBJECT = String.raw`(?:process\.env|Bun\.env|os\.environ|ENV|ENVIRON)`;
const ENV_CALL = String
  .raw`(?:os\.environ\.(?:get|pop|setdefault)|environ\.get|[Gg]et_?[Ee]nv|Deno\.env\.get|ENV\.(?:fetch|dig)|env::var(?:_os)?)`;

// Everything a reference to ONE variable spells BEFORE its name: `$` `${`,
// `process.env.` `process.env?.`, a subscript with a quoted name, a call with
// a quoted name (the quotes may be backslash-escaped inside a shell string).
const ENV_REFERENCE = String
  .raw`(?:\$\{?|\b(?:process\.env|Bun\.env)\??\.|\b${ENV_OBJECT}[ \t]*\??\.?\[[ \t]*\\{0,3}["\x27]|\b${ENV_CALL}[ \t]*\([ \t]*\\{0,3}["\x27])`;

// jq: the lead-in up to a candidate `env` (quoted strings are skipped whole,
// so a `|` inside the program is fine and a `|` outside it ends the scan; at
// most 200 units), and the builtin itself — `env` or `$ENV` followed by the
// end, a quote, a pipe, a bracket, a space, or a `.` that is not a field.
const JQ_LEAD = String.raw`\b(?:go)?jq\b(?:[^;&|\n"\x27]|\x27[^\x27]*\x27|"[^"]*"){0,200}`;
const JQ_ENV = String.raw`(?:env|\$ENV)(?:$|["\x27|)\]\[ \t]|\.[^A-Za-z_])`;

/** name → regex source. The names are the `{{name}}` a baseline row writes. */
export const FRAGMENTS: Readonly<Record<string, string>> = {
  'protected-name': PROTECTED_NAME_SOURCE,
  'command-position': COMMAND_POSITION,
  'reread-open': REREAD_OPEN,
  'shell-c-open': SHELL_C_OPEN,
  'env-dump-command': ENV_DUMP_COMMAND,
  'env-dump-end': ENV_DUMP_END,
  'remote-command-line': REMOTE_COMMAND_LINE,
  'unjudged-command': UNJUDGED_COMMAND,
  'env-object': ENV_OBJECT,
  'env-call': ENV_CALL,
  'env-reference': ENV_REFERENCE,
  'jq-lead': JQ_LEAD,
  'jq-env': JQ_ENV,
};

/** Fills every known `{{name}}`; an unknown one is left in place for the load guard. */
export function fillFragments(text: string): string {
  return text.replaceAll(
    FRAGMENT_PLACEHOLDER_GLOBAL,
    (placeholder, name: string) => (Object.hasOwn(FRAGMENTS, name) ? FRAGMENTS[name]! : placeholder),
  );
}
