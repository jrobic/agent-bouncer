// Shared regex fragments of the baseline `secret.bash` rows (ticket 57).
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

// The opening of `sh -c`, `bash -c`, … up to the quote or the command.
const SHELL_C = String.raw`\b(?:ba|z|da|k)?sh[ \t]+(?:-[a-zA-Z]+[ \t]+)*-[a-zA-Z]*c[ \t]+`;

// Where a command may start: the start of the text; `;` `&` newline `{`
// backtick `$(` `<(` `>(`; a pipe preceded by whitespace (so `a|env` inside a
// search pattern is not a pipeline); `then` `do` …; the opening of `sh -c` —
// then the wrappers a command may sit behind: `VAR=value` `rtk` `command`
// `exec` `nice` `time` `builtin` `proxy` `eval`.
const COMMAND_POSITION = String
  .raw`(?:^|[;&\n{\x60]|\$\(|[<>]\(|[ \t]\|\|?|\b(?:then|do|else|elif|if|while|until)[ \t]|${SHELL_C}["\x27]?)[ \t]*(?:(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()<>]*|rtk|command|exec|nice|time|builtin|proxy|eval)[ \t]+)*`;

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
  'shell-c': SHELL_C,
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
