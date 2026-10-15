// The protected-variable-name definition — ONE place.
// Pure: no Bun/Node APIs, no harness shapes, like the other rule modules.
//
// A name is protected when it is uppercase and equals, or ends in `_` plus,
// one of the suffixes below. The suffix must END the name: `MY_TOKEN_FILE`,
// `TOKENIZER_PATH` and `SECRET_KEY` are not protected, `NODE_ENV`, `HOME`
// and any lowercase name are not either. No client-specific list and no
// per-layer declaration: the definition is baseline, public and universal.
//
// Everything that needs to recognise a protected name reads it from here, so
// two definitions can never drift apart:
//   - the baseline `secret.bash` reference rows write `{{protected-name}}` in
//     their regex, after the `{{env-reference}}` forms (both are fragments of
//     src/policy/fragments.ts, filled in once at load time by
//     src/policy/baseline.ts; docs/reference/policy.md, "The environment
//     rows");
//   - code that holds a name as a string asks isProtectedName().

export const PROTECTED_NAME_SUFFIXES = [
  'TOKEN',
  'PASSWORD',
  'PASSWD',
  'SECRET',
  'API_KEY',
  'APIKEY',
  'PRIVATE_KEY',
  'ACCESS_KEY',
  'CREDENTIALS',
] as const;

/**
 * The regex SOURCE of one protected name: neither anchored nor flagged, so a
 * row can embed it between its own boundaries (`\$\{?<name>\b`).
 */
export const PROTECTED_NAME_SOURCE = `(?:[A-Z0-9_]*_)?(?:${PROTECTED_NAME_SUFFIXES.join('|')})`;

const PROTECTED_NAME = new RegExp(`^${PROTECTED_NAME_SOURCE}$`);

/** Whether `name` — a whole variable name, nothing around it — is protected. */
export function isProtectedName(name: string): boolean {
  return PROTECTED_NAME.test(name);
}

/**
 * The protected names an environment holds — what a caller deletes to hand a
 * child, or the rest of a process, an environment without them (the test
 * preload, the protocol capture script).
 */
export function protectedNamesIn(env: Readonly<Record<string, unknown>>): string[] {
  return Object.keys(env).filter(isProtectedName);
}
