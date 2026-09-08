// The one name this binary calls itself by — used for the audit log
// filename, stderr diagnostics, and CLI error messages. A single exported
// constant so all three can never drift apart.
export const HOOK_NAME = 'bouncer';

// Review round 1 S-4: the one v1-wiring default (ADR-0006 § 9) — every
// subcommand that takes an optional `--harness <id>` falls back to this
// when the flag is absent. A single exported constant so it can never
// drift between src/adapter/run.ts and src/cli-commands.ts (it did,
// briefly, as two independently-declared local consts of the same
// value), and so a bare `'claude-code'` literal checking "is this the
// default harness" (src/adapter/codecs/hook-file.ts) reads the same name.
export const DEFAULT_HARNESS_ID = 'claude-code';
