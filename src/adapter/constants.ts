// The one name this binary calls itself by — used for the audit log
// filename, stderr diagnostics, and CLI error messages. A single exported
// constant so all three can never drift apart.
export const HOOK_NAME = 'bouncer';
