// Which form decides a git subcommand. The one place that builds the set of
// subcommands a conditional rule governs, so every reader of that set sees
// the same one.

import type { CommandGitPolicy, GitConditionalTable } from './schema.ts';

/** What decides a subcommand once `safe_subcommands` is set aside: a declarative table, or the engine's own code. */
export type GitGoverningForm = GitConditionalTable | 'engine';

/**
 * Every subcommand a conditional rule decides (rather than the catch-all),
 * with the form that decides it — the first in the evaluation order of
 * gitSubcommandNeedsConfirm (src/command-rules.ts). `checkout` and `restore`
 * are the engine's own code. `safe_subcommands` is not included.
 */
export function gitGoverningForms(git: CommandGitPolicy): ReadonlyMap<string, GitGoverningForm> {
  const forms = new Map<string, GitGoverningForm>();
  const claim = (subs: readonly string[], form: GitGoverningForm): void => {
    for (const sub of subs) if (!forms.has(sub)) forms.set(sub, form);
  };
  claim(git.ask_flags.map((r) => r.sub), 'ask_flags');
  claim(git.safe_first_arg.map((r) => r.sub), 'safe_first_arg');
  claim(git.safe_grammar.map((r) => r.sub), 'safe_grammar');
  claim(git.safe_flags.map((r) => r.sub), 'safe_flags');
  claim(['checkout', 'restore'], 'engine');
  return forms;
}
