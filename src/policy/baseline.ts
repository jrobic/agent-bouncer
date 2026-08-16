// The embedded baseline: a STATIC import, resolved and bundled at build
// time (`bun build --compile` inlines the parsed TOML into the compiled
// binary — there is no on-disk file to find at runtime for this one). This
// is deliberately separate from the overlay, which is read from disk at
// runtime (see load.ts) — the baseline can never be missing or unreadable,
// which is exactly the property that makes "fall back to baseline" a safe
// fail-closed default.

import baselineData from '../../policy/baseline.toml';
import type { RawPolicyFile } from './schema.ts';

const raw = baselineData as unknown as RawPolicyFile;

// `config_read_modes` is the single source of truth for "this is a git
// config READ" — shared with the git `safe_first_arg` entry for
// `sub = "config"`, which by definition needs the exact same values (both
// answer the same question: which git-config invocation forms only read).
// Rather than a second literal copy of the same eight strings elsewhere in
// policy/baseline.toml, that entry's `values` is left empty in TOML and
// filled in here, once, at load time.
function withConfigValuesFilledIn(rules: RawPolicyFile['rules']): RawPolicyFile['rules'] {
  return {
    ...rules,
    command: {
      ...rules.command,
      git: {
        ...rules.command.git,
        safe_first_arg: rules.command.git.safe_first_arg.map((r) =>
          r.sub === 'config' && r.values.length === 0
            ? { ...r, values: rules.command.git.config_read_modes }
            : r
        ),
      },
    },
  };
}

export const BASELINE: RawPolicyFile = { ...raw, rules: withConfigValuesFilledIn(raw.rules) };
