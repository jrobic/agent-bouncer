// The embedded baseline: five STATIC imports, one per rule family
// (policy/command.toml, secret.toml, mcp-write.toml, write-secret.toml,
// prompt.toml — split from one ~500-line policy/baseline.toml for
// review/diff visibility, ticket 12), merged at build time into the same
// shape a single file used to produce. `bun build --compile` inlines all
// five parsed TOML files into the compiled binary — there is no on-disk
// file to find at runtime for any of them. This is deliberately separate
// from the overlay, which is read from disk at runtime (see load.ts) —
// the baseline can never be missing or unreadable, which is exactly the
// property that makes "fall back to baseline" a safe fail-closed default.
//
// Each family file's TOML header is `[[rules.<family>...]]`, so parsing
// it alone yields an object shaped `{ rules: { <family>: ... } }` — every
// family owns a DISTINCT top-level key under `rules` (command / secret /
// mcp_write / write_secret / prompt), so merging the five is a single
// shallow spread, not a deep merge: no two files ever contribute to the
// same key.

import commandData from '../../policy/command.toml';
import mcpWriteData from '../../policy/mcp-write.toml';
import promptData from '../../policy/prompt.toml';
import secretData from '../../policy/secret.toml';
import writeSecretData from '../../policy/write-secret.toml';
import type { RawPolicyFile, RulesPolicy } from './schema.ts';

// One typed interface per family file, each `Pick`-ing only the ONE key
// under `rules` that family owns. Cast at the import boundary (where each
// data value's shape genuinely IS that one family, TOML's untyped `unknown`
// import notwithstanding) instead of at the end of the spread — the spread
// below is then structurally a complete RulesPolicy on its own (one Pick
// per key, no more no less), so dropping a family from the spread becomes
// a real tsc error (a missing property) instead of a silently-accepted
// `as RulesPolicy` cast papering over the gap.
interface CommandFamilyFile {
  readonly rules: Pick<RulesPolicy, 'command'>;
}
interface SecretFamilyFile {
  readonly rules: Pick<RulesPolicy, 'secret'>;
}
interface McpWriteFamilyFile {
  readonly rules: Pick<RulesPolicy, 'mcp_write'>;
}
interface WriteSecretFamilyFile {
  readonly rules: Pick<RulesPolicy, 'write_secret'>;
}
interface PromptFamilyFile {
  readonly rules: Pick<RulesPolicy, 'prompt'>;
}

const mergedRules: RulesPolicy = {
  ...(commandData as unknown as CommandFamilyFile).rules,
  ...(secretData as unknown as SecretFamilyFile).rules,
  ...(mcpWriteData as unknown as McpWriteFamilyFile).rules,
  ...(writeSecretData as unknown as WriteSecretFamilyFile).rules,
  ...(promptData as unknown as PromptFamilyFile).rules,
};

// `config_read_modes` is the single source of truth for "this is a git
// config READ" — shared with the git `safe_first_arg` entry for
// `sub = "config"`, which by definition needs the exact same values (both
// answer the same question: which git-config invocation forms only read).
// Rather than a second literal copy of the same eight strings elsewhere in
// policy/command.toml, that entry's `values` is left empty in TOML and
// filled in here, once, at load time.
function withConfigValuesFilledIn(rules: RulesPolicy): RulesPolicy {
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

export const BASELINE: RawPolicyFile = { rules: withConfigValuesFilledIn(mergedRules) };
