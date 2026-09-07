// The embedded baseline: seven STATIC imports, one per rule family plus the
// harness declarations (policy/command.toml, secret.toml, protected-write.toml,
// mcp-write.toml, write-secret.toml, prompt.toml, harness.toml — split from one
// ~500-line policy/baseline.toml for review/diff visibility, ticket 12), merged at
// build time into the same shape a single file used to produce. `bun build --compile`
// inlines all seven parsed TOML files into the compiled binary — there is no on-disk
// file to find at runtime for any of them. This is deliberately separate
// from the overlay, which is read from disk at runtime (see load.ts) —
// the baseline can never be missing or unreadable, which is exactly the
// property that makes "fall back to baseline" a safe fail-closed default.
//
// Each family file's TOML header is `[[rules.<family>...]]`, so parsing
// it alone yields an object shaped `{ rules: { <family>: ... } }` — every
// family owns a DISTINCT top-level key under `rules` (command / secret /
// protected_write / mcp_write / write_secret / prompt); harness.toml owns
// top-level `[[harness]]` declarations. The family keys remain distinct, so
// merging the six rule families is a shallow spread.

import commandData from '../../policy/command.toml';
import harnessData from '../../policy/harness.toml';
import mcpWriteData from '../../policy/mcp-write.toml';
import promptData from '../../policy/prompt.toml';
import protectedWriteData from '../../policy/protected-write.toml';
import secretData from '../../policy/secret.toml';
import writeSecretData from '../../policy/write-secret.toml';
import { deriveHarnessRules, parseBaselineHarness } from './harness.ts';
import type { HarnessDeclaration, RawPolicyFile, RegexRule, RulesPolicy } from './schema.ts';

// assertExactlyOneFamily is the runtime check for each family file's
// [rules] table: a stray extra key (a family file accidentally nesting a
// second family's table under its own) or the WRONG key entirely would
// otherwise spread silently into mergedRules, either shadowing or being
// shadowed by the real owner depending on spread order. Every family file
// must contribute EXACTLY its one expected key under `[rules]`, checked
// at BUILD/import time (this runs at module load, before BASELINE is
// ever read), or the whole process fails loudly and immediately — the
// baseline has no "fall back" path the way a bad overlay does, so this
// failure mode must be as early and as loud as possible.
//
// A family silently MISSING from the spread below is caught separately,
// by something even cheaper than this function: `mergedRules` is
// explicitly typed `RulesPolicy`, so TypeScript's object-literal
// target-type checking already rejects a spread that omits a required
// key, no runtime check needed for that half.
export function assertExactlyOneFamily<K extends keyof RulesPolicy>(
  data: unknown,
  expectedKey: K,
  filename: string,
): { readonly rules: Pick<RulesPolicy, K>; } {
  const rules = data !== null && typeof data === 'object' ? (data as Record<string, unknown>).rules : undefined;
  if (rules === null || typeof rules !== 'object') {
    throw new Error(`baseline family file ${filename} has no [rules] table`);
  }
  const keys = Object.keys(rules);
  if (keys.length !== 1 || keys[0] !== expectedKey) {
    throw new Error(
      `baseline family file ${filename} must contribute exactly the "${expectedKey}" key under [rules] `
        + `— found: ${keys.length > 0 ? keys.join(', ') : '(none)'}`,
    );
  }
  return { rules: rules as Pick<RulesPolicy, K> };
}

export function assertHarnessDeclarations(data: unknown, filename: string): readonly HarnessDeclaration[] {
  if (data === null || typeof data !== 'object') {
    throw new Error(`baseline harness file ${filename} has no [[harness]] declarations`);
  }
  const declarations = Reflect.get(data, 'harness');
  if (!Array.isArray(declarations)) {
    throw new Error(`baseline harness file ${filename} has no [[harness]] declarations`);
  }

  return declarations.map((raw, index) => {
    const parsed = parseBaselineHarness(raw, `harness[${index}]`);
    if (parsed.value === undefined) {
      throw new Error(`baseline harness file ${filename}: ${parsed.issues.join('; ')}`);
    }
    return parsed.value;
  });
}

const harnesses = assertHarnessDeclarations(harnessData, 'policy/harness.toml');

const mergedRules: RulesPolicy = {
  ...assertExactlyOneFamily(commandData, 'command', 'policy/command.toml').rules,
  ...assertExactlyOneFamily(secretData, 'secret', 'policy/secret.toml').rules,
  protected_write: [
    ...deriveHarnessRules(harnesses),
    ...assertExactlyOneFamily(protectedWriteData, 'protected_write', 'policy/protected-write.toml').rules.protected_write,
  ],
  harness: harnesses,
  ...assertExactlyOneFamily(mcpWriteData, 'mcp_write', 'policy/mcp-write.toml').rules,
  ...assertExactlyOneFamily(writeSecretData, 'write_secret', 'policy/write-secret.toml').rules,
  ...assertExactlyOneFamily(promptData, 'prompt', 'policy/prompt.toml').rules,
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

export function assertUniqueRuleIds(rules: RulesPolicy): RulesPolicy {
  const ruleFamilies: readonly [string, readonly RegexRule[]][] = [
    ['command.bash', rules.command.bash],
    ['secret.path', rules.secret.path],
    ['secret.bash', rules.secret.bash],
    ['protected_write', rules.protected_write],
    ['write_secret', rules.write_secret],
    ['prompt', rules.prompt],
  ];
  const familyById = new Map<string, string>();
  for (const [family, entries] of ruleFamilies) {
    for (const rule of entries) {
      const existing = familyById.get(rule.id);
      if (existing !== undefined) {
        throw new Error(`baseline rule id ${JSON.stringify(rule.id)} is not globally unique (${existing}, ${family})`);
      }
      familyById.set(rule.id, family);
    }
  }
  return rules;
}

export const BASELINE: RawPolicyFile = { rules: assertUniqueRuleIds(withConfigValuesFilledIn(mergedRules)) };
