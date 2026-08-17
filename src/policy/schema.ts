// The policy schema: the shape every rule table takes once loaded from
// TOML (baseline or overlay). Field names mirror the TOML keys verbatim
// (snake_case) rather than translating to camelCase — this IS the loaded
// data, and a reader diffing a TOML file against this file should not have
// to translate names in their head.

// One regex-shaped rule row, the schema every family's regex table uses —
// collapses the three separate {regex, ruleId, reason} declarations
// (types.ts's BashRule, write-secret-rules' SecretRule, prompt-rules'
// PromptRule) and PathRule's divergent `id` into one shape.
export interface RegexRule {
  readonly id: string;
  readonly regex: string;
  readonly flags?: string;
  readonly reason: string;
  // A second regex that, if it ALSO matches, cancels this rule's hit (the
  // dotenv/ENV_WHITELIST and npmrc/node_modules exceptions).
  readonly except?: string;
  // An engine-recognized marker for logic no regex alone expresses — today
  // only "git_remote_url" (the remote.*.url config entry, checked through
  // the structural git parser instead of its own regex; see
  // hasUnsafeGitConfigRemoteUrl). Replaces the old object-identity branch.
  readonly special?: string;
  // A per-row static override of the family's default verdict (e.g.
  // secret.path rows default to "block"; a row that should only confirm
  // sets `verdict = "confirm"` here, in the TOML, as ordinary data — lint
  // validates it against {block, confirm, observe}). Distinct from
  // `verdict_override`: THIS field is the loaded data itself, visible in
  // the file, present on a raw baseline or overlay row exactly as
  // written. `verdict_override` is never here — it is the synthesized,
  // post-`[[override]]` form that lives on CompiledRule
  // (src/policy/match.ts), the compiled/effective layer, and wins over
  // this field when both are present (an override is a live, explicit
  // decision; this is a row's own static default).
  readonly verdict?: 'block' | 'confirm' | 'observe';
}

export interface AskFlagsRule {
  readonly sub: string;
  readonly flags: readonly string[];
  // When set, also ask if more than this many non-flag, non-redirection
  // tokens are present — symbolic-ref's "at most one ref name" rule.
  readonly max_positionals?: number;
  // Mandatory (lint-enforced) when `sub` is already governed by the
  // baseline (safe_subcommands, or any of the three declarative tables) —
  // such an overlay entry can only SUBSTITUTE, and therefore only relax,
  // the baseline's own behavior for that subcommand. Optional when `sub`
  // is genuinely new. See src/policy/lint.ts's lintGitConditionalRelaxation.
  readonly reason?: string;
}

export interface SafeFirstArgRule {
  readonly sub: string;
  readonly values: readonly string[];
  // Default false: ask when rest[0] is NOT in `values` (config/bundle/
  // worktree's shape). true: ask WHEN rest[0] IS in `values` (stash's
  // shape — "drop"/"clear" are the dangerous first args, not the safe ones).
  readonly invert?: boolean;
  // Whether a bare subcommand with no arguments at all is safe.
  readonly safe_when_absent: boolean;
  // See AskFlagsRule.reason.
  readonly reason?: string;
}

export interface SafeGrammarRule {
  readonly sub: string;
  // Each sequence must match `rest` exactly, position by position and in
  // length; "*" in a slot matches any single token that is not a flag
  // (does not start with "-").
  readonly sequences: readonly (readonly string[])[];
  // See AskFlagsRule.reason.
  readonly reason?: string;
}

export interface CommandGitPolicy {
  readonly safe_subcommands: readonly string[];
  readonly config_read_modes: readonly string[];
  readonly ask_flags: readonly AskFlagsRule[];
  readonly safe_first_arg: readonly SafeFirstArgRule[];
  readonly safe_grammar: readonly SafeGrammarRule[];
}

export interface CommandPolicy {
  readonly bash: readonly RegexRule[];
  readonly rm_rf: { readonly dangerous_targets: readonly string[] };
  readonly privilege_escalation: { readonly commands: readonly string[] };
  readonly git: CommandGitPolicy;
}

export interface SecretPolicy {
  readonly path: readonly RegexRule[];
  readonly bash: readonly RegexRule[];
}

export interface McpWritePolicy {
  readonly read_prefixes: readonly string[];
}

export interface RulesPolicy {
  readonly command: CommandPolicy;
  readonly secret: SecretPolicy;
  readonly mcp_write: McpWritePolicy;
  readonly write_secret: readonly RegexRule[];
  readonly prompt: readonly RegexRule[];
}

// The raw shape a TOML file parses into: `{ rules: RulesPolicy, override?:
// OverrideEntry[] }`. `override` is TOML's array-of-tables syntax
// (`[[override]]`), only meaningful in an overlay — the baseline never
// carries one.
export interface OverrideEntry {
  readonly rule: string;
  readonly action: 'disable' | 'replace' | 'relax';
  readonly reason: string;
  // action: "replace" — the new regex (and optionally reason) to use.
  readonly regex?: string;
  // action: "relax" — the new (milder) verdict kind this rule fires with.
  readonly verdict?: 'block' | 'confirm' | 'observe';
}

// The three allowlists an overlay can only ever RELAX by adding to (each
// addition unconditionally widens what silently passes) — `[[relax]]` is
// the sole path onto them; a plain overlay addition to
// `rules.command.git.safe_subcommands` etc. is rejected at load time
// specifically to force every widening through this reason-mandatory form.
export type RelaxableList =
  | 'command.git.safe_subcommands'
  | 'command.git.config_read_modes'
  | 'mcp_write.read_prefixes';

// The runtime companion to the type above — a string-literal union has no
// values to iterate or check membership against at runtime, so any caller
// that needs to validate "is this string a member of RelaxableList"
// (src/policy/lint.ts's overlay validation, src/adapter/audit.ts's
// suggestion levers and their own drift test) reads from here instead of
// re-declaring the three strings a second time.
export const RELAXABLE_LISTS: readonly RelaxableList[] = [
  'command.git.safe_subcommands',
  'command.git.config_read_modes',
  'mcp_write.read_prefixes',
];

export interface RelaxationEntry {
  readonly list: RelaxableList;
  readonly value: string;
  readonly reason: string;
}

export interface RawPolicyFile {
  readonly rules: RulesPolicy;
  readonly override?: readonly OverrideEntry[];
  // TOML's array-of-tables syntax (`[[relax]]`), only meaningful in an
  // overlay — see RelaxationEntry.
  readonly relax?: readonly RelaxationEntry[];
}
