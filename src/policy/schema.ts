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
  // An engine-recognized structural matcher. It receives the effective
  // compiled row: `"git_remote_url"` owns its Git predicate, while
  // `"docker_destructive"` applies the row's regex and exception to
  // executable Docker candidates. Replaces object-identity branches.
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
  readonly rm_rf: { readonly dangerous_targets: readonly string[]; };
  readonly privilege_escalation: { readonly commands: readonly string[]; };
  readonly git: CommandGitPolicy;
}

export interface SecretPolicy {
  readonly path: readonly RegexRule[];
  readonly bash: readonly RegexRule[];
}

export interface McpWritePolicy {
  readonly read_prefixes: readonly string[];
  readonly allowed_tools: readonly string[];
}

export interface HarnessPersistent {
  readonly id: string;
  readonly path: string;
  readonly reason: string;
}

// ADR-0006 § 3: the vocabulary a `[harness.protocol.tools]` row judges a
// tool call by. Every family a role names is exhaustive for that row —
// `command` (command + secret families), `read` (secret family only;
// `pattern` matched literally, `path` after canonicalisation), `write`
// (secret AND protected-write families on `path`, write-secret on `text`),
// `fetch` (secret family on `url`/`urls`), `mcp` (mcp-write family on the
// tool's own name, for any name not claimed by an explicit row).
export type HarnessRole = 'command' | 'read' | 'write' | 'fetch' | 'mcp';

// One `[harness.protocol.tools]` row — an exact tool name, or a trailing-
// `*` glob (`"mcp__*"`), mapped to a role plus EITHER the dotted-path
// selectors (§ below) that pull its fields out of the envelope's input
// bag, OR a named `codec` (ADR-0006 § 6) that parses the raw input bag
// itself when a field map cannot express the shape (Codex's `apply_patch`
// patch text). The two are mutually exclusive — lint rejects a row
// carrying both `codec` and any selector key (harness.ts's parseToolRow).
// A selector is unset when the row's role has nothing to say about that
// field (e.g. `read`'s `text` is never set) — never an empty string,
// which would be a selector naming the input's own root.
export interface HarnessToolRow {
  readonly role: HarnessRole;
  readonly command?: string;
  readonly path?: string;
  readonly pattern?: string;
  readonly text?: string;
  readonly url?: string;
  readonly urls?: string;
  readonly codec?: string;
}

// ADR-0006 § 4: the action a degraded abstract verdict renders as.
// `silent` has no template — nothing reaches stdout.
export type HarnessAction = 'deny' | 'ask' | 'context' | 'silent';

export interface HarnessOutputTable {
  readonly block: HarnessAction;
  readonly confirm: HarnessAction;
  readonly observe: HarnessAction;
  readonly flag: HarnessAction;
  readonly on_malformed: 'allow' | 'deny';
  // Mandatory (lint-enforced) whenever any action above is "ask" — the
  // written, measured reason a human believes this harness actually
  // surfaces an interactive prompt for it (lint cannot verify the
  // harness's own behavior, only that the author committed to a reason).
  readonly ask_probe?: string;
}

// Keyed by the ACTION name (not the abstract verdict) — "silent" carries
// no template, so this table only ever has up to four entries.
export type HarnessTemplateKey = 'deny' | 'ask' | 'context' | 'session_start';

// A template may render `stdout`, set the process `exit` code, or both —
// Claude Code's four templates only ever set `stdout` (exit stays the
// process default), a future shim-based harness may need `exit` instead.
export interface HarnessTemplate {
  readonly stdout?: string;
  readonly exit?: number;
}

// Review round 2 R2-1: `prompt`/`session_start` are OPTIONAL — a harness
// that never judges prompts (or has no doctor-facing SessionStart
// surface) declares neither, rather than being forced to lie about
// fields it has no envelope shape for. `src/policy/harness.ts`'s
// coherence checks keep `input.prompt` and `events.prompt` in lockstep,
// and gate `output.flag = "context"`/`output.session_start` on the
// matching event being declared.
export interface HarnessProtocolInput {
  readonly event: string;
  readonly tool: string;
  readonly input: string;
  readonly session: string;
  readonly prompt?: string;
  readonly cwd: string;
  // Review round 1 P-4: optional — Codex's own envelope carries
  // `permission_mode`, never read for a decision (the brief's own non-
  // goal), only LOGGED on every verdict entry for the call (src/adapter/
  // run.ts/log.ts). Absent on claude-code.toml, which sends no such
  // field at all.
  readonly permission?: string;
}

export interface HarnessProtocolEvents {
  readonly pre_tool: string;
  readonly prompt?: string;
  readonly session_start?: string;
}

// ADR-0006 § 3/6: the full declaration a harness's `run()` pipeline reads
// — transport, input map, event names, the tools map, the output table
// and its templates, plus the wiring codec `doctor` uses to prove the
// hook is actually installed. `wiring` is optional: a harness declared
// without one gets `wiring: not checkable (declared harness)` in doctor,
// visible rather than silently green.
export interface HarnessProtocol {
  readonly transport: string;
  readonly wiring?: string;
  readonly input: HarnessProtocolInput;
  readonly events: HarnessProtocolEvents;
  readonly tools: Readonly<Record<string, HarnessToolRow>>;
  readonly output: HarnessOutputTable;
  readonly templates: Readonly<Partial<Record<HarnessTemplateKey, HarnessTemplate>>>;
}

export interface HarnessDeclaration {
  readonly id: string;
  readonly dir: readonly string[];
  readonly parents?: readonly string[];
  readonly env: readonly string[];
  readonly witness: string;
  readonly reason: string;
  readonly persistent: readonly HarnessPersistent[];
  readonly protocol?: HarnessProtocol;
}

export interface DerivedHarnessRule extends RegexRule {
  readonly harnessId: string;
}

export type HarnessOverlay = Readonly<{
  id: string;
  dir?: readonly string[];
  parents?: readonly string[];
  env?: readonly string[];
  witness?: string;
  reason?: string;
  persistent?: readonly HarnessPersistent[];
  protocol?: HarnessProtocol;
}>;

export interface RulesPolicy {
  readonly command: CommandPolicy;
  readonly secret: SecretPolicy;
  readonly protected_write: readonly RegexRule[];
  readonly harness: readonly HarnessDeclaration[];
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

// The four allowlists an overlay can only ever RELAX by adding to (each
// addition unconditionally widens what silently passes) — `[[relax]]` is
// the sole path onto them; a plain overlay addition to
// `rules.command.git.safe_subcommands` etc. is rejected at load time
// specifically to force every widening through this reason-mandatory form.
export type RelaxableList =
  | 'command.git.safe_subcommands'
  | 'command.git.config_read_modes'
  | 'mcp_write.read_prefixes'
  | 'mcp_write.allowed_tools';

// The runtime companion to the type above — a string-literal union has no
// values to iterate or check membership against at runtime, so any caller
// that needs to validate "is this string a member of RelaxableList"
// (src/policy/lint.ts's overlay validation, src/adapter/audit.ts's
// suggestion levers and their own drift test) reads from here instead of
// re-declaring the four strings a second time.
export const RELAXABLE_LISTS: readonly RelaxableList[] = [
  'command.git.safe_subcommands',
  'command.git.config_read_modes',
  'mcp_write.read_prefixes',
  'mcp_write.allowed_tools',
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
