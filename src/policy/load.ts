// Policy loading: baseline + layered-overlay merge, `[[relax]]`/
// `[[override]]` application, cross-layer precedence, and the fail-closed
// fallback contract — a malformed or lint-failing load NEVER partially
// applies and never fails open; it is rejected as a whole, the embedded
// baseline stays fully active, and the rejection is a loud warning
// (surfaced by both the audit log and `rules list`), never a silent
// swallow. Pure — no filesystem access (see src/adapter/policy.ts for
// reading the overlay files, and for resolving the two named layers'
// roots, off disk).
//
// ONE pipeline, loadPolicyFromLayers (ADR-0001): named layers (today,
// exactly two — "common" then "profile", precedence order), each a SET
// of files, not one (ticket 12) — `policy.toml` (if present), then every
// `policy.d/*.toml` file the adapter found, in lexicographic filename
// order (src/adapter/policy.ts decides that order; this module just
// processes whatever list it's given, in the order given). Two files of
// the SAME layer targeting the same thing is a lint failure; the SAME
// target across TWO layers is precedence — the later layer wins, the
// earlier one's entry is dropped and the survivor carries `shadows`
// naming it (see resolvePrecedence). Rejection is PER LAYER (ticket 21,
// ADR-0001 § Rejection): a fault anywhere in a layer's file set rejects
// THAT layer only — its files drop out, every other layer keeps running.
// The one exception is a profile `[[override]]` whose target lived in a
// common layer that just got rejected: it no longer resolves, so the
// profile layer is rejected too, and the baseline runs alone — never a
// partial profile (see loadPolicyFromLayers's retry loop). Both layers
// gone (independently broken, or cascaded) is still "the baseline alone",
// exactly as before ticket 21 — what changed is that a healthy layer next
// to a broken one now stays live instead of falling with it.
// loadPolicyFromOverlayFiles is this pipeline's one-layer degenerate
// case (`loadPolicyFromLayers([{ name: 'profile', files }])`) — with
// only one layer, cross-layer precedence never triggers, and
// resolvePrecedence degenerates exactly into "two files, same key,
// reject". loadPolicyFromOverlayText is a further, single-file
// convenience wrapper on top of that — test-only now (no production
// caller reaches for it; the real path, src/adapter/policy.ts's
// loadCurrentPolicy, always resolves both layers and calls
// loadPolicyFromLayers directly).

import { BASELINE } from './baseline.ts';
import { deriveHarnessRules, isDerivedHarnessRule, parseHarnessOverlay as parseOverlayHarness } from './harness.ts';
import {
  lintAskFlagsShape,
  lintEffectiveDialect,
  lintGitConditionalRelaxation,
  lintOneRule,
  lintOverrides,
  lintRegexSource,
  lintRelaxEntries,
  lintSafeFirstArgShape,
  lintSafeGrammarShape,
  resolvableRuleIds,
} from './lint.ts';
import type { LintIssue } from './lint.ts';
import type {
  AskFlagsRule,
  HarnessDeclaration,
  HarnessOverlay,
  OverrideEntry,
  RegexRule,
  RelaxableList,
  RelaxationEntry,
  RulesPolicy,
  SafeFirstArgRule,
  SafeGrammarRule,
} from './schema.ts';

// Every regex-table id the embedded baseline already owns, across all six
// families combined — computed once at module load (the baseline never
// changes at runtime), see attemptCompose's use for the rationale.
const BASELINE_RULE_IDS = resolvableRuleIds(BASELINE.rules);

export type Provenance = 'baseline' | 'overlay' | 'baseline+overlay' | 'override';

export interface EffectiveRule {
  readonly family: string;
  readonly rule: RegexRule;
  readonly provenance: Provenance;
  readonly overrideAction?: 'replace' | 'relax';
  readonly overrideReason?: string;
  // The most recent overlay filename contributing to this entry — present
  // for overlay, baseline+overlay, and override provenance. Always
  // layer-qualified ("common:policy.toml",
  // "profile:policy.d/10-npm.toml") — every LoadResult comes from
  // loadPolicyFromLayers now (loadPolicyFromOverlayFiles is its one-layer,
  // `name: 'profile'` case).
  readonly sourceFile?: string;
  // Every overlay filename contributing to a coalesced derived harness row.
  // Normal overlay rows have one source, so they keep sourceFile alone.
  readonly sourceFiles?: readonly string[];
  // The layer `sourceFile` came from ("common"/"profile") — absent
  // exactly when `sourceFile` is (a baseline entry has neither). Lets
  // lint.ts's lintEffectiveDialect tag an issue with its layer directly
  // from this entry, rather than a caller having to re-derive it from
  // `sourceFile` (ADR-0001 § Rejection).
  readonly layer?: string;
  // ADR-0001 § Precedence: set only when this entry won cross-layer
  // precedence over an earlier layer's entry for the SAME target — names
  // the shadowed entry's qualified file (e.g. "common:policy.d/100-x.toml").
  // Only loadPolicyFromLayers ever sets this.
  readonly shadows?: string;
  // Derived harness rows retain the declaration that produced them, so
  // `rules list` can distinguish them from handwritten baseline rows.
  readonly harnessId?: string;
}

export interface ActiveOverride extends OverrideEntry {
  readonly sourceFile: string;
  readonly shadows?: string;
}

// A relaxation actively in effect — an allowlist addition via `[[relax]]`,
// or a git-conditional overlay entry substituting an already-governed
// baseline subcommand. Always carries a reason (lint-enforced) and the
// file it came from.
export interface ActiveRelaxation {
  readonly list: string;
  readonly value: string;
  readonly reason: string;
  readonly sourceFile: string;
  readonly shadows?: string;
}

// One named overlay layer, as loadPolicyFromLayers receives it — the
// adapter resolves roots and reads files (src/adapter/policy.ts); this
// module owns precedence, rejection and provenance across them
// (ADR-0001). Layer order in the array IS precedence order: a later
// layer's entry wins over an earlier layer's for the same target
// (ADR-0001 § Precedence — "the profile wins" is simply "profile is last").
export interface NamedLayer {
  readonly name: string;
  // The layer's resolved root directory, IFF it exists on disk — the
  // adapter's job to check (this module stays I/O-free); omitted (never
  // `undefined` explicitly — just left out) when the caller has no
  // filesystem root concept for this layer, or when the root does not
  // exist. `undefined` on the matching LoadResult.layers entry is what
  // `doctor`/`rules lint` render as "<name>: absent" — a root that DOES
  // exist but happens to hold zero files renders "<name>: 0 files"
  // instead (see LayerInfo).
  readonly root?: string;
  readonly files: readonly OverlayFile[];
}

// The single file whose fault sank the layer, plus why — ADR-0001
// § Rejection: "one policy-warning entry per rejected layer, naming the
// file". `reason` may name more than one file (a same-layer conflict
// between two files, or a layer where more than one file independently
// faulted) — `file` is always the FIRST one found, a "primary" pointer
// for callers (doctor's checklist, cli-commands' `rules lint`) that want
// one name to show, while `reason` stays the fuller detail.
export interface LayerRejectionInfo {
  readonly file: string;
  readonly reason: string;
}

// Per-layer provenance loadPolicyFromLayers always reports, independent
// of whether the overall load succeeded (see LoadResult.layers) — a
// rejected load still names what each layer had going in. `root` absent
// means the layer's root directory does not exist on disk at all (a
// fresh install with no `~/.agents/bouncer/`, say) — `doctor`/`rules
// lint` render that as "<name>: absent". `root` present with an EMPTY
// `files` is a real, distinct state (an existing-but-unconfigured root)
// and renders "<name>: 0 files" — the two must never collapse into one.
export interface LayerInfo {
  readonly name: string;
  readonly root?: string;
  readonly files: readonly string[];
  // Set only when this layer's OWN files caused it to be dropped from the
  // effective merge (ADR-0001 § Rejection) — absent for a layer that
  // either loaded cleanly or simply had nothing to load. Present
  // alongside a non-empty `files`: rejection always means "had files,
  // one of them was at fault", never "had none".
  readonly rejected?: LayerRejectionInfo;
}

export interface LoadResult {
  readonly policy: RulesPolicy;
  readonly effectiveRules: readonly EffectiveRule[];
  readonly warnings: readonly string[];
  readonly overlayApplied: boolean;
  // Every filename successfully merged in, in merge order — empty when
  // overlayApplied is false (no files given, or the whole set rejected).
  readonly overlayFiles: readonly string[];
  readonly activeOverrides: readonly ActiveOverride[];
  readonly activeRelaxations: readonly ActiveRelaxation[];
  // Always defined — every LoadResult comes from loadPolicyFromLayers now
  // (loadPolicyFromOverlayFiles is its one-layer, `name: 'profile'` case).
  readonly layers: readonly LayerInfo[];
}

// One overlay file as read off disk: a display name used in every
// warning/provenance message (not necessarily a filesystem path —
// "policy.toml", "policy.d/10-npm.toml") plus either its raw text, or —
// when the adapter's `readdir` proved the file exists but a subsequent
// read failed (permission denied, a broken symlink, a directory entry,
// a TOCTOU race) — a `readError` describing why. A file the adapter
// legitimately never saw (the root `policy.toml` simply not existing) is
// never represented here at all; the adapter drops it before building
// this list. From here on `readError` is treated exactly like a parse
// error: it rejects the whole overlay set, naming this file (see
// loadPolicyFromOverlayFiles) — a file readdir already proved present has
// no license to silently vanish.
export type OverlayFile =
  | { readonly filename: string; readonly text: string; }
  | { readonly filename: string; readonly readError: string; };

interface Tagged {
  readonly family: string;
  readonly rule: RegexRule;
  readonly provenance: 'baseline' | 'overlay' | 'baseline+overlay';
  readonly harnessId?: string;
  readonly sourceFile?: string;
  readonly sourceFiles?: readonly string[];
  // Absent exactly when `sourceFile` is (a baseline entry has neither) —
  // threaded onto EffectiveRule by applyOverrides so lintEffectiveDialect
  // can tag its own issues without re-deriving a layer from `sourceFile`.
  readonly layer?: string;
  readonly shadows?: string;
}

export interface FileTagged<T> {
  readonly filename: string;
  readonly raw: T;
  // Which named layer this entry came from — always set by
  // loadPolicyFromLayers (see NamedLayer). Optional only because
  // tests/policy-lint-filenames.test.ts constructs bare FileTagged
  // literals to unit-test lint.ts's functions directly, bypassing this
  // module's pipeline entirely.
  readonly layer?: string;
  // Set only when this entry won cross-layer precedence over an earlier
  // layer's entry for the same target — see EffectiveRule.shadows.
  readonly shadows?: string;
}

// The askFlags/safeFirstArg/safeGrammar trio: three parallel per-family
// lists of git-conditional overlay entries that get threaded through the
// merge (mergeGitPolicy), the active-relaxation report
// (buildActiveRelaxations), and the cross-file conflict check together,
// as one unit, at every call site — bundled here so a call site takes one
// value instead of three positionally-ordered ones.
interface GitConditionalEntries {
  readonly askFlags: readonly FileTagged<AskFlagsRule>[];
  readonly safeFirstArg: readonly FileTagged<SafeFirstArgRule>[];
  readonly safeGrammar: readonly FileTagged<SafeGrammarRule>[];
}

// One issue a compose attempt failed on, POSED by the throw site that
// found it — `layer` and `file` (when there is a single one) are copied
// directly from data the throw site already has in hand (a FileTagged/
// L<T> entry's own `.layer`/`.filename`, or an EffectiveRule's own
// `.layer`/`.sourceFile`), never derived from `detail` by a caller
// downstream. `file`, when present, is the layer-QUALIFIED name
// ("common:policy.d/1.toml") the rest of this module already threads
// through for provenance — groupIssuesByLayer un-qualifies it for
// display via plainFile, a decode of a concatenation this module made
// itself, not a guess. Absent `file` means a genuinely multi-file fault
// (a same-layer conflict names two).
interface RejectionIssue {
  readonly layer: string;
  readonly file?: string;
  readonly detail: string;
}

// A structural-shape error at the merge boundary (wrong-typed field) and a
// lint failure both take the same path out: reject the CURRENT compose
// attempt (loadPolicyFromLayers's attemptCompose, over whichever layers
// are still in play — see that function), carrying every individual
// RejectionIssue it found — never joined into one string first, which is
// what let loadPolicyFromLayers's groupIssuesByLayer read `.layer`
// straight off each issue instead of re-parsing free text for it.
class PolicyRejected extends Error {
  readonly issues: readonly RejectionIssue[];
  constructor(issues: readonly RejectionIssue[]) {
    super(issues.map((i) => `${i.layer}${i.file !== undefined ? `:${i.file}` : ''}: ${i.detail}`).join('; '));
    this.issues = issues;
  }
}

// A layer name that can never equal a real one (every real layer name —
// "common", "profile", any future adapter's own — never contains these
// characters) — used only as RejectionIssue.layer's fallback when a
// producer (toRejectionIssues, lintMergedDialect) has no real layer to
// give (unreachable in practice: every producer this module feeds through
// its own throw sites always has one). groupIssuesByLayer's single
// fail-closed branch treats an issue carrying this exactly like one
// naming a layer that isn't even among the ones being tried.
const UNATTRIBUTED_LAYER = '<unattributed>';

function getPath(obj: unknown, path: readonly string[]): unknown {
  let cur: unknown = obj;
  for (const key of path) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

// The plain filename portion of a qualified one ("common:policy.d/1.toml"
// -> "policy.d/1.toml") for a RejectionIssue's `file` field — safe here
// because the caller already knows both `layer` and that `qualified` was
// built as EXACTLY `${layer}:${plain}` (see parseOverlayFiles, the one
// place this module qualifies a filename): decoding a concatenation this
// module made itself, never recovering lost structure from someone
// else's free text.
function plainFile(layer: string, qualified: string): string {
  return qualified.slice(layer.length + 1);
}

// Reads an array-shaped field at `path` out of one file's parsed TOML,
// naming that file if the field is present but not an array. Absent is
// fine — an empty contribution, not a failure.
function fileArray<T>(parsed: unknown, path: readonly string[], displayPath: string, layer: string, filename: string): readonly T[] {
  const value = getPath(parsed, path);
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new PolicyRejected([{ layer, file: plainFile(layer, filename), detail: `${displayPath} must be an array` }]);
  }
  return value as T[];
}

function mergeRegexFamily(
  family: string,
  baseline: readonly RegexRule[],
  overlayEntries: readonly (FileTagged<unknown> & { readonly layer: string; })[],
): Tagged[] {
  const overlayTagged: Tagged[] = overlayEntries.map(({ filename, raw, layer, shadows }) => {
    if (
      raw === null || typeof raw !== 'object'
      || typeof (raw as Record<string, unknown>).id !== 'string'
      || typeof (raw as Record<string, unknown>).regex !== 'string'
      || typeof (raw as Record<string, unknown>).reason !== 'string'
    ) {
      throw new PolicyRejected([{
        layer,
        file: plainFile(layer, filename),
        detail: `${family}: an overlay rule is missing a required string field (id/regex/reason)`,
      }]);
    }
    return {
      family,
      rule: raw as RegexRule,
      provenance: 'overlay' as const,
      sourceFile: filename,
      layer,
      ...(shadows !== undefined ? { shadows } : {}),
    };
  });
  const baselineTagged: Tagged[] = baseline.map((rule) => ({
    family,
    rule,
    provenance: 'baseline' as const,
    ...(isDerivedHarnessRule(rule) ? { harnessId: rule.harnessId } : {}),
  }));
  // Regex tables: pure hardening. An overlay addition only ever adds a new
  // BLOCK/confirm signature — it can never relax an existing one — so it
  // stays silently additive, appended after the vetted baseline set, in
  // the order its file was given (policy.toml, then policy.d lex order).
  return appendedAfterBaseline(baselineTagged, overlayTagged);
}

// Regex-table families (and the two plain danger lists, rm_rf/privilege):
// baseline first, overlay entries appended after, in file order. The name
// says the order: an overlay addition can only ever ADD a new signature
// (pure hardening), never shadow or replace a vetted baseline entry by
// position — and among overlay entries themselves, "first match wins"
// (src/policy/match.ts's firstMatch) means the earlier FILE's entry wins
// when two overlay rules could both match the same input.
function appendedAfterBaseline<T>(baseline: readonly T[], overlay: readonly T[]): T[] {
  return [...baseline, ...overlay];
}

// The git-conditional keyed tables (ask_flags/safe_first_arg/safe_grammar):
// overlay entries come FIRST, so `Array.find()` (which every consumer of
// these tables uses to look up a `sub`) picks the overlay's entry over the
// baseline's when both govern the same subcommand. The name says the
// order: overlay wins position, which is exactly what makes such an entry
// a SUBSTITUTION — and therefore a relaxation requiring `reason` — when the
// `sub` was already baseline-governed (see lint.ts's
// lintGitConditionalRelaxation, which this asymmetry is what makes
// necessary). The SAME `sub` substituted by two DIFFERENT overlay files
// of the SAME layer is rejected outright before this function ever runs
// (see resolvePrecedence below); across two DIFFERENT layers it is
// precedence, already resolved down to one surviving entry per `sub` by
// the same point — there is no "which overlay file wins" question left
// to answer positionally by the time this executes.
function overlayTakesPrecedence<T>(overlay: readonly T[], baseline: readonly T[]): T[] {
  return [...overlay, ...baseline];
}

function relaxedValuesFor(relax: readonly FileTagged<RelaxationEntry>[], list: RelaxableList): string[] {
  return relax.filter((r) => r.raw.list === list).map((r) => r.raw.value);
}

interface MergedPolicy {
  readonly command: {
    readonly bash: Tagged[];
    readonly rm_rf: { readonly dangerous_targets: readonly string[]; };
    readonly privilege_escalation: { readonly commands: readonly string[]; };
    readonly git: RulesPolicy['command']['git'];
  };
  readonly secret: { readonly path: Tagged[]; readonly bash: Tagged[]; };
  readonly protected_write: Tagged[];
  readonly harness: readonly HarnessDeclaration[];
  readonly mcp_write: { readonly read_prefixes: readonly string[]; };
  readonly write_secret: Tagged[];
  readonly prompt: Tagged[];
}

function mergeGitPolicy(
  baseline: RulesPolicy['command']['git'],
  entries: GitConditionalEntries,
  relax: readonly FileTagged<RelaxationEntry>[],
): RulesPolicy['command']['git'] {
  return {
    // Additions here can ONLY come from [[relax]] (reason-mandatory,
    // lint-enforced) — a plain `rules.command.git.safe_subcommands`/
    // `config_read_modes` entry in any overlay file's [rules] table is
    // rejected before this is ever called (see loadPolicyFromOverlayFiles).
    safe_subcommands: appendedAfterBaseline(
      baseline.safe_subcommands,
      relaxedValuesFor(relax, 'command.git.safe_subcommands'),
    ),
    config_read_modes: appendedAfterBaseline(
      baseline.config_read_modes,
      relaxedValuesFor(relax, 'command.git.config_read_modes'),
    ),
    ask_flags: overlayTakesPrecedence(entries.askFlags.map((t) => t.raw), baseline.ask_flags),
    safe_first_arg: overlayTakesPrecedence(entries.safeFirstArg.map((t) => t.raw), baseline.safe_first_arg),
    safe_grammar: overlayTakesPrecedence(entries.safeGrammar.map((t) => t.raw), baseline.safe_grammar),
  };
}

// Dialect check over the baseline+overlay MERGED set (pre-override) —
// catches an overlay ADDITION using a lookaround/backreference/disallowed
// flag/unclosed group. Operates on the private Tagged shape, so it stays
// local rather than living in lint.ts (which has no visibility into
// MergedPolicy). See lintEffectiveDialect (lint.ts) for the second,
// POST-override pass an action="replace" injected regex needs. Builds
// RejectionIssue directly (not lint.ts's LintIssue) — `t.layer`/
// `t.sourceFile` are already in hand here, no conversion boundary needed.
function lintMergedDialect(merged: MergedPolicy): RejectionIssue[] {
  const issues: RejectionIssue[] = [];
  for (const t of allTagged(merged)) {
    const prefix = t.sourceFile !== undefined ? `${t.sourceFile}: ` : '';
    // A baseline entry has neither `layer` nor `sourceFile` (never mind
    // — the vetted baseline never actually fails this check); the
    // UNATTRIBUTED_LAYER fallback exists only so the type stays honest.
    const layer = t.layer ?? UNATTRIBUTED_LAYER;
    const file = t.layer !== undefined && t.sourceFile !== undefined ? plainFile(t.layer, t.sourceFile) : undefined;
    // lintOneRule covers regex/except dialect AND the row's own `verdict`
    // field (schema.ts's RegexRule) — an overlay row's verdict is
    // validated here exactly like a baseline row's, not just at the
    // single-file lintRegexDialect layer.
    for (const issue of lintOneRule(t.family, t.rule)) {
      issues.push({ layer, ...(file !== undefined ? { file } : {}), detail: `${prefix}${issue.message}` });
    }
  }
  return issues;
}

// `rm_rf.dangerous_targets` dialect check, kept SEPARATE from
// lintMergedDialect (unlike the regex-table families above, these targets
// are plain strings with no `Tagged` wrapper of their own) — takes the
// file-tagged list directly (attemptCompose's rmRfTagged) so a bad target
// is attributable to the LAYER that contributed it (ADR-0001 § Rejection).
function lintRmRfTargets(
  tagged: readonly { readonly filename: string; readonly layer: string; readonly raw: string; }[],
): RejectionIssue[] {
  const issues: RejectionIssue[] = [];
  for (const { filename, layer, raw } of tagged) {
    for (const issue of lintRegexSource(raw)) {
      issues.push({ layer, file: plainFile(layer, filename), detail: `command.rm_rf.dangerous_targets: ${issue.message}` });
    }
  }
  return issues;
}

function allTagged(merged: MergedPolicy): Tagged[] {
  return [
    ...merged.command.bash,
    ...merged.secret.path,
    ...merged.secret.bash,
    ...merged.protected_write,
    ...merged.write_secret,
    ...merged.prompt,
  ];
}

function assertUniqueEffectiveRuleIds(merged: MergedPolicy): void {
  const entryById = new Map<string, Tagged>();
  for (const entry of allTagged(merged)) {
    const existing = entryById.get(entry.rule.id);
    if (existing === undefined) {
      entryById.set(entry.rule.id, entry);
      continue;
    }
    const responsible = entry.sourceFile !== undefined
      ? entry
      : existing.sourceFile !== undefined
      ? existing
      : undefined;
    if (responsible === undefined) {
      throw new Error(`baseline rule id ${JSON.stringify(entry.rule.id)} is not globally unique`);
    }
    throw new PolicyRejected([{
      layer: responsible.layer!,
      file: plainFile(responsible.layer!, responsible.sourceFile!),
      detail: `effective rule id ${JSON.stringify(entry.rule.id)} is not globally unique`,
    }]);
  }
}

// Applies every [[override]] to the one globally unique tagged rule it
// names. Multiple overrides on that rule within one file still chain
// sequentially (e.g. replace then relax); a cross-file conflict on the
// same rule within one layer is rejected before this function runs, and a
// cross-layer one is resolved down to one surviving entry (see
// resolvePrecedence).
function applyOverrides(tagged: readonly Tagged[], overrides: readonly FileTagged<OverrideEntry>[]): EffectiveRule[] {
  let current: EffectiveRule[] = tagged.map((t) => ({
    family: t.family,
    rule: t.rule,
    provenance: t.provenance,
    ...(t.sourceFile !== undefined ? { sourceFile: t.sourceFile } : {}),
    ...(t.sourceFiles !== undefined ? { sourceFiles: t.sourceFiles } : {}),
    ...(t.layer !== undefined ? { layer: t.layer } : {}),
    ...(t.shadows !== undefined ? { shadows: t.shadows } : {}),
    ...(t.harnessId !== undefined ? { harnessId: t.harnessId } : {}),
  }));
  for (const { filename, raw: override, layer } of overrides) {
    current = current.flatMap((entry): EffectiveRule[] => {
      if (entry.rule.id !== override.rule) return [entry];
      if (override.action === 'disable') return [];
      if (override.action === 'replace') {
        return [{
          family: entry.family,
          rule: { ...entry.rule, regex: override.regex! },
          provenance: 'override',
          overrideAction: 'replace',
          overrideReason: override.reason,
          sourceFile: filename,
          ...(entry.harnessId !== undefined ? { harnessId: entry.harnessId } : {}),
          ...(layer !== undefined ? { layer } : {}),
        }];
      }
      // relax
      return [{
        family: entry.family,
        rule: { ...entry.rule, verdict_override: override.verdict } as RegexRule,
        provenance: 'override',
        overrideAction: 'relax',
        overrideReason: override.reason,
        sourceFile: filename,
        ...(entry.harnessId !== undefined ? { harnessId: entry.harnessId } : {}),
        ...(layer !== undefined ? { layer } : {}),
      }];
    });
  }
  return current;
}

function regexRulesOf(effective: readonly EffectiveRule[], family: string): RegexRule[] {
  return effective.filter((e) => e.family === family).map((e) => e.rule);
}

// Builds every LoadResult field EXCEPT `layers` — this function has no
// layer information of its own (mergedBaselineOnly/loadPolicyFromLayers
// are the only callers, both via baselineOnlyResult or directly, and both
// attach `layers` themselves at their own call sites, where the layer
// context actually lives).
function buildResult(
  merged: MergedPolicy,
  effective: readonly EffectiveRule[],
  overlayApplied: boolean,
  overlayFiles: readonly string[],
  activeOverrides: readonly ActiveOverride[],
  activeRelaxations: readonly ActiveRelaxation[],
  warnings: readonly string[],
): Omit<LoadResult, 'layers'> {
  const policy: RulesPolicy = {
    command: {
      bash: regexRulesOf(effective, 'command.bash'),
      rm_rf: merged.command.rm_rf,
      privilege_escalation: merged.command.privilege_escalation,
      git: merged.command.git,
    },
    secret: {
      path: regexRulesOf(effective, 'secret.path'),
      bash: regexRulesOf(effective, 'secret.bash'),
    },
    protected_write: regexRulesOf(effective, 'protected_write'),
    harness: merged.harness,
    mcp_write: merged.mcp_write,
    write_secret: regexRulesOf(effective, 'write_secret'),
    prompt: regexRulesOf(effective, 'prompt'),
  };
  return { policy, effectiveRules: effective, overlayApplied, overlayFiles, activeOverrides, activeRelaxations, warnings };
}

function mergedBaselineOnly(): MergedPolicy {
  const baseline = BASELINE.rules;
  return {
    command: {
      bash: mergeRegexFamily('command.bash', baseline.command.bash, []),
      rm_rf: { dangerous_targets: baseline.command.rm_rf.dangerous_targets },
      privilege_escalation: { commands: baseline.command.privilege_escalation.commands },
      git: mergeGitPolicy(baseline.command.git, { askFlags: [], safeFirstArg: [], safeGrammar: [] }, []),
    },
    secret: {
      path: mergeRegexFamily('secret.path', baseline.secret.path, []),
      bash: mergeRegexFamily('secret.bash', baseline.secret.bash, []),
    },
    protected_write: mergeRegexFamily('protected_write', baseline.protected_write, []),
    harness: baseline.harness,
    mcp_write: { read_prefixes: baseline.mcp_write.read_prefixes },
    write_secret: mergeRegexFamily('write_secret', baseline.write_secret, []),
    prompt: mergeRegexFamily('prompt', baseline.prompt, []),
  };
}

// Same `layers`-less contract as buildResult (whose result it wraps) —
// both call sites (loadPolicyFromLayers's empty-layers fast path and its
// catch block) spread this and attach `layers` themselves.
function baselineOnlyResult(warnings: readonly string[] = []): Omit<LoadResult, 'layers'> {
  const merged = mergedBaselineOnly();
  const effective = applyOverrides(allTagged(merged), []);
  return buildResult(merged, effective, false, [], [], [], warnings);
}

// Every subcommand the baseline already has an opinion on: unconditionally
// safe, or governed by one of the three declarative tables, or one of the
// two engine-escape names (checkout/restore). An overlay's own
// ask_flags/safe_first_arg/safe_grammar entry for a `sub` in this set is a
// SUBSTITUTION of vetted behavior, not a fresh addition — see
// lint.ts's lintGitConditionalRelaxation.
function baselineGovernedSubs(git: RulesPolicy['command']['git']): ReadonlySet<string> {
  return new Set<string>([
    ...git.safe_subcommands,
    ...git.ask_flags.map((r) => r.sub),
    ...git.safe_first_arg.map((r) => r.sub),
    ...git.safe_grammar.map((r) => r.sub),
    'checkout',
    'restore',
  ]);
}

function buildActiveRelaxations(
  relax: readonly FileTagged<RelaxationEntry>[],
  entries: GitConditionalEntries,
  governedSubs: ReadonlySet<string>,
): ActiveRelaxation[] {
  const fromGitConditional = (
    list: readonly FileTagged<{ readonly sub: string; readonly reason?: string; }>[],
    table: string,
  ): ActiveRelaxation[] =>
    list
      .filter((e) => governedSubs.has(e.raw.sub))
      .map((e) => ({
        list: `command.git.${table}`,
        value: e.raw.sub,
        reason: e.raw.reason!,
        sourceFile: e.filename,
        ...(e.shadows !== undefined ? { shadows: e.shadows } : {}),
      }));
  return [
    ...relax.map((r) => ({
      list: r.raw.list,
      value: r.raw.value,
      reason: r.raw.reason,
      sourceFile: r.filename,
      ...(r.shadows !== undefined ? { shadows: r.shadows } : {}),
    })),
    ...fromGitConditional(entries.askFlags, 'ask_flags'),
    ...fromGitConditional(entries.safeFirstArg, 'safe_first_arg'),
    ...fromGitConditional(entries.safeGrammar, 'safe_grammar'),
  ];
}

// Builds the ActiveOverride list `rules list`/doctor read from — an
// override's raw entry plus the file it came from and, when it won
// cross-layer precedence over an earlier layer's entry, that entry's
// qualified file (see FileTagged.shadows). Shared by
// loadPolicyFromOverlayFiles (shadows always absent) and
// loadPolicyFromLayers.
function buildActiveOverrides(overrides: readonly FileTagged<OverrideEntry>[]): ActiveOverride[] {
  return overrides.map(({ filename, raw, shadows }) => ({
    ...raw,
    sourceFile: filename,
    ...(shadows !== undefined ? { shadows } : {}),
  }));
}

// Every conflict/precedence check below (loadPolicyFromLayers's
// resolvePrecedence) needs to know whether a raw, not-yet-shape-validated
// regex-table entry HAS a string `id` before it can be grouped by one —
// the authoritative "id/regex/reason must all be strings" shape check
// still lives in mergeRegexFamily, which independently rejects a
// non-string-id entry regardless of this function's leniency here.
function hasStringId(raw: unknown): raw is { readonly id: string; } {
  return raw !== null && typeof raw === 'object' && typeof (raw as Record<string, unknown>).id === 'string';
}

interface HarnessOverlayEntry {
  readonly declaration: HarnessOverlay;
  readonly filename: string;
  readonly layer: string;
}

function rejectHarness(entry: { readonly filename: string; readonly layer: string; }, detail: string): never {
  throw new PolicyRejected([{ layer: entry.layer, file: plainFile(entry.layer, entry.filename), detail }]);
}

function parseHarnessOverlayEntry(
  raw: unknown,
  entry: { readonly filename: string; readonly layer: string; },
  index: number,
): HarnessOverlayEntry {
  const parsed = parseOverlayHarness(raw, `harness[${index}]`);
  if (parsed.value === undefined) return rejectHarness(entry, parsed.issues.join('; '));
  return { declaration: parsed.value, filename: entry.filename, layer: entry.layer };
}

type HarnessContribution = 'baseline' | HarnessOverlayEntry;

interface MergedHarness extends HarnessDeclaration {
  readonly configSources: readonly HarnessContribution[];
  readonly persistentSources: ReadonlyMap<string, readonly HarnessContribution[]>;
}

function overlayContributions(sources: readonly HarnessContribution[]): readonly HarnessOverlayEntry[] {
  return sources.filter((source): source is HarnessOverlayEntry => source !== 'baseline');
}

function derivedHarnessProvenance(
  sources: readonly HarnessContribution[],
): Pick<Tagged, 'provenance' | 'sourceFile' | 'sourceFiles' | 'layer'> {
  const overlays = overlayContributions(sources);
  if (overlays.length === 0) return { provenance: 'baseline' };
  const source = overlays.at(-1)!;
  return {
    provenance: sources.includes('baseline') ? 'baseline+overlay' : 'overlay',
    sourceFile: source.filename,
    sourceFiles: overlays.map((overlay) => overlay.filename),
    layer: source.layer,
  };
}

function derivedHarnessRows(harnesses: readonly MergedHarness[]): Tagged[] {
  return harnesses.flatMap((harness) =>
    deriveHarnessRules([harness]).map((rule): Tagged => {
      const sources = rule.id === `${harness.id}-config-dir`
        ? harness.configSources
        : harness.persistentSources.get(rule.id)!;
      return {
        family: 'protected_write',
        rule,
        ...derivedHarnessProvenance(sources),
        harnessId: rule.harnessId,
      };
    })
  );
}

function mergeHarnesses(
  baseline: readonly HarnessDeclaration[],
  overlayEntries: readonly HarnessOverlayEntry[],
): readonly MergedHarness[] {
  const persistentIds = new Set(baseline.flatMap((harness) => harness.persistent.map((persistent) => persistent.id)));
  const merged = new Map<string, MergedHarness>(baseline.map((harness) => [
    harness.id,
    {
      ...harness,
      configSources: ['baseline'],
      persistentSources: new Map(harness.persistent.map((persistent) => [persistent.id, ['baseline']])),
    },
  ]));
  const declaredInLayer = new Set<string>();

  for (const entry of overlayEntries) {
    const overlay = entry.declaration;
    const declarationKey = `${entry.layer}\u0000${overlay.id}`;
    if (declaredInLayer.has(declarationKey)) {
      return rejectHarness(entry, `harness id ${JSON.stringify(overlay.id)} is already declared by this overlay layer`);
    }
    declaredInLayer.add(declarationKey);

    const current = merged.get(overlay.id);
    if (current !== undefined) {
      if (overlay.persistent !== undefined) {
        return rejectHarness(entry, `harness ${JSON.stringify(overlay.id)} inherits persistent entries and cannot redefine them`);
      }
      if (overlay.reason !== undefined && overlay.reason !== current.reason) {
        return rejectHarness(entry, `harness ${JSON.stringify(overlay.id)} inherits its baseline reason`);
      }
      if (overlay.dir === undefined && overlay.parents === undefined && overlay.env === undefined) {
        return rejectHarness(entry, `harness ${JSON.stringify(overlay.id)} must append dir, parents, or env`);
      }
      const configChanged = overlay.dir !== undefined || overlay.parents !== undefined;
      merged.set(overlay.id, {
        ...current,
        dir: appendedAfterBaseline(current.dir, overlay.dir ?? []),
        ...(current.parents === undefined && overlay.parents === undefined
          ? {}
          : { parents: appendedAfterBaseline(current.parents ?? [], overlay.parents ?? []) }),
        env: appendedAfterBaseline(current.env, overlay.env ?? []),
        ...(configChanged ? { configSources: [...current.configSources, entry] } : {}),
        ...(overlay.dir === undefined
          ? {}
          : {
            persistentSources: new Map(
              [...current.persistentSources].map(([id, sources]) => [id, [...sources, entry]]),
            ),
          }),
      });
      continue;
    }

    if (
      overlay.dir === undefined || overlay.dir.length === 0 || overlay.env === undefined
      || overlay.reason === undefined || overlay.witness === undefined
    ) {
      return rejectHarness(entry, `new harness ${JSON.stringify(overlay.id)} requires dir, witness, env, and reason`);
    }
    for (const persistent of overlay.persistent ?? []) {
      if (persistentIds.has(persistent.id)) {
        return rejectHarness(entry, `harness persistent id ${JSON.stringify(persistent.id)} is already declared`);
      }
      persistentIds.add(persistent.id);
    }
    merged.set(overlay.id, {
      id: overlay.id,
      dir: overlay.dir,
      ...(overlay.parents === undefined ? {} : { parents: overlay.parents }),
      env: overlay.env,
      witness: overlay.witness,
      reason: overlay.reason,
      persistent: overlay.persistent ?? [],
      configSources: [entry],
      persistentSources: new Map((overlay.persistent ?? []).map((persistent) => [persistent.id, [entry]])),
    });
  }

  const effective = [...merged.values()];
  const derivedIds = new Map<string, MergedHarness>();
  for (const harness of effective) {
    for (const rule of deriveHarnessRules([harness])) {
      const existing = derivedIds.get(rule.id);
      if (existing === undefined) {
        derivedIds.set(rule.id, harness);
        continue;
      }
      const source = overlayContributions(
        harness.configSources.concat(harness.persistentSources.get(rule.id) ?? []),
      ).at(-1);
      if (source !== undefined) return rejectHarness(source, `derived protected-write id ${JSON.stringify(rule.id)} is not unique`);
      throw new Error(`baseline derived protected-write id ${JSON.stringify(rule.id)} is not unique`);
    }
  }
  return effective;
}

interface ParsedFile {
  readonly filename: string;
  readonly parsed: { rules?: unknown; override?: unknown; relax?: unknown; harness?: unknown; };
}

// Parses every file's TOML text, naming the ONE file at fault on the
// first failure — a read error readdir already proved present (never
// silently "absent") or a TOML syntax error, either way rejecting the
// LAYER this file belongs to (attemptCompose's retry loop drops it, the
// other layer keeps running). Called once per layer with that layer's own
// name and its (still plain) files — this is the ONE place a filename
// gets qualified ("policy.toml" -> "common:policy.toml"), threaded
// through every downstream provenance field (EffectiveRule.sourceFile,
// ActiveOverride.sourceFile, ...) from here on. The two throw sites below
// use the file's PLAIN name directly, already in hand — no need to
// decode it back out of the qualified form the way plainFile does
// elsewhere in this module.
function parseOverlayFiles(layer: string, files: readonly OverlayFile[]): ParsedFile[] {
  return files.map((file) => {
    const qualified = `${layer}:${file.filename}`;
    if ('readError' in file) {
      // readdir already proved this file exists — a subsequent read
      // failure (permission denied, a broken symlink, a directory
      // entry, a TOCTOU race) is never silently treated as "absent", it
      // rejects this layer exactly like a parse error, naming the file.
      throw new PolicyRejected([{ layer, file: file.filename, detail: file.readError }]);
    }
    try {
      return { filename: qualified, parsed: Bun.TOML.parse(file.text) as ParsedFile['parsed'] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new PolicyRejected([{ layer, file: file.filename, detail: message }]);
    }
  });
}

interface FileEntries {
  readonly overrides: readonly OverrideEntry[];
  readonly relax: readonly RelaxationEntry[];
  readonly askFlags: readonly AskFlagsRule[];
  readonly safeFirstArg: readonly SafeFirstArgRule[];
  readonly safeGrammar: readonly SafeGrammarRule[];
  readonly commandBash: readonly unknown[];
  readonly secretPath: readonly unknown[];
  readonly secretBash: readonly unknown[];
  readonly protectedWrite: readonly unknown[];
  readonly writeSecret: readonly unknown[];
  readonly prompt: readonly unknown[];
  readonly harness: readonly unknown[];
  readonly rmRfTargets: readonly string[];
  readonly privilegeCommands: readonly string[];
}

// Extracts and shape-validates ONE file's contribution to every rule
// table, throwing PolicyRejected (naming `layer` and `filename`) on the
// first shape violation — a wrong-typed field, a malformed declarative
// git-conditional entry, a direct write to one of the three relax-only
// allowlists, or an invalid [[relax]] entry. Shared by
// loadPolicyFromOverlayFiles and loadPolicyFromLayers: the
// field-extraction and per-file shape rules are identical either way —
// only how the CALLER tags and merges the result (single layer vs.
// cross-layer precedence) differs. `filename` is qualified (see
// parseOverlayFiles) — `layer` is what lets fileArray decode it back to
// a plain name for a RejectionIssue without guessing.
function extractFileEntries(layer: string, filename: string, parsed: ParsedFile['parsed']): FileEntries {
  const fileOverrides = fileArray<OverrideEntry>(parsed, ['override'], 'override', layer, filename);
  const fileRelax = fileArray<Record<string, unknown>>(parsed, ['relax'], 'relax', layer, filename);
  const fileAskFlags = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'ask_flags'],
    'rules.command.git.ask_flags',
    layer,
    filename,
  );
  const fileSafeFirstArg = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'safe_first_arg'],
    'rules.command.git.safe_first_arg',
    layer,
    filename,
  );
  const fileSafeGrammar = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'safe_grammar'],
    'rules.command.git.safe_grammar',
    layer,
    filename,
  );

  const shapeIssues = [
    ...lintAskFlagsShape(fileAskFlags),
    ...lintSafeFirstArgShape(fileSafeFirstArg),
    ...lintSafeGrammarShape(fileSafeGrammar),
  ];
  if (shapeIssues.length > 0) {
    throw new PolicyRejected([{
      layer,
      file: plainFile(layer, filename),
      detail: shapeIssues.map((i) => i.message).join('; '),
    }]);
  }

  if (getPath(parsed, ['rules', 'command', 'git', 'safe_subcommands']) !== undefined) {
    throw new PolicyRejected([{
      layer,
      file: plainFile(layer, filename),
      detail: `rules.command.git.safe_subcommands cannot be extended directly — use [[relax]] `
        + `(list = "command.git.safe_subcommands") with a reason`,
    }]);
  }
  if (getPath(parsed, ['rules', 'command', 'git', 'config_read_modes']) !== undefined) {
    throw new PolicyRejected([{
      layer,
      file: plainFile(layer, filename),
      detail: `rules.command.git.config_read_modes cannot be extended directly — use [[relax]] `
        + `(list = "command.git.config_read_modes") with a reason`,
    }]);
  }
  if (getPath(parsed, ['rules', 'mcp_write', 'read_prefixes']) !== undefined) {
    throw new PolicyRejected([{
      layer,
      file: plainFile(layer, filename),
      detail: `rules.mcp_write.read_prefixes cannot be extended directly — use [[relax]] `
        + `(list = "mcp_write.read_prefixes") with a reason`,
    }]);
  }

  const fileRelaxIssues = lintRelaxEntries(fileRelax);
  if (fileRelaxIssues.length > 0) {
    throw new PolicyRejected([{
      layer,
      file: plainFile(layer, filename),
      detail: fileRelaxIssues.map((i) => i.message).join('; '),
    }]);
  }

  return {
    overrides: fileOverrides,
    relax: fileRelax as unknown as RelaxationEntry[],
    askFlags: fileAskFlags as unknown as AskFlagsRule[],
    safeFirstArg: fileSafeFirstArg as unknown as SafeFirstArgRule[],
    safeGrammar: fileSafeGrammar as unknown as SafeGrammarRule[],
    commandBash: fileArray<unknown>(parsed, ['rules', 'command', 'bash'], 'rules.command.bash', layer, filename),
    secretPath: fileArray<unknown>(parsed, ['rules', 'secret', 'path'], 'rules.secret.path', layer, filename),
    secretBash: fileArray<unknown>(parsed, ['rules', 'secret', 'bash'], 'rules.secret.bash', layer, filename),
    protectedWrite: fileArray<unknown>(parsed, ['rules', 'protected_write'], 'rules.protected_write', layer, filename),
    writeSecret: fileArray<unknown>(parsed, ['rules', 'write_secret'], 'rules.write_secret', layer, filename),
    harness: fileArray<unknown>(parsed, ['harness'], 'harness', layer, filename),
    prompt: fileArray<unknown>(parsed, ['rules', 'prompt'], 'rules.prompt', layer, filename),
    rmRfTargets: fileArray<string>(
      parsed,
      ['rules', 'command', 'rm_rf', 'dangerous_targets'],
      'rules.command.rm_rf.dangerous_targets',
      layer,
      filename,
    ),
    privilegeCommands: fileArray<string>(
      parsed,
      ['rules', 'command', 'privilege_escalation', 'commands'],
      'rules.command.privilege_escalation.commands',
      layer,
      filename,
    ),
  };
}

// ---------------------------------------------------------------------
// Named layers (ADR-0001): common (~/.agents/bouncer/) then profile
// (<configDir>/bouncer/) — the profile wins on a shared target. This is
// the ONE pipeline: loadPolicyFromOverlayFiles (below, after
// loadPolicyFromLayers) is its one-layer, `name: 'profile'` degenerate
// case — a single-layer call, entries.layer identical for every entry,
// which is exactly what makes resolvePrecedence's cross-layer branch
// (`byLayer.size > 1`) unreachable and its behavior degenerate into "same
// key, two files → reject" (the property tests/policy-load.test.ts and
// tests/policy-load-multifile.test.ts already pin, now under a `profile:`
// qualified filename). Rejection is PER LAYER (ticket 21): a broken file
// rejects ITS layer only — see loadPolicyFromLayers's retry loop, below
// resolvePrecedence. What layering changes about conflicts is what "the
// same target in two files" MEANS: within one layer it is still an
// unconditional lint error; across layers it is precedence, not a
// conflict — see resolvePrecedence below.
// ---------------------------------------------------------------------

// Groups layer-tagged entries by target key (an override's `rule`, a
// relax's `list`+`value`, a declarative table's `sub`, a regex row's
// `id`), and immediately raises the same PolicyRejected shape
// loadPolicyFromOverlayFiles's pre-layering pipeline always raised for
// that target kind (`conflictMessage` supplies the template) on a
// same-layer conflict. Two DIFFERENT FILES contributing the same key
// WITHIN one layer is still that unconditional lint error — layering
// changes nothing about it (and with exactly one layer, this is the
// WHOLE check: `byLayer.size` can never exceed 1, so this degenerates
// into the old single-set "more than one file for this key" rule
// exactly). Across TWO OR MORE layers, the key is contested, not
// conflicting: the layer that sorts LAST in `layerOrder` wins, every
// earlier layer's entries for that key are dropped from the return
// value, and the survivor(s) carry `shadows` naming every earlier
// layer's (one per layer, since same-layer duplicates were already
// rejected above) file, joined — not just the first one, so a 3+-layer
// deployment (a future adapter, ticket 15) still names every layer it
// shadowed, not only the nearest.
function resolvePrecedence<E extends { readonly filename: string; readonly layer: string; }>(
  entries: readonly E[],
  keyOf: (e: E) => string,
  labelOf: (e: E) => string,
  layerOrder: readonly string[],
  conflictMessage: (label: string, files: readonly string[]) => string,
): readonly (E & { readonly shadows?: string; })[] {
  const byKey = new Map<string, E[]>();
  for (const e of entries) {
    const key = keyOf(e);
    const list = byKey.get(key) ?? [];
    list.push(e);
    byKey.set(key, list);
  }

  const kept: (E & { shadows?: string; })[] = [];

  for (const group of byKey.values()) {
    const byLayer = new Map<string, E[]>();
    for (const e of group) {
      const list = byLayer.get(e.layer) ?? [];
      list.push(e);
      byLayer.set(e.layer, list);
    }

    const conflicting = [...byLayer.values()].find((list) => new Set(list.map((e) => e.filename)).size > 1);
    if (conflicting !== undefined) {
      const files = [...new Set(conflicting.map((e) => e.filename))].toSorted();
      // No single file to name (the conflict is between two) — `layer`
      // is posed directly from the group, already in hand.
      throw new PolicyRejected([{ layer: conflicting[0]!.layer, detail: conflictMessage(labelOf(conflicting[0]!), files) }]);
    }

    if (byLayer.size === 1) {
      kept.push(...group);
      continue;
    }

    // Present in more than one layer: the later layer (per layerOrder)
    // wins outright — its entries survive as-is except for the `shadows`
    // annotation naming EVERY earlier layer's (single, per the
    // same-layer check above) file.
    const presentLayers = [...byLayer.keys()].toSorted((a, b) => layerOrder.indexOf(a) - layerOrder.indexOf(b));
    const winnerLayer = presentLayers.at(-1)!;
    const shadowedFiles = presentLayers.slice(0, -1).map((l) => byLayer.get(l)![0]!.filename).join(', ');
    for (const e of byLayer.get(winnerLayer)!) kept.push({ ...e, shadows: shadowedFiles });
  }

  return kept;
}

interface RegexCandidate {
  readonly filename: string;
  readonly layer: string;
  readonly raw: { readonly id: string; };
  // A stable identity for this candidate's SOURCE entry, assigned once at
  // Phase 1 push time (loadPolicyFromLayers's `nextSeq()`) — used (never
  // an object reference) to apply the precedence outcome (drop / keep +
  // shadow) back onto that entry's own family array. A key survives an
  // intermediate `.map()`/`.filter()` between "candidate built" and
  // "outcome applied" the way an object reference would not.
  readonly seq: number;
}

// Regex-table ids resolve GLOBALLY across all six families (same reason
// the pre-layering idConflicts check spanned all six, not per-table) —
// so cross-layer id precedence is computed once, over every family
// combined, not six times.
function regexIdCandidates(
  ...groups: readonly (readonly (FileTagged<unknown> & { readonly layer: string; readonly seq: number; })[])[]
): RegexCandidate[] {
  const out: RegexCandidate[] = [];
  for (const group of groups) {
    for (const entry of group) {
      if (hasStringId(entry.raw)) out.push({ filename: entry.filename, layer: entry.layer, raw: { id: entry.raw.id }, seq: entry.seq });
    }
  }
  return out;
}

// Converts lint.ts's flat LintIssue[] — message plus the entry's own
// layer/file, tagged by lintOverrides/lintGitConditionalRelaxation
// themselves at push time (never derived here) — into RejectionIssue[].
// A LintIssue with no `layer` gets UNATTRIBUTED_LAYER instead: reachable
// only if a future issue producer forgets to tag one (every producer this
// function is fed from does), and groupIssuesByLayer's single fail-closed
// branch treats that exactly like an issue naming a layer that isn't
// even among the ones currently being tried.
function toRejectionIssues(issues: readonly LintIssue[]): RejectionIssue[] {
  return issues.map((i) =>
    i.layer === undefined
      ? { layer: UNATTRIBUTED_LAYER, detail: i.message }
      : { layer: i.layer, ...(i.file !== undefined ? { file: plainFile(i.layer, i.file) } : {}), detail: i.message }
  );
}

// Groups a failed compose attempt's issues by the `layer` each one
// already carries (RejectionIssue — no parsing, see PolicyRejected), and
// folds each group into the single LayerRejectionInfo (file + reason)
// LoadResult.layers reports. Fail-closed, ONE branch: if ANY issue in
// this batch names a layer that isn't even among the ones being tried
// right now, the whole batch is untrustworthy — every surviving layer is
// rejected, rather than guessing which one an unattributable issue
// meant (reachable only via UNATTRIBUTED_LAYER, itself unreachable in
// practice).
function groupIssuesByLayer(issues: readonly RejectionIssue[], survivingLayers: readonly string[]): Map<string, LayerRejectionInfo> {
  const result = new Map<string, LayerRejectionInfo>();
  if (issues.some((i) => !survivingLayers.includes(i.layer))) {
    const reason = issues.map((i) => i.detail).join('; ');
    for (const layer of survivingLayers) result.set(layer, { file: layer, reason });
    return result;
  }
  for (const layer of new Set(issues.map((i) => i.layer))) {
    const layerIssues = issues.filter((i) => i.layer === layer);
    const primary = layerIssues.find((i) => i.file !== undefined);
    result.set(layer, {
      file: primary?.file ?? layer,
      reason: layerIssues.map((i) => i.detail).join('; '),
    });
  }
  return result;
}

// ADR-0001 § Rejection: "one policy-warning entry per rejected layer,
// naming the layer and the file" — one string per ORIGINALLY-given layer
// that ended up rejected, in the layer's own merge-order position (common
// before profile), never per retry iteration — a layer rejected on the
// first attempt and one rejected on a later cascade (the orphaned-override
// case) read identically here; the caller has no reason to see the retry
// mechanics.
function warningsFor(layers: readonly NamedLayer[], rejections: ReadonlyMap<string, LayerRejectionInfo>): string[] {
  return layers
    .filter((l) => rejections.has(l.name))
    .map((l) => {
      const r = rejections.get(l.name)!;
      return `${l.name} layer rejected — ${r.file}: ${r.reason}`;
    });
}

function finalizeLayerInfo(base: readonly LayerInfo[], rejections: ReadonlyMap<string, LayerRejectionInfo>): LayerInfo[] {
  return base.map((li) => {
    const rejected = rejections.get(li.name);
    return rejected === undefined ? li : { ...li, rejected };
  });
}

/**
 * One compose attempt over EXACTLY the layers given — the Phase 1/2/3
 * pipeline ticket 20 built (parse, layer-aware precedence, merge, lint),
 * unchanged in substance. Throws PolicyRejected (never returns a
 * rejection) so loadPolicyFromLayers's retry loop can attribute the
 * failure to a layer and retry without it — this function itself has no
 * notion of "a layer was already rejected", it only ever sees the
 * survivors it was called with.
 */
function attemptCompose(layers: readonly NamedLayer[]): Omit<LoadResult, 'layers'> {
  const layerOrder = layers.map((l) => l.name);

  const parsedFiles: (ParsedFile & { readonly layer: string; })[] = layers.flatMap((l) =>
    parseOverlayFiles(l.name, l.files).map((pf) => ({ ...pf, layer: l.name }))
  );

  type L<T> = FileTagged<T> & { readonly layer: string; readonly seq: number; };
  let nextSeq = 0;
  const seq = (): number => nextSeq++;

  const rawOverrides: L<OverrideEntry>[] = [];
  const rawRelax: L<RelaxationEntry>[] = [];
  const rawAskFlags: L<AskFlagsRule>[] = [];
  const rawSafeFirstArg: L<SafeFirstArgRule>[] = [];
  const rawSafeGrammar: L<SafeGrammarRule>[] = [];
  let rawCommandBash: L<unknown>[] = [];
  let rawSecretPath: L<unknown>[] = [];
  let rawSecretBash: L<unknown>[] = [];
  let rawProtectedWrite: L<unknown>[] = [];
  let rawWriteSecret: L<unknown>[] = [];
  let rawPrompt: L<unknown>[] = [];
  const rawHarness: L<unknown>[] = [];
  // Layer- and file-tagged — dangerous_targets has no `id` of its own to
  // carry through resolvePrecedence like the six regex families, it is
  // purely additive across layers (ADR-0001 § Merge order); `layer` here
  // is only for lintRmRfTargets to attribute a bad target back to it.
  const rmRfTagged: { readonly filename: string; readonly layer: string; readonly raw: string; }[] = [];
  let privilegeCommands: string[] = [];

  // Phase 1: identical per-file extraction to the pre-layering
  // pipeline (extractFileEntries), just also tagging each raw entry
  // with the layer it came from and a stable per-entry sequence number
  // (see RegexCandidate.seq).
  for (const { filename, parsed, layer } of parsedFiles) {
    const entries = extractFileEntries(layer, filename, parsed);
    for (const raw of entries.overrides) rawOverrides.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.relax) rawRelax.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.askFlags) rawAskFlags.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.safeFirstArg) rawSafeFirstArg.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.safeGrammar) rawSafeGrammar.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.commandBash) rawCommandBash.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.secretPath) rawSecretPath.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.secretBash) rawSecretBash.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.protectedWrite) rawProtectedWrite.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.writeSecret) rawWriteSecret.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.prompt) rawPrompt.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.harness) rawHarness.push({ filename, layer, raw, seq: seq() });
    for (const raw of entries.rmRfTargets) rmRfTagged.push({ filename, layer, raw });
    privilegeCommands = privilegeCommands.concat(entries.privilegeCommands);
  }

  // Phase 2: layer-aware resolution of the four precedence targets
  // (ADR-0001 § Precedence) — same-layer duplicate stays a lint error;
  // cross-layer duplicate is the later layer replacing the earlier one.
  const overrides = resolvePrecedence(
    rawOverrides,
    (o) => o.raw.rule,
    (o) => o.raw.rule,
    layerOrder,
    (label, files) => `conflicting [[override]] for rule ${JSON.stringify(label)} in ${files.join(' and ')}`,
  );
  const relax = resolvePrecedence(
    rawRelax,
    (r) => JSON.stringify([r.raw.list, r.raw.value]),
    (r) => `${r.raw.list}=${JSON.stringify(r.raw.value)}`,
    layerOrder,
    (label, files) => `conflicting [[relax]] for ${label} in ${files.join(' and ')}`,
  );
  const askFlags = resolvePrecedence(
    rawAskFlags,
    (e) => e.raw.sub,
    (e) => e.raw.sub,
    layerOrder,
    (label, files) => `conflicting command.git.ask_flags entries for sub ${JSON.stringify(label)} in ${files.join(' and ')}`,
  );
  const safeFirstArg = resolvePrecedence(
    rawSafeFirstArg,
    (e) => e.raw.sub,
    (e) => e.raw.sub,
    layerOrder,
    (label, files) => `conflicting command.git.safe_first_arg entries for sub ${JSON.stringify(label)} in ${files.join(' and ')}`,
  );
  const safeGrammar = resolvePrecedence(
    rawSafeGrammar,
    (e) => e.raw.sub,
    (e) => e.raw.sub,
    layerOrder,
    (label, files) => `conflicting command.git.safe_grammar entries for sub ${JSON.stringify(label)} in ${files.join(' and ')}`,
  );

  const regexCandidates = regexIdCandidates(
    rawCommandBash,
    rawSecretPath,
    rawSecretBash,
    rawProtectedWrite,
    rawWriteSecret,
    rawPrompt,
  );

  // ADR-0001 § Precedence: an overlay row reusing a BASELINE rule id is
  // rejected outright, before cross-layer precedence ever runs — checked
  // first so a profile row at a baseline id can never "shadow" a common
  // row at the same id and let the common layer survive carrying the
  // fault (precedence would silently keep the common entry's provenance
  // lying about what's actually in effect). Without this check the row
  // would get silently appended after the baseline row it collides with
  // (first-match-wins never lets it fire) while an `[[override]]` naming
  // that id would apply to BOTH rows at once. One issue per faulty row,
  // attributed to its own layer and file (`file` carries the attribution
  // — never repeated into `detail`, same convention every other throw
  // site in this function follows), so two independently-faulty layers
  // each get rejected by the retry loop below (see loadPolicyFromLayers)
  // exactly like any other per-layer fault.
  const baselineIdIssues: RejectionIssue[] = regexCandidates
    .filter((c) => BASELINE_RULE_IDS.has(c.raw.id))
    .map((c) => ({
      layer: c.layer,
      file: plainFile(c.layer, c.filename),
      detail: `regex rule id ${JSON.stringify(c.raw.id)} reuses a baseline rule id `
        + `— use [[override]] action = "replace"`,
    }));
  if (baselineIdIssues.length > 0) throw new PolicyRejected(baselineIdIssues);

  const regexKept = resolvePrecedence(
    regexCandidates,
    (c) => c.raw.id,
    (c) => c.raw.id,
    layerOrder,
    (label, files) => `conflicting regex rule id ${JSON.stringify(label)} in ${files.join(' and ')}`,
  );
  const keptSeqs = new Set(regexKept.map((c) => c.seq));
  const shadowsBySeq = new Map<number, string>();
  for (const c of regexKept) if (c.shadows !== undefined) shadowsBySeq.set(c.seq, c.shadows);
  const dropShadowed = (arr: readonly L<unknown>[]): L<unknown>[] =>
    arr
      .filter((e) => !hasStringId(e.raw) || keptSeqs.has(e.seq))
      .map((e) => (shadowsBySeq.has(e.seq) ? { ...e, shadows: shadowsBySeq.get(e.seq)! } : e));
  rawCommandBash = dropShadowed(rawCommandBash);
  rawSecretPath = dropShadowed(rawSecretPath);
  rawSecretBash = dropShadowed(rawSecretBash);
  rawProtectedWrite = dropShadowed(rawProtectedWrite);
  rawWriteSecret = dropShadowed(rawWriteSecret);
  rawPrompt = dropShadowed(rawPrompt);
  const mergedHarnesses = mergeHarnesses(
    BASELINE.rules.harness,
    rawHarness.map(({ raw, filename, layer }, index) => parseHarnessOverlayEntry(raw, { filename, layer }, index)),
  );
  const derivedRows = derivedHarnessRows(mergedHarnesses);

  const governedSubs = baselineGovernedSubs(BASELINE.rules.command.git);
  const gitConditionalEntries: GitConditionalEntries = { askFlags, safeFirstArg, safeGrammar };
  const conditionalReasonIssues = [
    ...lintGitConditionalRelaxation(gitConditionalEntries.askFlags, 'ask_flags', governedSubs),
    ...lintGitConditionalRelaxation(gitConditionalEntries.safeFirstArg, 'safe_first_arg', governedSubs),
    ...lintGitConditionalRelaxation(gitConditionalEntries.safeGrammar, 'safe_grammar', governedSubs),
  ];
  if (conditionalReasonIssues.length > 0) throw new PolicyRejected(toRejectionIssues(conditionalReasonIssues));

  // Phase 3: merge — the exact same pure functions the single-layer
  // case relies on. Precedence has already resolved every target down
  // to a plain additive set by this point, so the merge itself has no
  // layer-specific logic at all.
  const merged: MergedPolicy = {
    command: {
      bash: mergeRegexFamily('command.bash', BASELINE.rules.command.bash, rawCommandBash),
      rm_rf: {
        dangerous_targets: appendedAfterBaseline(BASELINE.rules.command.rm_rf.dangerous_targets, rmRfTagged.map((t) => t.raw)),
      },
      privilege_escalation: {
        commands: appendedAfterBaseline(BASELINE.rules.command.privilege_escalation.commands, privilegeCommands),
      },
      git: mergeGitPolicy(BASELINE.rules.command.git, gitConditionalEntries, relax),
    },
    secret: {
      path: mergeRegexFamily('secret.path', BASELINE.rules.secret.path, rawSecretPath),
      bash: mergeRegexFamily('secret.bash', BASELINE.rules.secret.bash, rawSecretBash),
    },
    protected_write: [
      ...derivedRows,
      ...mergeRegexFamily(
        'protected_write',
        BASELINE.rules.protected_write.filter((rule) => !isDerivedHarnessRule(rule)),
        rawProtectedWrite,
      ),
    ],
    harness: mergedHarnesses,
    mcp_write: {
      read_prefixes: appendedAfterBaseline(BASELINE.rules.mcp_write.read_prefixes, relaxedValuesFor(relax, 'mcp_write.read_prefixes')),
    },
    write_secret: mergeRegexFamily('write_secret', BASELINE.rules.write_secret, rawWriteSecret),
    prompt: mergeRegexFamily('prompt', BASELINE.rules.prompt, rawPrompt),
  };
  assertUniqueEffectiveRuleIds(merged);

  const dialectIssues = [...lintMergedDialect(merged), ...lintRmRfTargets(rmRfTagged)];
  if (dialectIssues.length > 0) throw new PolicyRejected(dialectIssues);

  const resolvable = resolvableRuleIds({
    command: { ...merged.command, bash: merged.command.bash.map((t) => t.rule) },
    secret: { path: merged.secret.path.map((t) => t.rule), bash: merged.secret.bash.map((t) => t.rule) },
    protected_write: merged.protected_write.map((t) => t.rule),
    harness: merged.harness,
    mcp_write: merged.mcp_write,
    write_secret: merged.write_secret.map((t) => t.rule),
    prompt: merged.prompt.map((t) => t.rule),
  });
  const overrideIssues = lintOverrides(overrides, resolvable);
  if (overrideIssues.length > 0) throw new PolicyRejected(toRejectionIssues(overrideIssues));

  const effective = applyOverrides(allTagged(merged), overrides);

  const postOverrideDialectIssues = lintEffectiveDialect(effective);
  if (postOverrideDialectIssues.length > 0) throw new PolicyRejected(toRejectionIssues(postOverrideDialectIssues));

  const activeRelaxations = buildActiveRelaxations(relax, gitConditionalEntries, governedSubs);
  const activeOverrides = buildActiveOverrides(overrides);

  return buildResult(
    merged,
    effective,
    true,
    parsedFiles.map((f) => f.filename),
    activeOverrides,
    activeRelaxations,
    [],
  );
}

/**
 * Loads the effective policy from NAMED layers (ADR-0001) — embedded
 * baseline, then every layer in `layers` order, each read the same way
 * (`policy.toml` first, then `policy.d/*.toml` lexicographically — the
 * adapter's job, not this function's). A LATER layer's entry for the
 * same target (a git `sub` in one of the three conditional tables, a
 * `[[relax]]` list+value, an `[[override]]` rule, a regex row `id`)
 * replaces an EARLIER layer's — never a conflict — and carries `shadows`
 * naming the file(s) it replaced. Two files of the SAME layer sharing a
 * target is still an unconditional lint error (resolvePrecedence).
 *
 * Rejection is PER LAYER (ticket 21, ADR-0001 § Rejection): attemptCompose
 * is retried with progressively fewer layers whenever it throws, each
 * retry dropping exactly the layer(s) groupIssuesByLayer attributes the
 * failure to — a broken common file drops common, keeps profile; a broken
 * profile file drops profile, keeps common. The one cascade: a surviving
 * profile `[[override]]` whose target lived in a JUST-dropped common layer
 * no longer resolves, which attemptCompose's own lintOverrides catches on
 * the retry — that failure is attributed to the PROFILE file carrying the
 * override, so profile is rejected too, and the loop bottoms out at the
 * baseline alone. Two layers converge in at most two retries; a future
 * third layer (ticket 15) in at most three.
 *
 * `layers` on the returned LoadResult always names every ORIGINAL layer's
 * root (when it exists) and the files it was given, win or lose — a
 * rejected one additionally carries `rejected: {file, reason}`. `warnings`
 * carries exactly one entry per rejected layer, not one per retry — this
 * is the ONE pipeline: loadPolicyFromOverlayFiles (below) is this
 * function's one-layer case, nothing else.
 */
export function loadPolicyFromLayers(layers: readonly NamedLayer[]): LoadResult {
  const layerInfoBase: readonly LayerInfo[] = layers.map((l) => ({
    name: l.name,
    ...(l.root !== undefined ? { root: l.root } : {}),
    files: l.files.map((f) => f.filename),
  }));

  const rejections = new Map<string, LayerRejectionInfo>();
  let surviving: readonly NamedLayer[] = layers;

  for (;;) {
    // Nothing left to try (every layer either absent or rejected — an
    // empty `surviving` array also satisfies `.every()` below, vacuously),
    // or what's left has no files at all (e.g. common survived but was
    // always empty) — either way this IS the baseline-alone case, not a
    // compose attempt with nothing to do.
    if (surviving.every((l) => l.files.length === 0)) {
      return {
        ...baselineOnlyResult(warningsFor(layers, rejections)),
        layers: finalizeLayerInfo(layerInfoBase, rejections),
      };
    }

    try {
      const composed = attemptCompose(surviving);
      return {
        ...composed,
        warnings: warningsFor(layers, rejections),
        layers: finalizeLayerInfo(layerInfoBase, rejections),
      };
    } catch (err) {
      if (!(err instanceof PolicyRejected)) throw err;
      const survivingNames = surviving.map((l) => l.name);
      // Fail-closed, ONE branch (see groupIssuesByLayer): an issue naming
      // a layer that isn't among `survivingNames` rejects every one of
      // them, same as an issue cleanly attributed to a subset — either
      // way this is guaranteed non-empty, so `surviving` strictly shrinks
      // every iteration and the loop terminates within `layers.length`
      // retries.
      const grouped = groupIssuesByLayer(err.issues, survivingNames);
      for (const [layerName, info] of grouped) rejections.set(layerName, info);
      surviving = surviving.filter((l) => !grouped.has(l.name));
    }
  }
}

/**
 * Single-layer convenience entry point — `loadPolicyFromLayers([{ name:
 * 'profile', files }])` and nothing else. An empty list is "no overlay at
 * all": baseline alone, silently. Never throws: any failure anywhere in
 * the set — invalid TOML in any one file, a wrong-shaped rule table, a
 * lint-failing regex or declarative entry, an unresolvable/reason-less
 * override/relax, a silent-relaxation attempt missing its mandatory
 * reason, a cross-file conflict on the same override/relax/declarative
 * target — rejects the WHOLE set and returns the baseline alone, with the
 * reason (naming the offending file(s), qualified `profile:...`) in
 * `warnings`.
 */
export function loadPolicyFromOverlayFiles(files: readonly OverlayFile[]): LoadResult {
  return loadPolicyFromLayers([{ name: 'profile', files }]);
}

/**
 * Single-file convenience wrapper around loadPolicyFromOverlayFiles —
 * test-only now: no production caller reaches for this, the real
 * (adapter) path calls loadCurrentPolicy's own two-layer
 * loadPolicyFromLayers call directly. `null` and blank text are both "no
 * overlay file present" — baseline alone, silently (matches the
 * original, pre-ticket-12 behavior exactly).
 */
export function loadPolicyFromOverlayText(overlayText: string | null): LoadResult {
  if (overlayText === null || overlayText.trim() === '') return loadPolicyFromOverlayFiles([]);
  return loadPolicyFromOverlayFiles([{ filename: 'policy.toml', text: overlayText }]);
}
