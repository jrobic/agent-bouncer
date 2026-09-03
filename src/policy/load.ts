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
// naming it (see resolvePrecedence). Failure stays collective across the
// WHOLE load, both layers: one bad file, in either layer, rejects
// everything, never a partial merge of "the files/layers that happened
// to be fine" (per-layer rejection is a later ticket).
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
import type {
  AskFlagsRule,
  OverrideEntry,
  RegexRule,
  RelaxableList,
  RelaxationEntry,
  RulesPolicy,
  SafeFirstArgRule,
  SafeGrammarRule,
} from './schema.ts';

export type Provenance = 'baseline' | 'overlay' | 'override';

export interface EffectiveRule {
  readonly family: string;
  readonly rule: RegexRule;
  readonly provenance: Provenance;
  readonly overrideAction?: 'replace' | 'relax';
  readonly overrideReason?: string;
  // The overlay filename this entry came from — present for 'overlay'
  // and 'override' provenance, absent for 'baseline' (the embedded
  // baseline has no file on disk to name). Always layer-qualified
  // ("common:policy.toml", "profile:policy.d/10-npm.toml") — every
  // LoadResult comes from loadPolicyFromLayers now
  // (loadPolicyFromOverlayFiles is its one-layer, `name: 'profile'` case).
  readonly sourceFile?: string;
  // ADR-0001 § Precedence: set only when this entry won cross-layer
  // precedence over an earlier layer's entry for the SAME target — names
  // the shadowed entry's qualified file (e.g. "common:policy.d/100-x.toml").
  // Only loadPolicyFromLayers ever sets this.
  readonly shadows?: string;
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
  readonly provenance: 'baseline' | 'overlay';
  readonly sourceFile?: string;
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

// A structural-shape error at the merge boundary (wrong-typed field) and a
// lint failure both take the same path out: reject the whole overlay SET.
class PolicyRejected extends Error {}

function getPath(obj: unknown, path: readonly string[]): unknown {
  let cur: unknown = obj;
  for (const key of path) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

// Reads an array-shaped field at `path` out of one file's parsed TOML,
// naming that file if the field is present but not an array. Absent is
// fine — an empty contribution, not a failure.
function fileArray<T>(parsed: unknown, path: readonly string[], displayPath: string, filename: string): readonly T[] {
  const value = getPath(parsed, path);
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new PolicyRejected(`${filename}: ${displayPath} must be an array`);
  return value as T[];
}

function mergeRegexFamily(
  family: string,
  baseline: readonly RegexRule[],
  overlayEntries: readonly FileTagged<unknown>[],
): Tagged[] {
  const overlayTagged: Tagged[] = overlayEntries.map(({ filename, raw, shadows }) => {
    if (
      raw === null || typeof raw !== 'object'
      || typeof (raw as Record<string, unknown>).id !== 'string'
      || typeof (raw as Record<string, unknown>).regex !== 'string'
      || typeof (raw as Record<string, unknown>).reason !== 'string'
    ) {
      throw new PolicyRejected(`${filename}: ${family}: an overlay rule is missing a required string field (id/regex/reason)`);
    }
    return {
      family,
      rule: raw as RegexRule,
      provenance: 'overlay' as const,
      sourceFile: filename,
      ...(shadows !== undefined ? { shadows } : {}),
    };
  });
  const baselineTagged: Tagged[] = baseline.map((rule) => ({ family, rule, provenance: 'baseline' as const }));
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
// POST-override pass an action="replace" injected regex needs.
function lintMergedDialect(merged: MergedPolicy): string[] {
  const issues: string[] = [];
  for (const t of allTagged(merged)) {
    const prefix = t.sourceFile !== undefined ? `${t.sourceFile}: ` : '';
    // lintOneRule covers regex/except dialect AND the row's own `verdict`
    // field (schema.ts's RegexRule) — an overlay row's verdict is
    // validated here exactly like a baseline row's, not just at the
    // single-file lintRegexDialect layer.
    for (const issue of lintOneRule(t.family, t.rule)) {
      issues.push(`${prefix}${issue.message}`);
    }
  }
  for (const target of merged.command.rm_rf.dangerous_targets) {
    for (const issue of lintRegexSource(target)) {
      issues.push(`command.rm_rf.dangerous_targets: ${issue.message}`);
    }
  }
  return issues;
}

function allTagged(merged: MergedPolicy): Tagged[] {
  return [
    ...merged.command.bash,
    ...merged.secret.path,
    ...merged.secret.bash,
    ...merged.write_secret,
    ...merged.prompt,
  ];
}

// Applies every [[override]] to the tagged rule it names (by id — id is
// not guaranteed unique within a family, e.g. a family with two entries
// sharing an id, so an override touches every entry sharing it). Multiple
// overrides on the same rule id WITHIN one file still chain sequentially
// (e.g. replace then relax) — a cross-FILE conflict on the same rule id
// (within one layer) is rejected before this function is ever called,
// and a cross-LAYER one is resolved down to a single surviving entry by
// the same point (see resolvePrecedence).
function applyOverrides(tagged: readonly Tagged[], overrides: readonly FileTagged<OverrideEntry>[]): EffectiveRule[] {
  let current: EffectiveRule[] = tagged.map((t) => ({
    family: t.family,
    rule: t.rule,
    provenance: t.provenance,
    ...(t.sourceFile !== undefined ? { sourceFile: t.sourceFile } : {}),
    ...(t.shadows !== undefined ? { shadows: t.shadows } : {}),
  }));
  for (const { filename, raw: override } of overrides) {
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

interface ParsedFile {
  readonly filename: string;
  readonly parsed: { rules?: unknown; override?: unknown; relax?: unknown; };
}

// Parses every file's TOML text, naming the ONE file at fault on the
// first failure — a read error readdir already proved present (never
// silently "absent") or a TOML syntax error, either way rejecting the
// whole set. Shared by loadPolicyFromOverlayFiles (called on its own flat
// list) and loadPolicyFromLayers (called once per layer, on filenames
// already qualified with that layer's name — see qualifyLayerFiles).
function parseOverlayFiles(files: readonly OverlayFile[]): ParsedFile[] {
  return files.map((file) => {
    if ('readError' in file) {
      // readdir already proved this file exists — a subsequent read
      // failure (permission denied, a broken symlink, a directory
      // entry, a TOCTOU race) is never silently treated as "absent",
      // it rejects the whole set exactly like a parse error, naming
      // the file.
      throw new PolicyRejected(`${file.filename}: ${file.readError}`);
    }
    try {
      return { filename: file.filename, parsed: Bun.TOML.parse(file.text) as ParsedFile['parsed'] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new PolicyRejected(`${file.filename}: ${message}`);
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
  readonly writeSecret: readonly unknown[];
  readonly prompt: readonly unknown[];
  readonly rmRfTargets: readonly string[];
  readonly privilegeCommands: readonly string[];
}

// Extracts and shape-validates ONE file's contribution to every rule
// table, throwing PolicyRejected (naming `filename`) on the first shape
// violation — a wrong-typed field, a malformed declarative git-conditional
// entry, a direct write to one of the three relax-only allowlists, or an
// invalid [[relax]] entry. Shared by loadPolicyFromOverlayFiles and
// loadPolicyFromLayers: the field-extraction and per-file shape rules are
// identical either way — only how the CALLER tags and merges the result
// (unqualified vs. layer-qualified, single set vs. cross-layer precedence)
// differs.
function extractFileEntries(filename: string, parsed: ParsedFile['parsed']): FileEntries {
  const fileOverrides = fileArray<OverrideEntry>(parsed, ['override'], 'override', filename);
  const fileRelax = fileArray<Record<string, unknown>>(parsed, ['relax'], 'relax', filename);
  const fileAskFlags = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'ask_flags'],
    'rules.command.git.ask_flags',
    filename,
  );
  const fileSafeFirstArg = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'safe_first_arg'],
    'rules.command.git.safe_first_arg',
    filename,
  );
  const fileSafeGrammar = fileArray<Record<string, unknown>>(
    parsed,
    ['rules', 'command', 'git', 'safe_grammar'],
    'rules.command.git.safe_grammar',
    filename,
  );

  const shapeIssues = [
    ...lintAskFlagsShape(fileAskFlags),
    ...lintSafeFirstArgShape(fileSafeFirstArg),
    ...lintSafeGrammarShape(fileSafeGrammar),
  ];
  if (shapeIssues.length > 0) throw new PolicyRejected(`${filename}: ${shapeIssues.map((i) => i.message).join('; ')}`);

  if (getPath(parsed, ['rules', 'command', 'git', 'safe_subcommands']) !== undefined) {
    throw new PolicyRejected(
      `${filename}: rules.command.git.safe_subcommands cannot be extended directly — use [[relax]] `
        + `(list = "command.git.safe_subcommands") with a reason`,
    );
  }
  if (getPath(parsed, ['rules', 'command', 'git', 'config_read_modes']) !== undefined) {
    throw new PolicyRejected(
      `${filename}: rules.command.git.config_read_modes cannot be extended directly — use [[relax]] `
        + `(list = "command.git.config_read_modes") with a reason`,
    );
  }
  if (getPath(parsed, ['rules', 'mcp_write', 'read_prefixes']) !== undefined) {
    throw new PolicyRejected(
      `${filename}: rules.mcp_write.read_prefixes cannot be extended directly — use [[relax]] `
        + `(list = "mcp_write.read_prefixes") with a reason`,
    );
  }

  const fileRelaxIssues = lintRelaxEntries(fileRelax);
  if (fileRelaxIssues.length > 0) throw new PolicyRejected(`${filename}: ${fileRelaxIssues.map((i) => i.message).join('; ')}`);

  return {
    overrides: fileOverrides,
    relax: fileRelax as unknown as RelaxationEntry[],
    askFlags: fileAskFlags as unknown as AskFlagsRule[],
    safeFirstArg: fileSafeFirstArg as unknown as SafeFirstArgRule[],
    safeGrammar: fileSafeGrammar as unknown as SafeGrammarRule[],
    commandBash: fileArray<unknown>(parsed, ['rules', 'command', 'bash'], 'rules.command.bash', filename),
    secretPath: fileArray<unknown>(parsed, ['rules', 'secret', 'path'], 'rules.secret.path', filename),
    secretBash: fileArray<unknown>(parsed, ['rules', 'secret', 'bash'], 'rules.secret.bash', filename),
    writeSecret: fileArray<unknown>(parsed, ['rules', 'write_secret'], 'rules.write_secret', filename),
    prompt: fileArray<unknown>(parsed, ['rules', 'prompt'], 'rules.prompt', filename),
    rmRfTargets: fileArray<string>(
      parsed,
      ['rules', 'command', 'rm_rf', 'dangerous_targets'],
      'rules.command.rm_rf.dangerous_targets',
      filename,
    ),
    privilegeCommands: fileArray<string>(
      parsed,
      ['rules', 'command', 'privilege_escalation', 'commands'],
      'rules.command.privilege_escalation.commands',
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
// qualified filename). Rejection stays collective across BOTH layers
// (ticket 21 makes it per-layer): any broken file, in either layer,
// rejects the whole load and falls back to the baseline. What layering
// changes is what "the same target in two files" MEANS: within one layer
// it is still an unconditional lint error; across layers it is
// precedence, not a conflict — see resolvePrecedence below.
// ---------------------------------------------------------------------

// Qualifies every file's display name with its layer ("policy.toml" under
// layer "common" becomes "common:policy.toml") — this is the ONE string
// every downstream warning, sourceFile, and file listing threads through
// from here on, including loadPolicyFromOverlayFiles's (qualified
// `profile:...`, since it is now just the one-layer call).
function qualifyLayerFiles(layerName: string, files: readonly OverlayFile[]): OverlayFile[] {
  return files.map((file) =>
    'readError' in file
      ? { filename: `${layerName}:${file.filename}`, readError: file.readError }
      : { filename: `${layerName}:${file.filename}`, text: file.text }
  );
}

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
      throw new PolicyRejected(conflictMessage(labelOf(conflicting[0]!), files));
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

// Regex-table ids resolve GLOBALLY across all five families (same reason
// the pre-layering idConflicts check spanned all five, not per-table) —
// so cross-layer id precedence is computed once, over every family
// combined, not five times.
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
 * Rejection stays collective (ticket 21 makes it per-layer): any failure
 * anywhere — in either layer — rejects the WHOLE load, falling back to
 * the baseline alone. `layers` on the returned LoadResult always names
 * every layer's root (when it exists) and the files it contributed, win
 * or lose — this is the ONE pipeline: loadPolicyFromOverlayFiles (below)
 * is this function's one-layer case, nothing else.
 */
export function loadPolicyFromLayers(layers: readonly NamedLayer[]): LoadResult {
  const layerInfo: readonly LayerInfo[] = layers.map((l) => ({
    name: l.name,
    ...(l.root !== undefined ? { root: l.root } : {}),
    files: l.files.map((f) => f.filename),
  }));
  const layerOrder = layers.map((l) => l.name);

  if (layers.every((l) => l.files.length === 0)) {
    return { ...baselineOnlyResult(), layers: layerInfo };
  }

  try {
    const parsedFiles: (ParsedFile & { readonly layer: string; })[] = layers.flatMap((l) =>
      parseOverlayFiles(qualifyLayerFiles(l.name, l.files)).map((pf) => ({ ...pf, layer: l.name }))
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
    let rawWriteSecret: L<unknown>[] = [];
    let rawPrompt: L<unknown>[] = [];
    let rmRfTargets: string[] = [];
    let privilegeCommands: string[] = [];

    // Phase 1: identical per-file extraction to the pre-layering
    // pipeline (extractFileEntries), just also tagging each raw entry
    // with the layer it came from and a stable per-entry sequence number
    // (see RegexCandidate.seq).
    for (const { filename, parsed, layer } of parsedFiles) {
      const entries = extractFileEntries(filename, parsed);
      for (const raw of entries.overrides) rawOverrides.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.relax) rawRelax.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.askFlags) rawAskFlags.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.safeFirstArg) rawSafeFirstArg.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.safeGrammar) rawSafeGrammar.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.commandBash) rawCommandBash.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.secretPath) rawSecretPath.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.secretBash) rawSecretBash.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.writeSecret) rawWriteSecret.push({ filename, layer, raw, seq: seq() });
      for (const raw of entries.prompt) rawPrompt.push({ filename, layer, raw, seq: seq() });
      rmRfTargets = rmRfTargets.concat(entries.rmRfTargets);
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

    const regexCandidates = regexIdCandidates(rawCommandBash, rawSecretPath, rawSecretBash, rawWriteSecret, rawPrompt);
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
    rawWriteSecret = dropShadowed(rawWriteSecret);
    rawPrompt = dropShadowed(rawPrompt);

    const governedSubs = baselineGovernedSubs(BASELINE.rules.command.git);
    const gitConditionalEntries: GitConditionalEntries = { askFlags, safeFirstArg, safeGrammar };
    const conditionalReasonIssues = [
      ...lintGitConditionalRelaxation(gitConditionalEntries.askFlags, 'ask_flags', governedSubs),
      ...lintGitConditionalRelaxation(gitConditionalEntries.safeFirstArg, 'safe_first_arg', governedSubs),
      ...lintGitConditionalRelaxation(gitConditionalEntries.safeGrammar, 'safe_grammar', governedSubs),
    ];
    if (conditionalReasonIssues.length > 0) throw new PolicyRejected(conditionalReasonIssues.map((i) => i.message).join('; '));

    // Phase 3: merge — the exact same pure functions the single-layer
    // case relies on. Precedence has already resolved every target down
    // to a plain additive set by this point, so the merge itself has no
    // layer-specific logic at all.
    const merged: MergedPolicy = {
      command: {
        bash: mergeRegexFamily('command.bash', BASELINE.rules.command.bash, rawCommandBash),
        rm_rf: { dangerous_targets: appendedAfterBaseline(BASELINE.rules.command.rm_rf.dangerous_targets, rmRfTargets) },
        privilege_escalation: {
          commands: appendedAfterBaseline(BASELINE.rules.command.privilege_escalation.commands, privilegeCommands),
        },
        git: mergeGitPolicy(BASELINE.rules.command.git, gitConditionalEntries, relax),
      },
      secret: {
        path: mergeRegexFamily('secret.path', BASELINE.rules.secret.path, rawSecretPath),
        bash: mergeRegexFamily('secret.bash', BASELINE.rules.secret.bash, rawSecretBash),
      },
      mcp_write: {
        read_prefixes: appendedAfterBaseline(BASELINE.rules.mcp_write.read_prefixes, relaxedValuesFor(relax, 'mcp_write.read_prefixes')),
      },
      write_secret: mergeRegexFamily('write_secret', BASELINE.rules.write_secret, rawWriteSecret),
      prompt: mergeRegexFamily('prompt', BASELINE.rules.prompt, rawPrompt),
    };

    const dialectIssues = lintMergedDialect(merged);
    if (dialectIssues.length > 0) throw new PolicyRejected(dialectIssues.join('; '));

    const resolvable = resolvableRuleIds({
      command: { ...merged.command, bash: merged.command.bash.map((t) => t.rule) },
      secret: { path: merged.secret.path.map((t) => t.rule), bash: merged.secret.bash.map((t) => t.rule) },
      mcp_write: merged.mcp_write,
      write_secret: merged.write_secret.map((t) => t.rule),
      prompt: merged.prompt.map((t) => t.rule),
    });
    const overrideIssues = lintOverrides(overrides, resolvable);
    if (overrideIssues.length > 0) throw new PolicyRejected(overrideIssues.map((i) => i.message).join('; '));

    const effective = applyOverrides(allTagged(merged), overrides);

    const postOverrideDialectIssues = lintEffectiveDialect(effective);
    if (postOverrideDialectIssues.length > 0) throw new PolicyRejected(postOverrideDialectIssues.join('; '));

    const activeRelaxations = buildActiveRelaxations(relax, gitConditionalEntries, governedSubs);
    const activeOverrides = buildActiveOverrides(overrides);

    return {
      ...buildResult(
        merged,
        effective,
        true,
        parsedFiles.map((f) => f.filename),
        activeOverrides,
        activeRelaxations,
        [],
      ),
      layers: layerInfo,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ...baselineOnlyResult([`overlay policy rejected — falling back to the embedded baseline: ${message}`]),
      layers: layerInfo,
    };
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
