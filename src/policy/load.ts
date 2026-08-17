// Policy loading: baseline + overlay merge, `[[relax]]`/`[[override]]`
// application, and the fail-closed fallback contract — a malformed or
// lint-failing overlay NEVER partially applies and never fails open; it is
// rejected as a whole, the embedded baseline stays fully active, and the
// rejection is a loud warning (surfaced by both the audit log and
// `rules list`), never a silent swallow. Pure — no filesystem access (see
// src/adapter/policy.ts for reading the overlay files off disk).
//
// The overlay is a SET of files, not one (ticket 12) — `policy.toml` (if
// present), then every `policy.d/*.toml` file the adapter found, in
// lexicographic filename order (src/adapter/policy.ts decides that order;
// this module just processes whatever list it's given, in the order
// given). Every failure mode stays collective across the whole set: one
// bad file rejects everything, never a partial merge of "the files that
// happened to be fine". `loadPolicyFromOverlayText` is a thin single-file
// wrapper — test-only now (no production caller reaches for it; the real
// path, src/adapter/policy.ts's loadCurrentPolicy, always builds a file
// list and calls loadPolicyFromOverlayFiles directly).

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
  // The overlay filename this entry came from ("policy.toml",
  // "policy.d/10-npm.toml", ...) — present for 'overlay' and 'override'
  // provenance, absent for 'baseline' (the embedded baseline has no file
  // on disk to name).
  readonly sourceFile?: string;
}

export interface ActiveOverride extends OverrideEntry {
  readonly sourceFile: string;
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
}

export interface FileTagged<T> {
  readonly filename: string;
  readonly raw: T;
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
  const overlayTagged: Tagged[] = overlayEntries.map(({ filename, raw }) => {
    if (
      raw === null || typeof raw !== 'object'
      || typeof (raw as Record<string, unknown>).id !== 'string'
      || typeof (raw as Record<string, unknown>).regex !== 'string'
      || typeof (raw as Record<string, unknown>).reason !== 'string'
    ) {
      throw new PolicyRejected(`${filename}: ${family}: an overlay rule is missing a required string field (id/regex/reason)`);
    }
    return { family, rule: raw as RegexRule, provenance: 'overlay' as const, sourceFile: filename };
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
// necessary). The SAME `sub` substituted by two DIFFERENT overlay files is
// rejected outright before this function ever runs (see
// crossFileConflicts below) — there is no "which overlay file wins"
// question left to answer positionally by the time this executes.
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
// overrides on the same rule id WITHIN one file still chain sequentially,
// exactly as before this ticket (e.g. replace then relax) — only a
// cross-FILE conflict on the same rule id is rejected, and that rejection
// happens earlier, before this function is ever called (see
// crossFileConflicts).
function applyOverrides(tagged: readonly Tagged[], overrides: readonly FileTagged<OverrideEntry>[]): EffectiveRule[] {
  let current: EffectiveRule[] = tagged.map((t) => ({
    family: t.family,
    rule: t.rule,
    provenance: t.provenance,
    ...(t.sourceFile !== undefined ? { sourceFile: t.sourceFile } : {}),
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

function buildResult(
  merged: MergedPolicy,
  effective: readonly EffectiveRule[],
  overlayApplied: boolean,
  overlayFiles: readonly string[],
  activeOverrides: readonly ActiveOverride[],
  activeRelaxations: readonly ActiveRelaxation[],
  warnings: readonly string[],
): LoadResult {
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

function baselineOnlyResult(warnings: readonly string[] = []): LoadResult {
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
      .map((e) => ({ list: `command.git.${table}`, value: e.raw.sub, reason: e.raw.reason!, sourceFile: e.filename }));
  return [
    ...relax.map((r) => ({ list: r.raw.list, value: r.raw.value, reason: r.raw.reason, sourceFile: r.filename })),
    ...fromGitConditional(entries.askFlags, 'ask_flags'),
    ...fromGitConditional(entries.safeFirstArg, 'safe_first_arg'),
    ...fromGitConditional(entries.safeGrammar, 'safe_grammar'),
  ];
}

// Detects the SAME conflict target (an override's `rule`, a relax's
// `list`+`value`, a declarative entry's `sub`) contributed by more than
// one FILE — an explicit lint failure, never a silent "last file wins".
// Multiple entries for the same target WITHIN one file are unaffected by
// this check (existing single-file semantics: sequential override
// chaining, first-entry-wins table lookup) — only cross-file duplication
// is ambiguous enough to reject outright.
//
// `keyOf` is only ever used to GROUP entries (map equality, never shown to
// a human) — it can encode however it likes. `labelOf` produces the
// human-readable label straight from the raw entry, once per key, for the
// caller's error message; it is never derived by re-parsing `keyOf`'s
// output, which used to be `${list} ${value}` re-split on a space — lossy
// for any `value` that itself contains a space.
function crossFileConflicts<T>(
  entries: readonly FileTagged<T>[],
  keyOf: (v: T) => string,
  labelOf: (v: T) => string,
): { readonly label: string; readonly files: readonly string[]; }[] {
  const byKey = new Map<string, { label: string; files: Set<string>; }>();
  for (const { filename, raw } of entries) {
    const key = keyOf(raw);
    const entry = byKey.get(key) ?? { label: labelOf(raw), files: new Set<string>() };
    entry.files.add(filename);
    byKey.set(key, entry);
  }
  const conflicts: { label: string; files: string[]; }[] = [];
  for (const { label, files } of byKey.values()) {
    if (files.size > 1) conflicts.push({ label, files: [...files].toSorted() });
  }
  return conflicts;
}

// The three declarative git-conditional tables' cross-file conflict check
// is the same shape three times over (group by `sub`, reject if more than
// one file contributes the same one) — one helper, called once per table,
// instead of three near-identical crossFileConflicts-call-then-.map(...)
// blocks.
function declarativeTableConflicts(
  table: string,
  entries: readonly FileTagged<{ readonly sub: string; }>[],
): { readonly table: string; readonly label: string; readonly files: readonly string[]; }[] {
  return crossFileConflicts(entries, (e) => e.sub, (e) => e.sub).map((c) => ({ ...c, table }));
}

// Narrows a raw (not-yet-shape-validated) regex-table entry to its `id`,
// when it has a string one — used only to DETECT a cross-file id
// collision early (Phase 2, before merge); the authoritative "id/regex/
// reason must all be strings" shape check still lives in
// mergeRegexFamily (Phase 3), which independently rejects a
// non-string-id entry regardless of this function's leniency here.
function withStringId(entries: readonly FileTagged<unknown>[]): FileTagged<{ readonly id: string; }>[] {
  const out: FileTagged<{ readonly id: string; }>[] = [];
  for (const { filename, raw } of entries) {
    const id = raw !== null && typeof raw === 'object' ? (raw as Record<string, unknown>).id : undefined;
    if (typeof id === 'string') out.push({ filename, raw: { id } });
  }
  return out;
}

interface ParsedFile {
  readonly filename: string;
  readonly parsed: { rules?: unknown; override?: unknown; relax?: unknown; };
}

/**
 * Loads the effective policy from a SET of overlay files — `policy.toml`
 * and every `policy.d/*.toml` file, in the order given (the adapter is
 * responsible for that order: policy.toml first, then policy.d files
 * lexicographically). An empty list is "no overlay at all": baseline
 * alone, silently. Never throws: any failure anywhere in the set —
 * invalid TOML in any one file, a wrong-shaped rule table, a lint-failing
 * regex or declarative entry, an unresolvable/reason-less
 * override/relax, a silent-relaxation attempt missing its mandatory
 * reason, a cross-file conflict on the same override/relax/declarative
 * target — rejects the WHOLE set and returns the baseline alone, with the
 * reason (naming the offending file(s)) in `warnings`.
 */
export function loadPolicyFromOverlayFiles(files: readonly OverlayFile[]): LoadResult {
  if (files.length === 0) return baselineOnlyResult();

  try {
    const parsedFiles: ParsedFile[] = files.map((file) => {
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

    const rawOverrides: FileTagged<OverrideEntry>[] = [];
    const rawRelax: FileTagged<RelaxationEntry>[] = [];
    const rawAskFlags: FileTagged<AskFlagsRule>[] = [];
    const rawSafeFirstArg: FileTagged<SafeFirstArgRule>[] = [];
    const rawSafeGrammar: FileTagged<SafeGrammarRule>[] = [];
    const rawCommandBash: FileTagged<unknown>[] = [];
    const rawSecretPath: FileTagged<unknown>[] = [];
    const rawSecretBash: FileTagged<unknown>[] = [];
    const rawWriteSecret: FileTagged<unknown>[] = [];
    const rawPrompt: FileTagged<unknown>[] = [];
    let rmRfTargets: string[] = [];
    let privilegeCommands: string[] = [];

    // Phase 1: per-file extraction and per-file shape validation, in the
    // order the files were given. A failure here always names the ONE
    // file it came from.
    for (const { filename, parsed } of parsedFiles) {
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

      for (const raw of fileOverrides) rawOverrides.push({ filename, raw });
      for (const raw of fileRelax) rawRelax.push({ filename, raw: raw as unknown as RelaxationEntry });
      for (const raw of fileAskFlags) rawAskFlags.push({ filename, raw: raw as unknown as AskFlagsRule });
      for (const raw of fileSafeFirstArg) rawSafeFirstArg.push({ filename, raw: raw as unknown as SafeFirstArgRule });
      for (const raw of fileSafeGrammar) rawSafeGrammar.push({ filename, raw: raw as unknown as SafeGrammarRule });
      for (const raw of fileArray<unknown>(parsed, ['rules', 'command', 'bash'], 'rules.command.bash', filename)) {
        rawCommandBash.push({ filename, raw });
      }
      for (const raw of fileArray<unknown>(parsed, ['rules', 'secret', 'path'], 'rules.secret.path', filename)) {
        rawSecretPath.push({ filename, raw });
      }
      for (const raw of fileArray<unknown>(parsed, ['rules', 'secret', 'bash'], 'rules.secret.bash', filename)) {
        rawSecretBash.push({ filename, raw });
      }
      for (const raw of fileArray<unknown>(parsed, ['rules', 'write_secret'], 'rules.write_secret', filename)) {
        rawWriteSecret.push({ filename, raw });
      }
      for (const raw of fileArray<unknown>(parsed, ['rules', 'prompt'], 'rules.prompt', filename)) {
        rawPrompt.push({ filename, raw });
      }
      rmRfTargets = rmRfTargets.concat(
        fileArray<string>(parsed, ['rules', 'command', 'rm_rf', 'dangerous_targets'], 'rules.command.rm_rf.dangerous_targets', filename),
      );
      privilegeCommands = privilegeCommands.concat(
        fileArray<string>(
          parsed,
          ['rules', 'command', 'privilege_escalation', 'commands'],
          'rules.command.privilege_escalation.commands',
          filename,
        ),
      );
    }

    // Phase 2: cross-file conflicts — the same override/relax/declarative
    // substitution target named by more than one file is ambiguous,
    // rejected explicitly rather than resolved by silent file order.
    const overrideConflicts = crossFileConflicts(rawOverrides, (o) => o.rule, (o) => o.rule);
    if (overrideConflicts.length > 0) {
      throw new PolicyRejected(
        overrideConflicts
          .map((c) => `conflicting [[override]] for rule ${JSON.stringify(c.label)} in ${c.files.join(' and ')}`)
          .join('; '),
      );
    }
    const relaxConflicts = crossFileConflicts(
      rawRelax,
      (r) => JSON.stringify([r.list, r.value]),
      (r) => `${r.list}=${JSON.stringify(r.value)}`,
    );
    if (relaxConflicts.length > 0) {
      throw new PolicyRejected(
        relaxConflicts
          .map((c) => `conflicting [[relax]] for ${c.label} in ${c.files.join(' and ')}`)
          .join('; '),
      );
    }
    const declarativeConflicts = [
      ...declarativeTableConflicts('ask_flags', rawAskFlags),
      ...declarativeTableConflicts('safe_first_arg', rawSafeFirstArg),
      ...declarativeTableConflicts('safe_grammar', rawSafeGrammar),
    ];
    if (declarativeConflicts.length > 0) {
      throw new PolicyRejected(
        declarativeConflicts
          .map((c) => `conflicting command.git.${c.table} entries for sub ${JSON.stringify(c.label)} in ${c.files.join(' and ')}`)
          .join('; '),
      );
    }
    // Carried from ticket 12's review, decided in ticket 13: the SAME
    // regex-rule id defined by two DIFFERENT overlay files is ambiguous
    // the same way an override/relax/sub conflict is — ids resolve
    // GLOBALLY (resolvableRuleIds has no per-family scoping, and
    // applyOverrides matches by id alone across every regex table), so a
    // duplicate is checked across all five regex families combined, not
    // per-table.
    const idConflicts = crossFileConflicts(
      withStringId([...rawCommandBash, ...rawSecretPath, ...rawSecretBash, ...rawWriteSecret, ...rawPrompt]),
      (e) => e.id,
      (e) => e.id,
    );
    if (idConflicts.length > 0) {
      throw new PolicyRejected(
        idConflicts
          .map((c) => `conflicting regex rule id ${JSON.stringify(c.label)} in ${c.files.join(' and ')}`)
          .join('; '),
      );
    }

    const governedSubs = baselineGovernedSubs(BASELINE.rules.command.git);
    const gitConditionalEntries: GitConditionalEntries = {
      askFlags: rawAskFlags,
      safeFirstArg: rawSafeFirstArg,
      safeGrammar: rawSafeGrammar,
    };
    const conditionalReasonIssues = [
      ...lintGitConditionalRelaxation(gitConditionalEntries.askFlags, 'ask_flags', governedSubs),
      ...lintGitConditionalRelaxation(gitConditionalEntries.safeFirstArg, 'safe_first_arg', governedSubs),
      ...lintGitConditionalRelaxation(gitConditionalEntries.safeGrammar, 'safe_grammar', governedSubs),
    ];
    if (conditionalReasonIssues.length > 0) throw new PolicyRejected(conditionalReasonIssues.map((i) => i.message).join('; '));

    // Phase 3: merge, in file order.
    const merged: MergedPolicy = {
      command: {
        bash: mergeRegexFamily('command.bash', BASELINE.rules.command.bash, rawCommandBash),
        rm_rf: { dangerous_targets: appendedAfterBaseline(BASELINE.rules.command.rm_rf.dangerous_targets, rmRfTargets) },
        privilege_escalation: {
          commands: appendedAfterBaseline(BASELINE.rules.command.privilege_escalation.commands, privilegeCommands),
        },
        git: mergeGitPolicy(BASELINE.rules.command.git, gitConditionalEntries, rawRelax),
      },
      secret: {
        path: mergeRegexFamily('secret.path', BASELINE.rules.secret.path, rawSecretPath),
        bash: mergeRegexFamily('secret.bash', BASELINE.rules.secret.bash, rawSecretBash),
      },
      mcp_write: {
        read_prefixes: appendedAfterBaseline(BASELINE.rules.mcp_write.read_prefixes, relaxedValuesFor(rawRelax, 'mcp_write.read_prefixes')),
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
    const overrideIssues = lintOverrides(rawOverrides, resolvable);
    if (overrideIssues.length > 0) throw new PolicyRejected(overrideIssues.map((i) => i.message).join('; '));

    const effective = applyOverrides(allTagged(merged), rawOverrides);

    // Re-lint the dialect AFTER override application — an action="replace"
    // override injects a regex the merged-set pass above never saw. This
    // is what closes the "override regex bypasses the dialect" hole:
    // unconditional, every load, not conditioned on whether an override
    // happened to fire.
    const postOverrideDialectIssues = lintEffectiveDialect(effective);
    if (postOverrideDialectIssues.length > 0) throw new PolicyRejected(postOverrideDialectIssues.join('; '));

    const activeRelaxations = buildActiveRelaxations(rawRelax, gitConditionalEntries, governedSubs);
    const activeOverrides: ActiveOverride[] = rawOverrides.map(({ filename, raw }) => ({ ...raw, sourceFile: filename }));

    return buildResult(
      merged,
      effective,
      true,
      parsedFiles.map((f) => f.filename),
      activeOverrides,
      activeRelaxations,
      [],
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return baselineOnlyResult([
      `overlay policy rejected — falling back to the embedded baseline: ${message}`,
    ]);
  }
}

/**
 * Single-file convenience wrapper around loadPolicyFromOverlayFiles —
 * test-only now: no production caller reaches for this, the real
 * (adapter) path calls loadPolicyFromOverlayFiles directly and applies
 * this same "null/blank means no overlay" rule itself, before ever
 * building the file list (see src/adapter/policy.ts's readOverlayFile).
 * `null` and blank text are both "no overlay file present" — baseline
 * alone, silently (matches the original, pre-ticket-12 behavior exactly).
 */
export function loadPolicyFromOverlayText(overlayText: string | null): LoadResult {
  if (overlayText === null || overlayText.trim() === '') return baselineOnlyResult();
  return loadPolicyFromOverlayFiles([{ filename: 'policy.toml', text: overlayText }]);
}
