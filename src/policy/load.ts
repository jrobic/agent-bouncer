// Policy loading: baseline + overlay merge, `[[relax]]`/`[[override]]`
// application, and the fail-closed fallback contract — a malformed or
// lint-failing overlay NEVER partially applies and never fails open; it is
// rejected as a whole, the embedded baseline stays fully active, and the
// rejection is a loud warning (surfaced by both the audit log and
// `rules list`), never a silent swallow. Pure — no filesystem access (see
// src/adapter/policy.ts for reading the overlay file off disk).

import { BASELINE } from './baseline.ts';
import {
  lintAskFlagsShape,
  lintEffectiveDialect,
  lintGitConditionalRelaxation,
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
}

// A relaxation actively in effect — an allowlist addition via `[[relax]]`,
// or a git-conditional overlay entry substituting an already-governed
// baseline subcommand. Always carries a reason (lint-enforced).
export interface ActiveRelaxation {
  readonly list: string;
  readonly value: string;
  readonly reason: string;
}

export interface LoadResult {
  readonly policy: RulesPolicy;
  readonly effectiveRules: readonly EffectiveRule[];
  readonly warnings: readonly string[];
  readonly overlayApplied: boolean;
  readonly activeOverrides: readonly OverrideEntry[];
  readonly activeRelaxations: readonly ActiveRelaxation[];
}

interface Tagged {
  readonly family: string;
  readonly rule: RegexRule;
  readonly provenance: 'baseline' | 'overlay';
}

// A structural-shape error at the merge boundary (wrong-typed field) and a
// lint failure both take the same path out: reject the whole overlay.
class PolicyRejected extends Error {}

function asArray<T>(value: unknown, path: string): readonly T[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new PolicyRejected(`${path} must be an array`);
  return value as T[];
}

function mergeRegexFamily(
  family: string,
  baseline: readonly RegexRule[],
  overlay: readonly unknown[],
): Tagged[] {
  const overlayTagged: Tagged[] = overlay.map((raw) => {
    if (
      raw === null || typeof raw !== 'object'
      || typeof (raw as Record<string, unknown>).id !== 'string'
      || typeof (raw as Record<string, unknown>).regex !== 'string'
      || typeof (raw as Record<string, unknown>).reason !== 'string'
    ) {
      throw new PolicyRejected(`${family}: an overlay rule is missing a required string field (id/regex/reason)`);
    }
    return { family, rule: raw as RegexRule, provenance: 'overlay' as const };
  });
  const baselineTagged: Tagged[] = baseline.map((rule) => ({ family, rule, provenance: 'baseline' as const }));
  // Regex tables: pure hardening. An overlay addition only ever adds a new
  // BLOCK/confirm signature — it can never relax an existing one — so it
  // stays silently additive, appended after the vetted baseline set.
  return appendedAfterBaseline(baselineTagged, overlayTagged);
}

// Regex-table families (and the two plain danger lists, rm_rf/privilege):
// baseline first, overlay entries appended after. The name says the order:
// an overlay addition can only ever ADD a new signature (pure hardening),
// never shadow or replace a vetted baseline entry by position.
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
// lintGitConditionalRelaxation, which this asymmetry is what makes necessary).
function overlayTakesPrecedence<T>(overlay: readonly T[], baseline: readonly T[]): T[] {
  return [...overlay, ...baseline];
}

function relaxedValuesFor(relax: readonly RelaxationEntry[], list: RelaxableList): string[] {
  return relax.filter((r) => r.list === list).map((r) => r.value);
}

interface MergedPolicy {
  readonly command: {
    readonly bash: Tagged[];
    readonly rm_rf: { readonly dangerous_targets: readonly string[] };
    readonly privilege_escalation: { readonly commands: readonly string[] };
    readonly git: RulesPolicy['command']['git'];
  };
  readonly secret: { readonly path: Tagged[]; readonly bash: Tagged[] };
  readonly mcp_write: { readonly read_prefixes: readonly string[] };
  readonly write_secret: Tagged[];
  readonly prompt: Tagged[];
}

function mergeGitPolicy(
  baseline: RulesPolicy['command']['git'],
  o: Record<string, unknown> | undefined,
  relax: readonly RelaxationEntry[],
): RulesPolicy['command']['git'] {
  return {
    // Additions here can ONLY come from [[relax]] (reason-mandatory,
    // lint-enforced) — a plain `rules.command.git.safe_subcommands`/
    // `config_read_modes` entry in the overlay's [rules] table is rejected
    // before mergeAll is ever called (see loadPolicyFromOverlayText).
    safe_subcommands: appendedAfterBaseline(
      baseline.safe_subcommands,
      relaxedValuesFor(relax, 'command.git.safe_subcommands'),
    ),
    config_read_modes: appendedAfterBaseline(
      baseline.config_read_modes,
      relaxedValuesFor(relax, 'command.git.config_read_modes'),
    ),
    ask_flags: overlayTakesPrecedence(asArray<AskFlagsRule>(o?.['ask_flags'], 'rules.command.git.ask_flags'), baseline.ask_flags),
    safe_first_arg: overlayTakesPrecedence(
      asArray<SafeFirstArgRule>(o?.['safe_first_arg'], 'rules.command.git.safe_first_arg'),
      baseline.safe_first_arg,
    ),
    safe_grammar: overlayTakesPrecedence(
      asArray<SafeGrammarRule>(o?.['safe_grammar'], 'rules.command.git.safe_grammar'),
      baseline.safe_grammar,
    ),
  };
}

function mergeAll(baseline: RulesPolicy, overlayRules: unknown, relax: readonly RelaxationEntry[]): MergedPolicy {
  const o = (overlayRules ?? {}) as Record<string, any>;
  const oCommand = o.command ?? {};
  const oSecret = o.secret ?? {};

  return {
    command: {
      bash: mergeRegexFamily('command.bash', baseline.command.bash, asArray(oCommand.bash, 'rules.command.bash')),
      rm_rf: {
        dangerous_targets: appendedAfterBaseline(
          baseline.command.rm_rf.dangerous_targets,
          asArray<string>(oCommand.rm_rf?.dangerous_targets, 'rules.command.rm_rf.dangerous_targets'),
        ),
      },
      privilege_escalation: {
        commands: appendedAfterBaseline(
          baseline.command.privilege_escalation.commands,
          asArray<string>(oCommand.privilege_escalation?.commands, 'rules.command.privilege_escalation.commands'),
        ),
      },
      git: mergeGitPolicy(baseline.command.git, oCommand.git, relax),
    },
    secret: {
      path: mergeRegexFamily('secret.path', baseline.secret.path, asArray(oSecret.path, 'rules.secret.path')),
      bash: mergeRegexFamily('secret.bash', baseline.secret.bash, asArray(oSecret.bash, 'rules.secret.bash')),
    },
    mcp_write: {
      read_prefixes: appendedAfterBaseline(
        baseline.mcp_write.read_prefixes,
        relaxedValuesFor(relax, 'mcp_write.read_prefixes'),
      ),
    },
    write_secret: mergeRegexFamily('write_secret', baseline.write_secret, asArray(o.write_secret, 'rules.write_secret')),
    prompt: mergeRegexFamily('prompt', baseline.prompt, asArray(o.prompt, 'rules.prompt')),
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
    for (const issue of lintRegexSource(t.rule.regex, t.rule.flags)) {
      issues.push(`${t.family} rule ${JSON.stringify(t.rule.id)}: ${issue.message}`);
    }
    if (t.rule.except !== undefined) {
      for (const issue of lintRegexSource(t.rule.except, t.rule.flags)) {
        issues.push(`${t.family} rule ${JSON.stringify(t.rule.id)} (except): ${issue.message}`);
      }
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
// sharing an id, so an override touches every entry sharing it).
function applyOverrides(tagged: readonly Tagged[], overrides: readonly OverrideEntry[]): EffectiveRule[] {
  let current: EffectiveRule[] = tagged.map((t) => ({ family: t.family, rule: t.rule, provenance: t.provenance }));
  for (const override of overrides) {
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
        }];
      }
      // relax
      return [{
        family: entry.family,
        rule: { ...entry.rule, verdict_override: override.verdict } as RegexRule,
        provenance: 'override',
        overrideAction: 'relax',
        overrideReason: override.reason,
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
  activeOverrides: readonly OverrideEntry[],
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
  return { policy, effectiveRules: effective, overlayApplied, activeOverrides, activeRelaxations, warnings };
}

function baselineOnlyResult(warnings: readonly string[] = []): LoadResult {
  const merged = mergeAll(BASELINE.rules, undefined, []);
  const effective = applyOverrides(allTagged(merged), []);
  return buildResult(merged, effective, false, [], [], warnings);
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
  relax: readonly RelaxationEntry[],
  rawAskFlags: readonly { readonly sub: string; readonly reason?: string }[],
  rawSafeFirstArg: readonly { readonly sub: string; readonly reason?: string }[],
  rawSafeGrammar: readonly { readonly sub: string; readonly reason?: string }[],
  governedSubs: ReadonlySet<string>,
): ActiveRelaxation[] {
  const fromGitConditional = (
    entries: readonly { readonly sub: string; readonly reason?: string }[],
    table: string,
  ): ActiveRelaxation[] =>
    entries
      .filter((e) => governedSubs.has(e.sub))
      .map((e) => ({ list: `command.git.${table}`, value: e.sub, reason: e.reason! }));
  return [
    ...relax.map((r) => ({ list: r.list, value: r.value, reason: r.reason })),
    ...fromGitConditional(rawAskFlags, 'ask_flags'),
    ...fromGitConditional(rawSafeFirstArg, 'safe_first_arg'),
    ...fromGitConditional(rawSafeGrammar, 'safe_grammar'),
  ];
}

/**
 * Loads the effective policy from raw overlay TEXT (or `null` for "no
 * overlay file present"). Never throws: any failure — invalid TOML, a
 * wrong-shaped rule table, a lint-failing regex or declarative entry, an
 * unresolvable/reason-less override, a silent-relaxation attempt missing
 * its mandatory reason — rejects the WHOLE overlay and returns the
 * baseline alone, with the reason in `warnings`.
 */
export function loadPolicyFromOverlayText(overlayText: string | null): LoadResult {
  if (overlayText === null) return baselineOnlyResult();
  if (overlayText.trim() === '') return baselineOnlyResult();

  try {
    const parsed = Bun.TOML.parse(overlayText) as { rules?: unknown; override?: unknown; relax?: unknown };
    const rawOverrides = asArray<OverrideEntry>(parsed.override, 'override');
    const rawRelax = asArray<Record<string, unknown>>(parsed.relax, 'relax');

    const rulesRaw = (parsed.rules ?? {}) as Record<string, any>;
    const oGit = (rulesRaw.command ?? {}).git ?? {};
    const rawAskFlags = asArray<Record<string, unknown>>(oGit.ask_flags, 'rules.command.git.ask_flags');
    const rawSafeFirstArg = asArray<Record<string, unknown>>(oGit.safe_first_arg, 'rules.command.git.safe_first_arg');
    const rawSafeGrammar = asArray<Record<string, unknown>>(oGit.safe_grammar, 'rules.command.git.safe_grammar');

    // Shape-validate the three declarative forms before anything
    // downstream (governed-subs check, merge, the checker itself) reads
    // their fields — a malformed entry must fail lint, not throw at match
    // time.
    const shapeIssues = [
      ...lintAskFlagsShape(rawAskFlags),
      ...lintSafeFirstArgShape(rawSafeFirstArg),
      ...lintSafeGrammarShape(rawSafeGrammar),
    ];
    if (shapeIssues.length > 0) throw new PolicyRejected(shapeIssues.map((i) => i.message).join('; '));

    // The three pure allowlists can only be widened through [[relax]]
    // (reason-mandatory) — a direct addition via [rules.command.git] or
    // [rules.mcp_write] bypasses that requirement and is rejected outright.
    if (oGit.safe_subcommands !== undefined) {
      throw new PolicyRejected(
        'rules.command.git.safe_subcommands cannot be extended directly — use [[relax]] '
          + '(list = "command.git.safe_subcommands") with a reason',
      );
    }
    if (oGit.config_read_modes !== undefined) {
      throw new PolicyRejected(
        'rules.command.git.config_read_modes cannot be extended directly — use [[relax]] '
          + '(list = "command.git.config_read_modes") with a reason',
      );
    }
    if ((rulesRaw.mcp_write ?? {}).read_prefixes !== undefined) {
      throw new PolicyRejected(
        'rules.mcp_write.read_prefixes cannot be extended directly — use [[relax]] '
          + '(list = "mcp_write.read_prefixes") with a reason',
      );
    }

    const relaxIssues = lintRelaxEntries(rawRelax);
    if (relaxIssues.length > 0) throw new PolicyRejected(relaxIssues.map((i) => i.message).join('; '));
    const relax = rawRelax as unknown as RelaxationEntry[];

    const governedSubs = baselineGovernedSubs(BASELINE.rules.command.git);
    const conditionalReasonIssues = [
      ...lintGitConditionalRelaxation(rawAskFlags as { sub: string; reason?: string }[], 'ask_flags', governedSubs),
      ...lintGitConditionalRelaxation(rawSafeFirstArg as { sub: string; reason?: string }[], 'safe_first_arg', governedSubs),
      ...lintGitConditionalRelaxation(rawSafeGrammar as { sub: string; reason?: string }[], 'safe_grammar', governedSubs),
    ];
    if (conditionalReasonIssues.length > 0) throw new PolicyRejected(conditionalReasonIssues.map((i) => i.message).join('; '));

    const merged = mergeAll(BASELINE.rules, parsed.rules, relax);

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

    const activeRelaxations = buildActiveRelaxations(
      relax,
      rawAskFlags as { sub: string; reason?: string }[],
      rawSafeFirstArg as { sub: string; reason?: string }[],
      rawSafeGrammar as { sub: string; reason?: string }[],
      governedSubs,
    );

    return buildResult(merged, effective, true, rawOverrides, activeRelaxations, []);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return baselineOnlyResult([
      `overlay policy rejected — falling back to the embedded baseline: ${message}`,
    ]);
  }
}
