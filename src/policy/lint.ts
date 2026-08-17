// Policy validation: the RE2-like (lookaround-free, backreference-free)
// regex dialect — enforced by actually COMPILING every regex, not by
// string-matching a denylist of syntax — the shape of the three
// declarative git-conditional overlay forms, `[[relax]]` entries, and
// `[[override]]` resolution. Both baseline and overlay run through this
// before being trusted — the baseline is expected to always pass (it is
// the vetted set); the overlay's failures are what trigger the
// loud-warning fallback in load.ts.

import type { EffectiveRule, FileTagged } from './load.ts';
import type { OverrideEntry, RawPolicyFile, RegexRule } from './schema.ts';

export interface LintIssue {
  readonly message: string;
}

// `(?=`, `(?!` — lookahead. `(?<=`, `(?<!` — lookbehind.
const LOOKAROUND = /\(\?<?[=!]/;
// `\1` through `\9` — numbered backreferences. (`\0` and `\10`+ are not
// backreference syntax in JS regex; the dialect ban is specifically the
// classic single-digit backreference form RE2 has no equivalent for.)
const BACKREFERENCE = /\\[1-9]/;

// `g` carries mutable `lastIndex` state across calls on the SAME RegExp
// object — compileRules builds one RegExp per rule and reuses it across
// every match call, so a `g`-flagged rule matches on call N and silently
// skips on call N+1 (probed: alternates hit/miss). `y` (sticky) has the
// same `lastIndex` hazard. `i`/`m`/`s` carry no cross-call state.
const ALLOWED_FLAGS = new Set(['i', 'm', 's']);

function lintFlags(flags: string | undefined): LintIssue[] {
  if (flags === undefined) return [];
  const issues: LintIssue[] = [];
  for (const f of flags) {
    if (!ALLOWED_FLAGS.has(f)) {
      issues.push({
        message: `regex flags ${JSON.stringify(flags)} include disallowed flag ${JSON.stringify(f)} `
          + `— only i/m/s are permitted (g/y carry cross-call lastIndex state a reused RegExp cannot safely hold)`,
      });
    }
  }
  return issues;
}

// The authoritative dialect gate: an actual `new RegExp(...)` compile,
// not a string-match approximation. Lookaround/backreference get their
// own pre-check for a clearer message; compilation additionally catches
// anything else invalid (an unclosed group like `([a-z`, a bad flag
// combination, ...).
export function lintRegexSource(pattern: string, flags?: string): LintIssue[] {
  const issues: LintIssue[] = [];
  if (LOOKAROUND.test(pattern)) {
    issues.push({
      message: `regex ${JSON.stringify(pattern)} uses a lookaround assertion — outside the RE2-like dialect`,
    });
  }
  if (BACKREFERENCE.test(pattern)) {
    issues.push({
      message: `regex ${JSON.stringify(pattern)} uses a backreference (\\1-\\9) — outside the RE2-like dialect`,
    });
  }
  issues.push(...lintFlags(flags));
  try {
    // Compiled only to prove it compiles — the RegExp itself is discarded.
    void new RegExp(pattern, [...(flags ?? '')].filter((f) => ALLOWED_FLAGS.has(f)).join(''));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    issues.push({ message: `regex ${JSON.stringify(pattern)} failed to compile: ${message}` });
  }
  return issues;
}

function allRegexRules(rules: RawPolicyFile['rules']): readonly [family: string, rule: RegexRule][] {
  return [
    ...rules.command.bash.map((r): [string, RegexRule] => ['command.bash', r]),
    ...rules.secret.path.map((r): [string, RegexRule] => ['secret.path', r]),
    ...rules.secret.bash.map((r): [string, RegexRule] => ['secret.bash', r]),
    ...rules.write_secret.map((r): [string, RegexRule] => ['write_secret', r]),
    ...rules.prompt.map((r): [string, RegexRule] => ['prompt', r]),
  ];
}

function lintOneRule(family: string, rule: RegexRule): LintIssue[] {
  const issues: LintIssue[] = [];
  for (const issue of lintRegexSource(rule.regex, rule.flags)) {
    issues.push({ message: `${family} rule ${JSON.stringify(rule.id)}: ${issue.message}` });
  }
  if (rule.except !== undefined) {
    for (const issue of lintRegexSource(rule.except, rule.flags)) {
      issues.push({ message: `${family} rule ${JSON.stringify(rule.id)} (except): ${issue.message}` });
    }
  }
  return issues;
}

// Every regex-bearing field (`regex`, and `except` where present) across
// every family's regex table must stay inside the dialect. Used on the
// baseline+overlay merged set (pre-override) — see lintEffectiveDialect
// for the post-override pass an action="replace" injected regex needs too.
export function lintRegexDialect(file: RawPolicyFile): LintIssue[] {
  const issues: LintIssue[] = [];
  for (const [family, rule] of allRegexRules(file.rules)) {
    issues.push(...lintOneRule(family, rule));
  }
  for (const target of file.rules.command.rm_rf.dangerous_targets) {
    for (const issue of lintRegexSource(target)) {
      issues.push({ message: `command.rm_rf.dangerous_targets: ${issue.message}` });
    }
  }
  return issues;
}

// The post-`applyOverrides` pass: an action="replace" override injects a
// brand-new regex into the effective set that lintRegexDialect (run
// before overrides applied) never saw. Running this after application —
// and always, unconditionally, not just when an override happens to have
// fired — is what closes that bypass regardless of match order.
export function lintEffectiveDialect(effective: readonly EffectiveRule[]): LintIssue[] {
  const issues: LintIssue[] = [];
  for (const entry of effective) {
    const prefix = entry.sourceFile !== undefined ? `${entry.sourceFile}: ` : '';
    for (const issue of lintOneRule(entry.family, entry.rule)) {
      issues.push({ message: `${prefix}${issue.message}` });
    }
  }
  return issues;
}

// Every ruleId a [[override]] entry is allowed to name — the regex rules
// only (the {id, regex, reason} tables). Git-conditional forms and plain
// allowlists (safe_subcommands, read_prefixes, ...) have no per-entry id
// and are out of scope for override targeting in this ticket.
export function resolvableRuleIds(rules: RawPolicyFile['rules']): ReadonlySet<string> {
  return new Set(allRegexRules(rules).map(([, rule]) => rule.id));
}

const VALID_ACTIONS = new Set(['disable', 'replace', 'relax']);
const VALID_VERDICTS = new Set(['block', 'confirm', 'observe']);

export function lintOverrides(
  overrides: readonly FileTagged<OverrideEntry>[],
  resolvable: ReadonlySet<string>,
): LintIssue[] {
  const issues: LintIssue[] = [];
  for (const { filename, raw: override } of overrides) {
    const prefix = `${filename}: `;
    if (!override.reason || override.reason.trim() === '') {
      issues.push({ message: `${prefix}override on ${JSON.stringify(override.rule)}: reason must not be empty` });
    }
    if (!resolvable.has(override.rule)) {
      issues.push({
        message: `${prefix}override rule ${JSON.stringify(override.rule)} does not resolve to any known rule id`,
      });
    }
    if (!VALID_ACTIONS.has(override.action)) {
      issues.push({
        message: `${prefix}override on ${JSON.stringify(override.rule)}: action ${JSON.stringify(override.action)} `
          + `is not one of disable/replace/relax`,
      });
    }
    if (override.action === 'replace') {
      if (override.regex === undefined || override.regex.trim() === '') {
        issues.push({
          message: `${prefix}override on ${JSON.stringify(override.rule)}: action "replace" requires a "regex" field`,
        });
      } else {
        for (const issue of lintRegexSource(override.regex)) {
          issues.push({ message: `${prefix}override on ${JSON.stringify(override.rule)} (regex): ${issue.message}` });
        }
      }
    }
    if (override.action === 'relax') {
      if (override.verdict === undefined) {
        issues.push({
          message: `${prefix}override on ${JSON.stringify(override.rule)}: action "relax" requires a "verdict" field`,
        });
      } else if (!VALID_VERDICTS.has(override.verdict)) {
        issues.push({
          message: `${prefix}override on ${JSON.stringify(override.rule)}: verdict ${JSON.stringify(override.verdict)} `
            + `is not one of block/confirm/observe`,
        });
      }
    }
  }
  return issues;
}

// Shape validation for the three declarative git-conditional overlay
// forms — without this, a malformed entry (e.g. ask_flags with no
// `flags` field) throws at MATCH time, deep inside gitSubcommandNeedsConfirm,
// instead of failing lint up front.
function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

export function lintAskFlagsShape(entries: readonly unknown[]): LintIssue[] {
  const issues: LintIssue[] = [];
  entries.forEach((raw, i) => {
    if (raw === null || typeof raw !== 'object') {
      issues.push({ message: `command.git.ask_flags[${i}]: must be a table` });
      return;
    }
    const e = raw as Record<string, unknown>;
    if (!isNonEmptyString(e.sub)) {
      issues.push({ message: `command.git.ask_flags[${i}]: "sub" must be a non-empty string` });
    }
    if (!isStringArray(e.flags)) {
      issues.push({
        message: `command.git.ask_flags[${i}] (sub=${JSON.stringify(e.sub)}): "flags" must be an array of strings`,
      });
    }
    if (e.max_positionals !== undefined && typeof e.max_positionals !== 'number') {
      issues.push({
        message: `command.git.ask_flags[${i}] (sub=${JSON.stringify(e.sub)}): `
          + `"max_positionals" must be a number`,
      });
    }
    if (e.reason !== undefined && typeof e.reason !== 'string') {
      issues.push({ message: `command.git.ask_flags[${i}] (sub=${JSON.stringify(e.sub)}): "reason" must be a string` });
    }
  });
  return issues;
}

export function lintSafeFirstArgShape(entries: readonly unknown[]): LintIssue[] {
  const issues: LintIssue[] = [];
  entries.forEach((raw, i) => {
    if (raw === null || typeof raw !== 'object') {
      issues.push({ message: `command.git.safe_first_arg[${i}]: must be a table` });
      return;
    }
    const e = raw as Record<string, unknown>;
    if (!isNonEmptyString(e.sub)) {
      issues.push({ message: `command.git.safe_first_arg[${i}]: "sub" must be a non-empty string` });
    }
    if (!isStringArray(e.values)) {
      issues.push({
        message: `command.git.safe_first_arg[${i}] (sub=${JSON.stringify(e.sub)}): "values" must be an array of strings`,
      });
    }
    if (e.invert !== undefined && typeof e.invert !== 'boolean') {
      issues.push({ message: `command.git.safe_first_arg[${i}] (sub=${JSON.stringify(e.sub)}): "invert" must be a boolean` });
    }
    if (typeof e.safe_when_absent !== 'boolean') {
      issues.push({
        message: `command.git.safe_first_arg[${i}] (sub=${JSON.stringify(e.sub)}): `
          + `"safe_when_absent" must be a boolean`,
      });
    }
    if (e.reason !== undefined && typeof e.reason !== 'string') {
      issues.push({
        message: `command.git.safe_first_arg[${i}] (sub=${JSON.stringify(e.sub)}): "reason" must be a string`,
      });
    }
  });
  return issues;
}

export function lintSafeGrammarShape(entries: readonly unknown[]): LintIssue[] {
  const issues: LintIssue[] = [];
  entries.forEach((raw, i) => {
    if (raw === null || typeof raw !== 'object') {
      issues.push({ message: `command.git.safe_grammar[${i}]: must be a table` });
      return;
    }
    const e = raw as Record<string, unknown>;
    if (!isNonEmptyString(e.sub)) {
      issues.push({ message: `command.git.safe_grammar[${i}]: "sub" must be a non-empty string` });
    }
    if (!Array.isArray(e.sequences) || !e.sequences.every((seq) => isStringArray(seq))) {
      issues.push({
        message: `command.git.safe_grammar[${i}] (sub=${JSON.stringify(e.sub)}): `
          + `"sequences" must be an array of arrays of strings`,
      });
    }
    if (e.reason !== undefined && typeof e.reason !== 'string') {
      issues.push({ message: `command.git.safe_grammar[${i}] (sub=${JSON.stringify(e.sub)}): "reason" must be a string` });
    }
  });
  return issues;
}

const RELAX_LISTS = new Set(['command.git.safe_subcommands', 'command.git.config_read_modes', 'mcp_write.read_prefixes']);

// `[[relax]]` entries are the ONLY sanctioned way to add to the three
// pure-allowlist fields — see schema.ts's RelaxableList. Every entry
// widens what silently passes, so `reason` is mandatory, not optional.
export function lintRelaxEntries(entries: readonly unknown[]): LintIssue[] {
  const issues: LintIssue[] = [];
  entries.forEach((raw, i) => {
    if (raw === null || typeof raw !== 'object') {
      issues.push({ message: `relax[${i}]: must be a table` });
      return;
    }
    const e = raw as Record<string, unknown>;
    if (typeof e.list !== 'string' || !RELAX_LISTS.has(e.list)) {
      issues.push({ message: `relax[${i}]: "list" must be one of ${[...RELAX_LISTS].join(', ')}` });
    }
    if (!isNonEmptyString(e.value)) {
      issues.push({ message: `relax[${i}] (list=${JSON.stringify(e.list)}): "value" must be a non-empty string` });
    }
    if (!isNonEmptyString(e.reason)) {
      issues.push({
        message: `relax[${i}] (list=${JSON.stringify(e.list)}, value=${JSON.stringify(e.value)}): `
          + `"reason" must not be empty — this entry can only relax security`,
      });
    }
  });
  return issues;
}

// A git-conditional overlay entry (ask_flags/safe_first_arg/safe_grammar)
// whose `sub` is ALREADY governed by the baseline (present in baseline's
// safe_subcommands, or in any of the three declarative tables, or one of
// the two engine-escape names) can only SUBSTITUTE — and therefore only
// relax — the baseline's own behavior for that subcommand: the merge puts
// overlay entries ahead of baseline ones (see load.ts's
// overlayTakesPrecedence), so this entry wins over the vetted one. Such an
// entry requires a non-empty `reason`, same discipline as `[[relax]]`. A
// `sub` NOT in that governed set is a genuinely new declarative rule, not
// a substitution, and stays reason-optional.
export function lintGitConditionalRelaxation(
  entries: readonly FileTagged<{ readonly sub: string; readonly reason?: string }>[],
  table: 'ask_flags' | 'safe_first_arg' | 'safe_grammar',
  governedSubs: ReadonlySet<string>,
): LintIssue[] {
  const issues: LintIssue[] = [];
  for (const { filename, raw: e } of entries) {
    if (governedSubs.has(e.sub) && (!e.reason || e.reason.trim() === '')) {
      issues.push({
        message: `${filename}: command.git.${table}: overlay entry for sub ${JSON.stringify(e.sub)} substitutes a `
          + `baseline-governed subcommand and can only relax its behavior — "reason" must not be empty`,
      });
    }
  }
  return issues;
}

// The full lint pass a policy file must clear: RE2 dialect on every regex,
// and (if present) override resolution + reason. Used identically for the
// baseline (expected to always be clean) and for `rules lint`. Does NOT
// cover `[[relax]]`, the three declarative shape checks, or the
// substitution-reason check — those need the raw overlay's own arrays and
// the baseline's governed-subs set, which only src/policy/load.ts's
// loadPolicyFromOverlayText has in scope; this function is the
// context-free subset, still useful for linting a whole file in isolation
// (e.g. the baseline itself, which never carries relax/declarative
// overlay entries).
//
// No caller anywhere in src/ or tests/ (confirmed by grep) — a single
// RawPolicyFile has no filename of its own to attach to lintOverrides'
// now-mandatory FileTagged shape, so one is synthesized here for the
// (currently unused) case where a future caller wants to lint a lone file
// in isolation without a real overlay filename to give it.
export function lintPolicyFile(file: RawPolicyFile): LintIssue[] {
  const dialectIssues = lintRegexDialect(file);
  const overrideIssues = file.override
    ? lintOverrides(
      file.override.map((raw) => ({ filename: '<file>', raw })),
      resolvableRuleIds(file.rules),
    )
    : [];
  return [...dialectIssues, ...overrideIssues];
}
