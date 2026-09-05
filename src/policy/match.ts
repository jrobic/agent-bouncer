// The "first match wins" loop over a compiled regex-rule table — used
// identically by all six families (command.bash, secret.path, secret.bash,
// write_secret, protected_write, prompt), where it used to be duplicated.

import type { Verdict, VerdictKind } from '../types.ts';
import type { RegexRule } from './schema.ts';

export interface CompiledRule extends RegexRule {
  readonly re: RegExp;
  readonly exceptRe?: RegExp;
  // The compiled/effective layer's own field — see schema.ts's RegexRule
  // header comment. Synthesized by src/policy/load.ts's applyOverrides
  // when an `[[override]]` with action = "relax" applies; never present
  // on a raw baseline or overlay row.
  readonly verdict_override?: VerdictKind;
}

export function compileRules(rules: readonly RegexRule[]): CompiledRule[] {
  return rules.map((r) => ({
    ...r,
    re: new RegExp(r.regex, r.flags ?? ''),
    ...(r.except !== undefined ? { exceptRe: new RegExp(r.except, r.flags ?? '') } : {}),
  }));
}

// A special rule owns structural recognition; it receives the effective
// compiled row when recognition also needs that row's regex or exception.
// Existing predicates remain boolean so they cannot accidentally expose an
// unrelated shell segment as a candidate for a replacement regex.
export type SpecialHandlers = Readonly<Record<string, (rule: CompiledRule, input: string) => boolean>>;

function regexMatches(rule: CompiledRule, input: string): boolean {
  return rule.re.test(input) && !rule.exceptRe?.test(input);
}

function ruleMatches(rule: CompiledRule, input: string, specials: SpecialHandlers): boolean {
  if (rule.special === undefined) return regexMatches(rule, input);
  return specials[rule.special]?.(rule, input) ?? false;
}

function toVerdict(rule: CompiledRule, input: string, defaultVerdict: VerdictKind): Verdict {
  // Priority: a live [[override]] relax (verdict_override, synthesized,
  // never on a raw row) beats the row's own static `verdict` field
  // (schema.ts's RegexRule, ordinary loaded data), which beats the
  // family's plain default.
  return {
    verdict: rule.verdict_override ?? rule.verdict ?? defaultVerdict,
    ruleId: rule.id,
    reason: rule.reason,
    target: input,
  };
}

/** The first rule (in table order) that matches `input`, or null. */
export function firstMatch(
  rules: readonly CompiledRule[],
  input: string,
  defaultVerdict: VerdictKind,
  specials: SpecialHandlers = {},
): Verdict | null {
  for (const rule of rules) {
    if (ruleMatches(rule, input, specials)) return toVerdict(rule, input, defaultVerdict);
  }
  return null;
}

/** Every rule (in table order) that matches `input` — the prompt family's
 * shape, which flags every signature found rather than stopping at one. */
export function allMatches(
  rules: readonly CompiledRule[],
  input: string,
  defaultVerdict: VerdictKind,
  specials: SpecialHandlers = {},
): Verdict[] {
  const hits: Verdict[] = [];
  for (const rule of rules) {
    if (ruleMatches(rule, input, specials)) hits.push(toVerdict(rule, input, defaultVerdict));
  }
  return hits;
}
