// The "first match wins" loop over a compiled regex-rule table — used
// identically by all five families (command.bash, secret.path, secret.bash,
// write_secret, prompt), where it used to be duplicated once per family.

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

// A `special`-marked rule (see schema.ts) is resolved by a named predicate
// instead of its own regex — e.g. "git_remote_url", checked through the
// structural git parser rather than a literal pattern. Checked in the
// rule's own table position, same as any other entry, so evaluation order
// (and therefore which ruleId is reported first) is unaffected.
export type SpecialHandlers = Readonly<Record<string, (input: string) => boolean>>;

function ruleMatches(rule: CompiledRule, input: string, specials: SpecialHandlers): boolean {
  if (rule.special !== undefined) {
    return specials[rule.special]?.(input) ?? false;
  }
  if (!rule.re.test(input)) return false;
  if (rule.exceptRe?.test(input)) return false;
  return true;
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
