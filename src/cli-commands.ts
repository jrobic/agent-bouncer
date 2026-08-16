// The non-`run` CLI subcommands: `check`, `rules lint`, `rules list`. Each
// returns the text to print plus whether it counts as a success (for the
// exit code) — kept separate from process.exit/console.log so these are
// unit-testable without spawning a subprocess.

import { createDispatcher } from './adapter/dispatch.ts';
import { loadCurrentPolicy, overlayPath } from './adapter/policy.ts';
import type { EffectiveRule, LoadResult } from './policy/load.ts';

export interface CommandResult {
  readonly text: string;
  readonly ok: boolean;
}

/**
 * `bouncer check "<command>"` — dry-runs a Bash command against the
 * effective (baseline + account overlay) policy and prints the verdict it
 * would produce, without a live session. Reproduces the PreToolUse
 * dispatch exactly (so a command that also trips the secret family, say,
 * is reported faithfully) rather than command-family-only.
 */
export async function runCheck(command: string): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  const dispatcher = createDispatcher(loaded.policy);
  const hit = await dispatcher.inspectPreToolUse({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  });

  const warningLines = loaded.warnings.map((w) => `warning: ${w}`);
  if (!hit) {
    return { text: [...warningLines, 'allow'].join('\n'), ok: true };
  }
  const line = `${hit.verdict.verdict} [${hit.verdict.ruleId}] ${hit.verdict.reason}`;
  return { text: [...warningLines, line].join('\n'), ok: true };
}

/**
 * `bouncer rules lint` — validates the account's current overlay (if any)
 * against the RE2-like dialect and the [[override]] resolution/reason
 * rules. Non-zero exit on failure (unlike `run`, which must always exit 0
 * for the hook protocol) — this is a validation command meant to be
 * scripted against.
 */
export async function runRulesLint(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  if (loaded.warnings.length === 0) {
    const suffix = loaded.overlayApplied
      ? `overlay at ${overlayPath()}`
      : 'no overlay present — baseline only';
    return { text: `lint: OK (${suffix})`, ok: true };
  }
  return {
    text: [`lint: FAILED (${overlayPath()})`, ...loaded.warnings.map((w) => `  - ${w}`)].join('\n'),
    ok: false,
  };
}

function ruleLine(entry: EffectiveRule): string {
  const suffix = entry.provenance === 'override'
    ? `override(${entry.overrideAction}) — ${entry.overrideReason}`
    : entry.provenance;
  return `rule ${entry.family} ${entry.rule.id} ${suffix}`;
}

function overrideLine(loaded: LoadResult): string[] {
  return loaded.activeOverrides.map((o) => `override ${o.action} ${o.rule} — ${o.reason}`);
}

// `[[relax]]` entries and a governed-sub git-conditional substitution both
// only ever widen the effective policy — surfaced with their own
// `overlay-relax` provenance (distinct from `override`, which can also
// disable/replace/relax an EXISTING rule) so a relaxed allowlist is exactly
// as impossible to overlook as an active override.
function relaxationLine(loaded: LoadResult): string[] {
  return loaded.activeRelaxations.map((r) => `overlay-relax ${r.list} ${r.value} — ${r.reason}`);
}

/**
 * `bouncer rules list` — one line per effective rule (family, id,
 * provenance), active overrides and relaxations listed first and counted
 * together in a summary line so a relaxed policy is impossible to overlook.
 * Stable, greppable output: `^summary`, `^override`, `^overlay-relax`,
 * `^rule` prefixes.
 */
export async function runRulesList(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  const overridesActive = loaded.activeOverrides.length + loaded.activeRelaxations.length;
  const lines = [
    `summary: ${loaded.effectiveRules.length} rules, ${overridesActive} overrides active`
      + (loaded.warnings.length > 0 ? `, ${loaded.warnings.length} warnings` : ''),
    ...loaded.warnings.map((w) => `warning: ${w}`),
    ...overrideLine(loaded),
    ...relaxationLine(loaded),
    ...loaded.effectiveRules.map(ruleLine),
  ];
  return { text: lines.join('\n'), ok: true };
}
