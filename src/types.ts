// Pure shared types for the guard rule modules in this directory. No Bun/
// Node APIs, no harness protocol shapes — safe to import from any adapter
// that speaks in strings (Claude Code today, any future harness later).

// The abstract verdict vocabulary every rule family emits directly — no
// harness-specific decision string (no more "deny"/"ask"). An adapter maps
// this vocabulary onto its own protocol via an explicit, written degradation
// table (see src/adapter/degradation.ts for the Claude Code one):
//   block    hard-stop the tool call
//   confirm  surface an interactive prompt instead of a hard block
//   flag     warn without blocking (prompt-injection signatures)
//   observe  allow, but worth a log entry with provenance (a conditional
//            rule decided this, as opposed to an unconditional allow that
//            never reaches this vocabulary at all — absence of a Verdict
//            IS allow, silently, by contract)
export type VerdictKind = 'block' | 'confirm' | 'flag' | 'observe';

// Total over VerdictKind: adding a verdict kind requires defining where it
// falls in the severity order instead of silently producing undefined.
export const VERDICT_SEVERITY: Readonly<Record<VerdictKind, number>> = {
  block: 3,
  confirm: 2,
  observe: 1,
  flag: 0,
};

export interface Verdict {
  readonly verdict: VerdictKind;
  readonly ruleId: string;
  readonly reason: string;
  readonly target: string;
}

export interface BashRule {
  regex: RegExp;
  ruleId: string;
  reason: string;
}

// The six guard families this repository ports, named once so a dispatcher
// or a log entry can say which one produced a verdict without falling back
// to a bare `string` (a typo'd family name would otherwise type-check).
export type Family = 'command' | 'secret' | 'protected-write' | 'mcp-write' | 'write-secret' | 'prompt';
