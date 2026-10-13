// Pure shared types for the guard rule modules in this directory. No Bun/
// Node APIs, no harness protocol shapes — safe to import from any adapter
// that speaks in strings (Claude Code today, any future harness later).

// The abstract verdict vocabulary every rule family emits directly — no
// harness-specific decision string (no more "deny"/"ask"). A harness maps
// this vocabulary onto its own protocol via its declared output table
// (ADR-0006 § 4 — `policy/harness/<id>.toml`'s `[harness.protocol.output]`;
// src/adapter/degrade.ts is the pure lookup):
//   block    hard-stop the tool call
//   confirm  surface an interactive prompt instead of a hard block
//   flag     warn without blocking (prompt-injection signatures)
//   observe  allow, but worth a log entry with provenance (a conditional
//            rule decided this, as opposed to an unconditional allow that
//            never reaches this vocabulary at all — absence of a Verdict
//            IS allow, silently, by contract)
//   redact   post-tool only (ADR-0008): the tool ran, and its output
//            reached the model with the value of a protected environment
//            variable replaced by `[redacted: NAME]` — never a pre-tool
//            verdict, never degraded through an output table
export type VerdictKind = 'block' | 'confirm' | 'flag' | 'observe' | 'redact';

// Total over VerdictKind: adding a verdict kind requires defining where it
// falls in the severity order instead of silently producing undefined.
// `flag` and `redact` are never ranked against a pre-tool verdict (their own
// events emit nothing else); 0 is a placeholder, never a decision.
export const VERDICT_SEVERITY: Readonly<Record<VerdictKind, number>> = {
  block: 3,
  confirm: 2,
  observe: 1,
  flag: 0,
  redact: 0,
};

// Total over VerdictKind, like VERDICT_SEVERITY: adding a verdict kind
// requires deciding whether a pre-tool family may emit it. `flag` belongs to
// UserPromptSubmit, `redact` to the post-tool event (ADR-0008).
const PRE_TOOL_VERDICTS = {
  block: true,
  confirm: true,
  observe: true,
  flag: false,
  redact: false,
} as const satisfies Readonly<Record<VerdictKind, boolean>>;

/** The verdicts a pre-tool family may emit — read off PRE_TOOL_VERDICTS, so the two cannot drift. */
export type PreToolVerdictKind = { [K in VerdictKind]: (typeof PRE_TOOL_VERDICTS)[K] extends true ? K : never; }[VerdictKind];

/**
 * The one test both pre-tool consumers apply (src/adapter/dispatch.ts's
 * strictestOf, src/adapter/degrade.ts): a verdict outside this set on the
 * pre-tool path is a routing bug, thrown — never ranked, never degraded.
 */
export function isPreToolKind(kind: VerdictKind): kind is PreToolVerdictKind {
  return PRE_TOOL_VERDICTS[kind];
}

export interface Verdict {
  readonly verdict: VerdictKind;
  readonly ruleId: string;
  readonly reason: string;
  readonly target: string;
  // The env-value guard (ticket 58) only: the NAMES of the protected
  // variables whose value the text carries — what the audit log records as
  // `env_vars`. Never a value, never a fragment of one.
  readonly envVars?: readonly string[];
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
