// Pure shared types for the guard rule modules in this directory. No Bun/
// Node APIs, no harness protocol shapes — safe to import from any adapter
// that speaks in strings (Claude Code today, any future harness later).

// A guard verdict. `decision` defaults to "deny" when omitted; set
// `decision: "ask"` to surface an interactive prompt instead of a hard
// block.
export interface Deny {
  decision?: 'deny' | 'ask';
  ruleId: string;
  reason: string;
  target: string;
}

export interface BashRule {
  regex: RegExp;
  ruleId: string;
  reason: string;
}
