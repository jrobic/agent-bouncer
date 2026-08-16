// MCP-write guard rules: which MCP tool calls are reads (pass silently)
// versus everything else (asks for confirmation). Pure — no Bun/Node APIs,
// no harness protocol shapes.
//
// ─── Posture (default-ask, and fail-open by construction) ────────────────
// Every MCP tool call whose operation is not recognised as a READ asks for
// confirmation — on every connected server, not one tenant's. The inverse is
// the property to keep in mind while editing: whatever this module fails to
// recognise as a write PASSES SILENTLY. A shortened prefix or a mis-cut
// operation breaks nothing visible, it opens the gate. The behavioural
// counter-examples in tests/mcp-write-rules.test.ts (one write neighbour per
// prefix) are what holds that boundary; the read vectors do not — an
// allowlist shrunk to single initials satisfies all nine of them.
//
// Scope, deliberately generic: this module is server-agnostic on purpose. A
// tenant-scoped allowlist (e.g. one extra read prefix for a single MCP
// server) belongs in a policy overlay, not in the trunk engine.

import type { Deny } from './types.ts';

// Read-only operation prefixes, matched on the START of the operation name.
// ORDERED and exported on purpose: the guards-digest lock freezes this exact
// sequence, so a rename, a reordering or a prefix shortened to its initial
// fails that lock.
export const MCP_READ_PREFIXES: readonly string[] = [
  'get',
  'list',
  'search',
  'fetch',
  'read',
  'query',
  'lookup',
  'describe',
  'view',
];

// NON-GREEDY on purpose: the operation is everything after the SECOND `__`,
// not after the last one. Greedy would cut `mcp__plugin__deploy__getStatus`
// down to `getStatus`, match the `get` prefix, and let a deploy tool through
// silently — servers whose identifier contains `__` are exactly where the
// two readings diverge, and the divergence is fail-open. Cutting at the
// second `__` errs the other way: friction on an ambiguous read, never a
// hole.
//
// The `^mcp__` anchor is also a deliberate scope re-check, not a redundancy.
// The adapter wires this on a matcher already scoped to `mcp__.*`; trusting
// that matcher would couple this pure module to today's glue. Removing the
// anchor is stricter, not fail-open: an embedded write-shaped suffix starts
// asking. The local check keeps out-of-scope names out of this guard if the
// wiring widens.
const MCP_TOOL_NAME = /^mcp__.+?__(.+)$/;

/**
 * Decides on an MCP tool name. Returns an `ask` verdict for anything that is
 * not a recognised read, or null when the call is out of scope (non-MCP tool,
 * empty name, no operation to read).
 */
export function checkMcpWrite(toolName: string): Deny | null {
  const operation = MCP_TOOL_NAME.exec(toolName)?.[1];
  if (!operation) return null;
  if (MCP_READ_PREFIXES.some((prefix) => operation.startsWith(prefix))) return null;

  return {
    decision: 'ask',
    ruleId: 'mcp-write',
    reason: 'Non-read MCP tool — every MCP write asks for confirmation, on any connected server',
    target: toolName,
  };
}
