// MCP-write guard: which MCP tool calls pass silently versus ask for
// confirmation. Pure — no Bun/Node APIs or harness protocol shapes. The
// read-prefix and exact-tool allowlists are policy data
// (policy/mcp-write.toml, `rules.mcp_write`); this module owns only the
// operation-name parsing and exact membership check.
//
// ─── Posture (default-ask) ───────────────────────────────────────────────
// Every in-scope MCP tool call that is neither a recognised read nor an exact
// policy-approved name asks for confirmation. A shortened read prefix or a
// mis-cut operation breaks nothing visible, it opens the gate. The
// behavioural counter-examples in tests/mcp-write-rules.test.ts (one write
// neighbour per prefix) are what holds that boundary; the read vectors do
// not — an allowlist shrunk to single initials satisfies all nine of them.
//
// Exact permissions are deliberately full names, not operation prefixes:
// policy can approve one tool on one MCP server without widening an
// identically named operation on another server.

import { BASELINE } from './policy/baseline.ts';
import type { McpWritePolicy } from './policy/schema.ts';
import type { Verdict } from './types.ts';

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

export type CheckMcpWrite = (toolName: string) => Verdict | null;

/**
 * Builds a checkMcpWrite() bound to the given MCP-write policy (baseline,
 * or a merged baseline+overlay set).
 */
export function createCheckMcpWrite(policy: McpWritePolicy): CheckMcpWrite {
  const allowedTools = new Set(policy.allowed_tools);

  return (toolName) => {
    if (allowedTools.has(toolName)) return null;
    const operation = MCP_TOOL_NAME.exec(toolName)?.[1];
    if (!operation) return null;
    if (policy.read_prefixes.some((prefix) => operation.startsWith(prefix))) return null;

    return {
      verdict: 'confirm',
      ruleId: 'mcp-write',
      reason: 'Unapproved MCP tool — every in-scope MCP call not recognised as a read or exact allowlisted tool asks for confirmation',
      target: toolName,
    };
  };
}

/**
 * Decides on an MCP tool name. Returns a `confirm` verdict for anything
 * that is neither a recognised read nor an exact policy-approved tool, or
 * null when the call is out of scope (non-MCP tool, empty name, no
 * operation to read). Uses the embedded baseline policy.
 */
export const checkMcpWrite: CheckMcpWrite = createCheckMcpWrite(BASELINE.rules.mcp_write);

// Exported for the tests/completeness locks that inspect the allowlist
// directly (coverage diffing, digest freezing) — the array itself, not a
// derived count, so a rename/reorder/narrowing is visible at its own index.
export const MCP_READ_PREFIXES: readonly string[] = BASELINE.rules.mcp_write.read_prefixes;
