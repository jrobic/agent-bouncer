// Ticket 54 reconstructs direct NeutralCalls: no input selectors or codecs run,
// and no tool is executed. Superset surfaces err toward still-friction; truncated,
// write-secret, prompt, unknown-tool, and other-harness entries remain as logged.
import type { HarnessProtocol, HarnessToolRow } from '../policy/schema.ts';
import type { VerdictKind } from '../types.ts';
import type { AuditEntry } from './audit.ts';
import type { Dispatcher, FamilyVerdict } from './dispatch.ts';
import { expandPathCandidates, findToolRow } from './neutral-call.ts';
import type { NeutralCall } from './neutral-call.ts';

export type ReplayExclusion = 'truncated' | 'write-secret' | 'prompt' | 'unknown-tool' | 'other-harness';
export type PolicyTransition = 'resolved' | 'softened' | 'hardened' | 'drift';
export type ReplayedVerdict = { readonly verdict: 'allow'; } | FamilyVerdict;

export type ReplayResult =
  | { readonly replayed: ReplayedVerdict; readonly transition: PolicyTransition | null; }
  | { readonly excluded: ReplayExclusion; };

export interface ReplaySummary {
  readonly results: readonly ReplayResult[];
  readonly replayedCount: number;
  readonly exclusions: Readonly<Record<ReplayExclusion, number>>;
}

function callFor(toolName: string, target: string, row: HarnessToolRow): NeutralCall {
  const paths = row.codec !== undefined || row.path !== undefined || row.role === 'read' || row.role === 'write'
    ? row.codec === undefined && row.role === 'read' ? expandPathCandidates(target) : [target]
    : [];
  const urls = row.url !== undefined || row.urls !== undefined || row.role === 'fetch' ? [target] : [];
  return {
    toolName,
    role: row.role,
    commands: row.command !== undefined || row.role === 'command' ? [target] : [],
    paths,
    pattern: row.pattern === undefined ? null : target,
    text: null,
    urls,
    mcpName: row.role === 'mcp' ? toolName : null,
  };
}

function exclusionFor(entry: AuditEntry, harnessId: string): ReplayExclusion | null {
  if (entry.truncated) return 'truncated';
  if (entry.family === 'write-secret') return 'write-secret';
  if (entry.family === 'prompt' || entry.verdict === 'flag') return 'prompt';
  if (entry.harness !== null && entry.harness !== harnessId) return 'other-harness';
  return null;
}
export function transitionFor(historical: VerdictKind, current: VerdictKind | 'allow'): PolicyTransition | null {
  if (historical === 'block') {
    if (current === 'allow') return 'resolved';
    if (current === 'confirm' || current === 'observe') return 'softened';
    return null;
  }
  if (historical === 'confirm') {
    if (current === 'allow') return 'resolved';
    if (current === 'block') return 'hardened';
    if (current === 'observe') return 'softened';
    return null;
  }
  if (historical === 'observe') {
    if (current === 'allow') return 'drift';
    if (current === 'block' || current === 'confirm') return 'hardened';
  }
  return null;
}

export async function replayEntries(
  entries: readonly AuditEntry[],
  harnessId: string,
  protocol: HarnessProtocol,
  dispatcher: Dispatcher,
): Promise<ReplaySummary> {
  const exclusions: Record<ReplayExclusion, number> = {
    truncated: 0,
    'write-secret': 0,
    prompt: 0,
    'unknown-tool': 0,
    'other-harness': 0,
  };
  const results: ReplayResult[] = [];
  let replayedCount = 0;

  for (const entry of entries) {
    const excluded = exclusionFor(entry, harnessId);
    if (excluded !== null) {
      exclusions[excluded] += 1;
      results.push({ excluded });
      continue;
    }

    const toolName = entry.toolName;
    if (toolName === null) {
      exclusions['unknown-tool'] += 1;
      results.push({ excluded: 'unknown-tool' });
      continue;
    }
    const row = findToolRow(protocol.tools, toolName);
    if (row === null) {
      exclusions['unknown-tool'] += 1;
      results.push({ excluded: 'unknown-tool' });
      continue;
    }

    const call = callFor(toolName, entry.target, row);
    // oxlint-disable-next-line no-await-in-loop
    const preTool = await dispatcher.inspectPreToolUse(call);
    const replayed = preTool ?? dispatcher.classifyObserve(call) ?? { verdict: 'allow' as const };
    const current = replayed.verdict === 'allow' ? 'allow' : replayed.verdict.verdict;
    results.push({ replayed, transition: transitionFor(entry.verdict, current) });
    replayedCount += 1;
  }

  return { results, replayedCount, exclusions };
}
