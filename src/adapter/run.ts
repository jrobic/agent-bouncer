// The adapter's top-level entry point: parses the stdin envelope, dispatches
// to the right family, degrades the abstract verdict to the Claude Code
// protocol, logs it, and returns what (if anything) belongs on stdout.
//
// Fail-open by contract: an unreadable or malformed envelope produces no
// verdict at all (silent allow) rather than guessing or crashing. The
// settings.json `permissions` layer is the fallback for a session running
// with a broken hook — never this process pretending it understood.

import type { Family } from '../types.ts';
import { degradeToClaudeCode } from './degradation.ts';
import { buildContextOutput, buildPreToolUseOutput } from './envelopes.ts';
import { classifyObserve, inspectPreToolUse, inspectUserPromptSubmit } from './dispatch.ts';
import { logVerdict } from './log.ts';
import type { HookInput } from './protocol.ts';

export interface RunResult {
  readonly stdout: string | null;
}

const SILENT: RunResult = { stdout: null };

export function parseEnvelope(raw: string): HookInput | null {
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as HookInput;
  } catch {
    return null;
  }
}

async function runPreToolUse(input: HookInput): Promise<RunResult> {
  const hit = await inspectPreToolUse(input);
  if (hit) {
    await logVerdict(hit.family, input, hit.verdict);
    const action = degradeToClaudeCode(hit.verdict);
    return { stdout: buildPreToolUseOutput(action) };
  }

  // Nothing to block or confirm — check whether a conditional rule still
  // earned an audit-log entry (allow proceeds either way).
  const observe = classifyObserve(input);
  if (observe) {
    await logVerdict(observe.family, input, observe.verdict);
  }
  return SILENT;
}

async function runUserPromptSubmit(input: HookInput): Promise<RunResult> {
  const hits = inspectUserPromptSubmit(input);
  if (hits.length === 0) return SILENT;
  for (const hit of hits) {
    // oxlint-disable-next-line no-await-in-loop
    await logVerdict('prompt' satisfies Family, input, hit);
  }
  return { stdout: buildContextOutput(hits) };
}

// Explicit whitelist, not "UserPromptSubmit or else PreToolUse": a
// PostToolUse envelope, a future event this binary doesn't know about yet,
// or a typo'd/missing hook_event_name must never fall through to the
// PreToolUse dispatch by default — that would judge a tool call this
// process was never asked to judge. Fail open, same contract as a
// malformed envelope.
export async function run(rawStdin: string): Promise<RunResult> {
  const input = parseEnvelope(rawStdin);
  if (input === null) return SILENT;

  switch (input.hook_event_name) {
    case 'PreToolUse':
      return runPreToolUse(input);
    case 'UserPromptSubmit':
      return runUserPromptSubmit(input);
    default:
      return SILENT;
  }
}
