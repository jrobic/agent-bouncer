// The adapter's top-level entry point: parses the stdin envelope, loads
// the current (baseline + account overlay) policy, dispatches to the right
// family, degrades the abstract verdict to the Claude Code protocol, logs
// it, and returns what (if anything) belongs on stdout.
//
// Fail-open by contract ONLY for a malformed/unreadable envelope: an
// unreadable or malformed envelope produces no verdict at all (silent
// allow) rather than guessing or crashing — the settings.json `permissions`
// layer is the fallback for a session running with a broken hook, never
// this process pretending it understood.
//
// Never fail-open by ACCIDENT: a throw during dispatcher construction or
// dispatch itself (a policy-loading edge case a lint pass didn't catch, a
// checker bug, ...) must NOT crash this process — Claude Code treats a
// crashed hook as an unguarded call, which is strictly worse than falling
// back to the vetted baseline. Any such throw retries once, from scratch,
// with a pure-baseline dispatcher, and logs a warning. The baseline is the
// floor this process can fall to, never a door it accidentally opens.
//
// The policy is loaded ONCE per invocation (this binary runs one process
// per hook call, ~10ms baseline measured — reading and merging a few KB of
// TOML does not change that order of magnitude) — never cached across
// calls, so an edited overlay takes effect on the very next tool call, no
// restart or session reload needed.

import { BASELINE } from '../policy/baseline.ts';
import type { LoadResult } from '../policy/load.ts';
import type { Family } from '../types.ts';
import { degradeToClaudeCode } from './degradation.ts';
import type { Dispatcher, FamilyVerdict } from './dispatch.ts';
import { createDispatcher } from './dispatch.ts';
import { buildContextOutput, buildPreToolUseOutput } from './envelopes.ts';
import { logPolicyWarnings, logVerdict } from './log.ts';
import { loadCurrentPolicy } from './policy.ts';
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

async function runPreToolUse(
  input: HookInput,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
): Promise<RunResult> {
  const hit: FamilyVerdict | null = await dispatcher.inspectPreToolUse(input);
  if (hit) {
    await logVerdict(hit.family, input, hit.verdict, loaded);
    const action = degradeToClaudeCode(hit.verdict);
    return { stdout: buildPreToolUseOutput(action) };
  }

  // Nothing to block or confirm — check whether a conditional rule still
  // earned an audit-log entry (allow proceeds either way).
  const observe = dispatcher.classifyObserve(input);
  if (observe) {
    await logVerdict(observe.family, input, observe.verdict, loaded);
  }
  return SILENT;
}

async function runUserPromptSubmit(
  input: HookInput,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
): Promise<RunResult> {
  const hits = dispatcher.inspectUserPromptSubmit(input);
  if (hits.length === 0) return SILENT;
  for (const hit of hits) {
    // oxlint-disable-next-line no-await-in-loop
    await logVerdict('prompt' satisfies Family, input, hit, loaded);
  }
  return { stdout: buildContextOutput(hits) };
}

// Explicit whitelist, not "UserPromptSubmit or else PreToolUse": a
// PostToolUse envelope, a future event this binary doesn't know about yet,
// or a typo'd/missing hook_event_name must never fall through to the
// PreToolUse dispatch by default — that would judge a tool call this
// process was never asked to judge. Fail open, same contract as a
// malformed envelope.
async function dispatchByEvent(
  input: HookInput,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
): Promise<RunResult> {
  switch (input.hook_event_name) {
    case 'PreToolUse':
      return runPreToolUse(input, dispatcher, loaded);
    case 'UserPromptSubmit':
      return runUserPromptSubmit(input, dispatcher, loaded);
    default:
      return SILENT;
  }
}

export async function run(rawStdin: string): Promise<RunResult> {
  const input = parseEnvelope(rawStdin);
  if (input === null) return SILENT;

  // Loaded (and, on a broken overlay, silently fell back) before dispatch
  // — a policy-load warning is logged regardless of which event this turns
  // out to be, so "the overlay is broken" is visible even on a turn that
  // otherwise produces no verdict at all.
  const loaded = await loadCurrentPolicy();
  if (loaded.warnings.length > 0) {
    await logPolicyWarnings(loaded.warnings, loaded);
  }

  try {
    const dispatcher = createDispatcher(loaded.policy);
    return await dispatchByEvent(input, dispatcher, loaded);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      await logPolicyWarnings([`dispatch failed, retrying with the embedded baseline: ${message}`]);
    } catch {
      // Logging must never be what crashes the hook either.
    }
    try {
      const baselineDispatcher = createDispatcher(BASELINE.rules);
      return await dispatchByEvent(input, baselineDispatcher, undefined);
    } catch {
      // The baseline dispatcher is the vetted, tested set — it should
      // never throw. If it somehow does, silence is still strictly safer
      // than letting the process crash (Claude Code reads a crash as "no
      // hook ran" — an accidental fail-open this catch exists to prevent).
      return SILENT;
    }
  }
}
