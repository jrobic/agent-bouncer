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
import { buildSessionStartContext, defaultSettingsPath, type DoctorReport, runDoctorChecks } from './doctor.ts';
import { buildContextOutput, buildPreToolUseOutput, buildSessionStartOutput } from './envelopes.ts';
import { logPolicyWarnings, logSessionStartShadow, logVerdict, toLogMode } from './log.ts';
import { loadCurrentPolicy } from './policy.ts';
import type { HookInput } from './protocol.ts';

export interface RunResult {
  readonly stdout: string | null;
}

// Ticket 08: `bouncer run --shadow` (cli.ts parses the flag; `run()` here
// is where it actually takes effect). Absolute contract — shadow evaluates
// every event exactly as normal (same dispatch, same policy, same
// logging), but NEVER writes to stdout, on any event shape: no deny, no
// ask, no additionalContext, no SessionStart scream. The TS guard chain
// stays the real enforcement path for the whole shadow window; this
// process only watches and logs (`mode: "shadow"` on every entry it
// writes — see log.ts).
//
// `unrecognizedTokens`: any argv token cli.ts's `run` handling didn't
// recognize (a typo like `--shadwo`, a stray flag). The SAFE direction is
// enforced deliberately: an unrecognized token never disarms enforcement
// (only the EXACT string `--shadow` ever sets `shadow: true` — a typo
// stays false, by construction) — but it also must not be silently
// swallowed, since a live typo desyncing "I meant to be in shadow mode"
// from "I am actually enforcing" is exactly the kind of drift this ticket
// exists to make loud. Logged via logPolicyWarnings so it survives in the
// audit trail even though the tool call itself proceeds normally.
export interface RunOptions {
  readonly shadow?: boolean;
  readonly unrecognizedTokens?: readonly string[];
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
  shadow: boolean,
): Promise<RunResult> {
  const mode = toLogMode(shadow);
  const hit: FamilyVerdict | null = await dispatcher.inspectPreToolUse(input);
  if (hit) {
    await logVerdict(hit.family, input, hit.verdict, loaded, mode);
    if (shadow) return SILENT;
    const action = degradeToClaudeCode(hit.verdict);
    return { stdout: buildPreToolUseOutput(action) };
  }

  // Nothing to block or confirm — check whether a conditional rule still
  // earned an audit-log entry (allow proceeds either way, shadow or not).
  const observe = dispatcher.classifyObserve(input);
  if (observe) {
    await logVerdict(observe.family, input, observe.verdict, loaded, mode);
  }
  return SILENT;
}

async function runUserPromptSubmit(
  input: HookInput,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
  shadow: boolean,
): Promise<RunResult> {
  const hits = dispatcher.inspectUserPromptSubmit(input);
  if (hits.length === 0) return SILENT;
  const mode = toLogMode(shadow);
  for (const hit of hits) {
    // oxlint-disable-next-line no-await-in-loop
    await logVerdict('prompt' satisfies Family, input, hit, loaded, mode);
  }
  if (shadow) return SILENT;
  return { stdout: buildContextOutput(hits) };
}

// doctor's own event — deliberately NOT routed through dispatchByEvent
// below: it never needs a Dispatcher (no tool call to judge, no family to
// evaluate), only the policy already loaded for this invocation and the
// settings.json wiring check (src/adapter/doctor.ts). `checkFn` defaults to
// the real runDoctorChecks and exists only as a test seam (see
// tests/adapter-run-sessionstart.test.ts's throwing-check case) — run()
// itself always calls this with the default. Wrapped in its own try/catch
// for the same "the hook never crashes" reason as dispatch itself — a
// diagnostic failing to diagnose must not read as a crashed hook (Claude
// Code's cue for "no hook ran at all") — and, unlike the pre-review
// version, the catch LOGS before falling silent: a silent catch here would
// itself be an unannounced loss of the doctor signal, the exact failure
// class this ticket exists to catch.
export async function runSessionStart(
  loaded: LoadResult,
  shadow: boolean,
  checkFn: (settingsPath: string, loaded: LoadResult) => Promise<DoctorReport> = runDoctorChecks,
): Promise<RunResult> {
  try {
    const report = await checkFn(defaultSettingsPath(), loaded);
    const context = buildSessionStartContext(report);
    if (shadow) {
      // Ticket 08 decision 2: the scream/announcement never reaches
      // stdout in shadow, but it must not be lost either — logged so
      // shadow wiring health stays verifiable through the log. Nothing to
      // log when context is null (a fully healthy SessionStart stays
      // silent everywhere, shadow or not — there is no "verdict it would
      // have emitted" when it would not have emitted one).
      if (context !== null) await logSessionStartShadow(context, loaded);
      return SILENT;
    }
    return { stdout: buildSessionStartOutput(context) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      await logPolicyWarnings([`doctor checks failed: ${message}`], loaded, toLogMode(shadow));
    } catch {
      // Logging must never be what crashes the hook either.
    }
    return SILENT;
  }
}

// Explicit whitelist, not "UserPromptSubmit or else PreToolUse": a
// PostToolUse envelope, a future event this binary doesn't know about yet,
// or a typo'd/missing hook_event_name must never fall through to the
// PreToolUse dispatch by default — that would judge a tool call this
// process was never asked to judge. Fail open, same contract as a
// malformed envelope. SessionStart is deliberately absent from this
// switch too — run() routes it to runSessionStart() upstream, before this
// function is ever called, so this table alone no longer lists every event
// the binary understands; see run()'s own body for the full dispatch.
async function dispatchByEvent(
  input: HookInput,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
  shadow: boolean,
): Promise<RunResult> {
  switch (input.hook_event_name) {
    case 'PreToolUse':
      return runPreToolUse(input, dispatcher, loaded, shadow);
    case 'UserPromptSubmit':
      return runUserPromptSubmit(input, dispatcher, loaded, shadow);
    default:
      return SILENT;
  }
}

export async function run(rawStdin: string, options?: RunOptions): Promise<RunResult> {
  const shadow = options?.shadow ?? false;
  const unrecognizedTokens = options?.unrecognizedTokens ?? [];
  const input = parseEnvelope(rawStdin);
  if (input === null) return SILENT;

  // Loaded (and, on a broken overlay, silently fell back) before dispatch
  // — a policy-load warning is logged regardless of which event this turns
  // out to be, so "the overlay is broken" is visible even on a turn that
  // otherwise produces no verdict at all.
  const loaded = await loadCurrentPolicy();
  if (loaded.warnings.length > 0) {
    await logPolicyWarnings(loaded.warnings, loaded, toLogMode(shadow));
  }
  if (unrecognizedTokens.length > 0) {
    // Never disarms enforcement (shadow only ever activates on the exact
    // `--shadow` token — see RunOptions's own comment) — this is purely
    // making the mistake visible in the audit trail.
    await logPolicyWarnings(
      [`run: unrecognized argument(s) ${unrecognizedTokens.map((t) => JSON.stringify(t)).join(', ')} `
        + `— ignored, running in normal enforce mode`],
      loaded,
      toLogMode(shadow),
    );
  }

  if (input.hook_event_name === 'SessionStart') {
    return runSessionStart(loaded, shadow);
  }

  try {
    const dispatcher = createDispatcher(loaded.policy);
    return await dispatchByEvent(input, dispatcher, loaded, shadow);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      await logPolicyWarnings(
        [`dispatch failed, retrying with the embedded baseline: ${message}`],
        undefined,
        toLogMode(shadow),
      );
    } catch {
      // Logging must never be what crashes the hook either.
    }
    try {
      const baselineDispatcher = createDispatcher(BASELINE.rules);
      return await dispatchByEvent(input, baselineDispatcher, undefined, shadow);
    } catch {
      // The baseline dispatcher is the vetted, tested set — it should
      // never throw. If it somehow does, silence is still strictly safer
      // than letting the process crash (Claude Code reads a crash as "no
      // hook ran" — an accidental fail-open this catch exists to prevent).
      return SILENT;
    }
  }
}
