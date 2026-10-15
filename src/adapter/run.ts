// The adapter's top-level entry point: reads the harness declaration for
// `--harness <id>` (default `claude-code`, baseline + account overlay,
// ADR-0006), parses the stdin envelope through its input map, routes by
// its declared event names, builds the neutral call through its tools
// map, dispatches to the engine, degrades the abstract verdict through
// its output table, and renders the matching template — nothing here
// names Claude Code specifically any more; the declaration does.
//
// An unreadable or unparseable stdin envelope (empty,
// invalid JSON) honours the harness's OWN declared `on_malformed`
// (mandatory, ADR-0006 § 4) rather than always allowing silently —
// `"allow"` (Claude Code's contract, unchanged) is the former silent
// allow; `"deny"` renders that harness's own `deny` template
// (`envelope-malformed: unreadable or malformed hook envelope — failing
// closed`) and logs a policy-warning. A WELL-FORMED envelope naming an
// event this binary does not judge (one the harness's declaration does
// not name, a missing `hook_event_name`) is a SEPARATE case — never
// malformed, always silent regardless of `on_malformed`.
// The post-tool events (ADR-0008 § 9) are judged only where the declaration
// names them; run() routes those events directly below.
//
// Fail-CLOSED for an unusable harness declaration (ADR-0006 § 6): an id no
// layer declares, or declared without a usable `protocol`, or whose block
// was rejected, produces no stdout, one stderr line, and exit 2 — the one
// signal that needs no declaration to interpret (every harness this repo
// targets reads a non-zero hook exit as a hard stop).
//
// Never fail-open by ACCIDENT: a throw during dispatcher construction or
// dispatch itself (a policy-loading edge case a lint pass didn't catch, a
// checker bug, ...) must NOT crash this process — a crashed hook reads as
// an unguarded call, which is strictly worse than falling back to the
// vetted baseline. Any such throw retries once, from scratch, with a
// pure-baseline dispatcher (the SAME resolved harness/protocol data —
// validation already happened at load time, never at dispatch time), and
// logs a warning. The baseline is the floor this process can fall to,
// never a door it accidentally opens.
//
// The policy is loaded ONCE per invocation (this binary runs one process
// per hook call, ~10ms baseline measured — reading and merging a few KB of
// TOML does not change that order of magnitude) — never cached across
// calls, so an edited overlay takes effect on the very next tool call, no
// restart or session reload needed.

import { type BuildInfo, currentBuild } from '../build-info.ts';
import {
  createEnvValueGuard,
  createEnvValueScanner,
  type EnvRecord,
  type EnvValueFinding,
  namesOf,
  withheldNotice,
} from '../env-value-rules.ts';
import { BASELINE } from '../policy/baseline.ts';
import type { LoadResult } from '../policy/load.ts';
import type { HarnessDeclaration, HarnessProtocol, RulesPolicy } from '../policy/schema.ts';
import { parseStdinJson } from './codecs/stdin-json.ts';
import { DEFAULT_HARNESS_ID, HOOK_NAME } from './constants.ts';
import { degradePreToolUseVerdict } from './degrade.ts';
import type { Dispatcher, FamilyVerdict } from './dispatch.ts';
import { createDispatcher } from './dispatch.ts';
import { buildSessionStartContext, type DoctorReport, runDoctorChecks } from './doctor.ts';
import { type LogMode, logPolicyWarnings, logSessionStartShadow, logVerdict, toLogMode } from './log.ts';
import { buildNeutralCall } from './neutral-call.ts';
import { loadCurrentPolicy } from './policy.ts';
import { type RedactedResponse, redactResponse, withheldResponse } from './post-tool.ts';
import { assembleFlagContext, reasonText, renderAction, renderFailureContext, renderRedaction, renderSessionStart } from './render.ts';

export interface RunResult {
  readonly stdout: string | null;
  // A template may set the process exit code instead of, or with, stdout
  // (ADR-0006 § 3) — unset means "the caller's own default" (cli.ts uses
  // 0), which is every Claude Code template today.
  readonly exit?: number;
}

// `bouncer run --shadow` (cli.ts parses the flag; `run()` here
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
// from "I am actually enforcing" is exactly the kind of drift this check
// exists to make loud. Logged via logPolicyWarnings so it survives in the
// audit trail even though the tool call itself proceeds normally.
//
// `harness`: `--harness <id>` (cli.ts), default `claude-code` — the v1
// wiring stays untouched by default (ADR-0006 § 9).
export interface RunOptions {
  readonly shadow?: boolean;
  readonly unrecognizedTokens?: readonly string[];
  readonly harness?: string;
  // Test seam for replaying the clean compiled-binary SessionStart contract.
  readonly build?: BuildInfo;
  // The environment the env-value guard reads protected values
  // from. Absent = this process's own (`process.env`), taken here, at the edge,
  // once per invocation; every dispatcher construction then reads that record
  // (the overlay-aware one, then the baseline retry). The hook's environment
  // is the agent's, in both harnesses. A test hands one in rather than
  // touching the real one.
  readonly env?: EnvRecord;
}

const SILENT: RunResult = { stdout: null };

/** Parses a stdin-json envelope (the only transport codec declared so far). `null` for anything unreadable. */
export function parseEnvelope(raw: string): Record<string, unknown> | null {
  return parseStdinJson(raw);
}

function stringField(envelope: Record<string, unknown>, selector: string): string | undefined {
  const value = envelope[selector];
  return typeof value === 'string' ? value : undefined;
}

function recordField(envelope: Record<string, unknown>, selector: string): Record<string, unknown> {
  const value = envelope[selector];
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

// `permission` is the one OPTIONAL selector on
// `[harness.protocol.input]` with no engine-side reader at all — it
// exists purely so `run.ts` can attach it to every logged verdict entry
// (log.ts's own VerdictLogContext.permission). `undefined` (the selector
// itself undeclared, e.g. claude-code.toml) is distinct from `null` (the
// selector IS declared but this particular envelope sent nothing) —
// only the latter still logs a `permission` key with a real value.
function permissionField(envelope: Record<string, unknown>, protocol: HarnessProtocol): string | null | undefined {
  if (protocol.input.permission === undefined) return undefined;
  return stringField(envelope, protocol.input.permission) ?? null;
}

async function runPreToolUse(
  envelope: Record<string, unknown>,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
  shadow: boolean,
  build: BuildInfo,
): Promise<RunResult> {
  const toolName = stringField(envelope, protocol.input.tool);
  if (toolName === undefined) return SILENT;
  const call = buildNeutralCall(
    protocol,
    toolName,
    recordField(envelope, protocol.input.input),
    stringField(envelope, protocol.input.cwd) ?? null,
    HOOK_NAME,
  );
  if (call === null) return SILENT;

  const mode = toLogMode(shadow);
  const permission = permissionField(envelope, protocol);
  const context = {
    toolName,
    sessionId: stringField(envelope, protocol.input.session) ?? null,
    ...(permission !== undefined ? { permission } : {}),
  };

  const hit: FamilyVerdict | null = await dispatcher.inspectPreToolUse(call);
  if (hit) {
    await logVerdict(hit.family, context, hit.verdict, harness, loaded, mode, build);
    if (shadow) return SILENT;
    const action = degradePreToolUseVerdict(hit.verdict.verdict, protocol.output);
    return renderAction(protocol, action, {
      reason: reasonText(hit.verdict),
      rule: hit.verdict.ruleId,
      verdict: hit.verdict.verdict,
    });
  }

  // Nothing to block or confirm — check whether a conditional rule still
  // earned an audit-log entry (allow proceeds either way, shadow or not).
  const observe = dispatcher.classifyObserve(call);
  if (observe) {
    await logVerdict(observe.family, context, observe.verdict, harness, loaded, mode, build);
  }
  return SILENT;
}

async function runUserPromptSubmit(
  envelope: Record<string, unknown>,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
  shadow: boolean,
  build: BuildInfo,
): Promise<RunResult> {
  // `input.prompt` is guaranteed defined here — this function is only ever
  // called when `protocol.events.prompt` is declared, and lint requires
  // `input.prompt` whenever `events.prompt` is (protocolCoherenceIssues).
  const prompt = stringField(envelope, protocol.input.prompt!) ?? '';
  const hits = dispatcher.inspectUserPromptSubmit(prompt);
  if (hits.length === 0) return SILENT;
  const mode = toLogMode(shadow);
  const permission = permissionField(envelope, protocol);
  const context = {
    toolName: null,
    sessionId: stringField(envelope, protocol.input.session) ?? null,
    ...(permission !== undefined ? { permission } : {}),
  };
  for (const hit of hits) {
    // oxlint-disable-next-line no-await-in-loop
    await logVerdict('prompt', context, hit, harness, loaded, mode, build);
  }
  if (shadow) return SILENT;
  return renderAction(protocol, protocol.output.flag, { context: assembleFlagContext(hits) });
}

// doctor's own event — deliberately NOT routed through dispatchByEvent
// below: it never needs a Dispatcher (no tool call to judge, no family to
// evaluate), only the policy already loaded for this invocation and the
// hook-file wiring check (src/adapter/codecs/wiring/hook-file.ts). `checkFn`
// defaults to the real runDoctorChecks and exists only as a test seam
// (see tests/adapter-run-sessionstart.test.ts's throwing-check case) —
// run() itself always calls this with the default. Wrapped in its own
// try/catch for the same "the hook never crashes" reason as dispatch
// itself — a diagnostic failing to diagnose must not read as a crashed
// hook (Claude Code's cue for "no hook ran at all") — and the catch LOGS
// before falling silent: a silent catch here would itself be an
// unannounced loss of the doctor signal, the exact failure class this
// doctor path exists to catch.
export async function runSessionStart(
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  loaded: LoadResult,
  shadow: boolean,
  checkFn: (
    settingsPath: string | undefined,
    loaded: LoadResult,
    harness: HarnessDeclaration,
    build: BuildInfo,
  ) => Promise<DoctorReport> = runDoctorChecks,
  build: BuildInfo = currentBuild(),
): Promise<RunResult> {
  try {
    const report = await checkFn(undefined, loaded, harness, build);
    const context = buildSessionStartContext(report);
    if (shadow) {
      // The scream/announcement never reaches
      // stdout in shadow, but it must not be lost either — logged so
      // shadow wiring health stays verifiable through the log. Nothing to
      // log when context is null (a fully healthy SessionStart stays
      // silent everywhere, shadow or not — there is no "verdict it would
      // have emitted" when it would not have emitted one).
      if (context !== null) await logSessionStartShadow(context, harness, loaded);
      return SILENT;
    }
    return renderSessionStart(protocol, context);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      await logPolicyWarnings([`doctor checks failed: ${message}`], harness, loaded, toLogMode(shadow));
    } catch {
      // Logging must never be what crashes the hook either.
    }
    return SILENT;
  }
}

// `on_malformed` is mandatory on every protocol (ADR-
// 0006 § 4) but was read nowhere until now — this is that one call site.
// "allow" is Claude Code's own original contract: silent, exit 0, nothing
// logged (an unreadable envelope on a healthy install is noise, not a
// signal). "deny" renders the harness's OWN `deny` template — the same
// template a real blocked tool call would get — with a fixed, harness-
// neutral reason, and logs a policy-warning so the malformed input is
// visible in the audit trail even though no tool call fired. `harness` is
// always resolved by the time this is reached (run() only calls this
// after its own exit-2 harness/protocol check), so a log path always
// resolves.
async function handleMalformedEnvelope(
  protocol: HarnessProtocol,
  harness: HarnessDeclaration,
  loaded: LoadResult,
  shadow: boolean,
  mode: LogMode | undefined,
): Promise<RunResult> {
  if (protocol.output.on_malformed === 'allow') return SILENT;

  const reason = 'envelope-malformed: unreadable or malformed hook envelope — failing closed';
  try {
    await logPolicyWarnings([reason], harness, loaded, mode);
  } catch {
    // Logging must never be what crashes the hook either.
  }
  if (shadow) return SILENT;
  return renderAction(protocol, 'deny', { reason, rule: 'envelope-malformed' });
}

// Explicit whitelist, not "prompt or else pre_tool": an event this
// harness's protocol doesn't declare must never fall through to the
// pre_tool dispatch by default — that would judge a tool call this
// process was never asked to judge. A well-formed envelope naming an
// unjudged event is never malformed (see the file's own top comment) —
// this always stays silent regardless of `on_malformed`. session_start is
// deliberately absent from this switch too — run() routes it to
// runSessionStart() upstream, before this function is ever called.
async function dispatchByEvent(
  envelope: Record<string, unknown>,
  eventName: string | undefined,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  dispatcher: Dispatcher,
  loaded: LoadResult | undefined,
  shadow: boolean,
  build: BuildInfo,
): Promise<RunResult> {
  if (eventName === protocol.events.pre_tool) {
    return runPreToolUse(envelope, harness, protocol, dispatcher, loaded, shadow, build);
  }
  if (protocol.events.prompt !== undefined && eventName === protocol.events.prompt) {
    return runUserPromptSubmit(envelope, harness, protocol, dispatcher, loaded, shadow, build);
  }
  return SILENT;
}

/**
 * Binds the current policy (`bind`) and executes; on any binding or
 * execution failure, retries once against the embedded baseline. Every path
 * that acts on the loaded policy goes through here — `run` (a full dispatcher
 * for a tool call or a prompt; only the env-value guard for a post-tool
 * event, ADR-0008) and `ping` — so a runnable baseline has one definition.
 * The environment the env-value guard reads is captured by the
 * caller's `bind`: the SAME record for both attempts, so the guard survives
 * the retry.
 */
export async function withPolicyLikeRun<B, T>(
  loaded: LoadResult,
  bind: (policy: RulesPolicy) => B,
  execute: (bound: B, effectiveLoaded: LoadResult | undefined) => Promise<T> | T,
  onRetry?: (error: unknown) => Promise<void>,
): Promise<T> {
  try {
    return await execute(bind(loaded.policy), loaded);
  } catch (error) {
    if (onRetry !== undefined) await onRetry(error);
    return execute(bind(BASELINE.rules), undefined);
  }
}

const RETRY_WARNING = 'dispatch failed, retrying with the embedded baseline';
const POST_TOOL_FAILURE_WARNING = 'post-tool check failed, output withheld';
/** Fixed failed-alert policy-warning messages; documented in audit-log.md and never include exception text. */
const FAILED_TOOL_ALERT_RETRY_WARNING = 'post-tool failure alert check failed, retrying with the embedded baseline';
const FAILED_TOOL_ALERT_CHECK_WARNING = 'post-tool failure alert check failed';
const FAILED_TOOL_ALERT_RENDER_WARNING = 'post-tool failure alert render failed';

// Retry warnings for policy dispatch/rewrite paths may include a protected
// value in `err.message`, so scan before logging. The failed-tool alert path
// never uses this helper; it emits the fixed warning constants above and
// never logs exception text.
function scrubbedWarning(what: string, err: unknown, env: EnvRecord): string {
  const message = err instanceof Error ? err.message : String(err);
  try {
    const names = namesOf(createEnvValueScanner(env)(message));
    if (names.length === 0) return `${what}: ${message}`;
    return `${what} ${withheldNotice('error message', names)}`;
  } catch {
    // If the scanner cannot be built, withhold the message: without a completed
    // scan, logging it could expose a protected value.
    return `${what} (error message withheld: the environment could not be scanned)`;
  }
}

// One scrubbed policy-warning, never what crashes the hook.
async function logScrubbedWarning(
  what: string,
  err: unknown,
  env: EnvRecord,
  harness: HarnessDeclaration,
  mode: LogMode | undefined,
): Promise<void> {
  try {
    await logPolicyWarnings([scrubbedWarning(what, err, env)], harness, undefined, mode);
  } catch {
    // Logging must never be what crashes the hook either.
  }
}

async function logFailureAlertWarning(
  message: string,
  harness: HarnessDeclaration,
  loaded: LoadResult | undefined,
  mode: LogMode | undefined,
): Promise<void> {
  try {
    await logPolicyWarnings([message], harness, loaded, mode);
  } catch {
    // A warning write must never change the already-run tool result.
  }
}

async function logEnvValueFinding(
  envelope: Record<string, unknown>,
  protocol: HarnessProtocol,
  finding: EnvValueFinding,
  verdict: 'redact' | 'flag',
  target: string,
  harness: HarnessDeclaration,
  loaded: LoadResult | undefined,
  mode: LogMode | undefined,
  build: BuildInfo,
): Promise<void> {
  const permission = permissionField(envelope, protocol);
  try {
    await logVerdict(
      'write-secret',
      {
        toolName: stringField(envelope, protocol.input.tool) ?? null,
        sessionId: stringField(envelope, protocol.input.session) ?? null,
        ...(permission !== undefined ? { permission } : {}),
      },
      {
        verdict,
        ruleId: finding.ruleId,
        target,
        envVars: finding.names,
      },
      harness,
      loaded,
      mode,
      build,
    );
  } catch {
    // Logging must never change the action taken on the tool output.
  }
}

// ADR-0008 § 6: never silence after a failure — the answer is the response
// in its own shape with every text that could hold a value withheld; if even
// that cannot be rendered, exit 2 with one stderr line (the shim withholds on
// any non-zero exit; Claude Code shows the original, the documented limit).
function withheldAnswer(protocol: HarnessProtocol, response: unknown): RunResult {
  try {
    return renderRedaction(protocol, withheldResponse(response));
  } catch {
    console.error(`${HOOK_NAME}: post-tool check failed and the withheld answer could not be rendered — failing closed`);
    return { stdout: null, exit: 2 };
  }
}

// ADR-0008: the post-tool event — the tool already ran; its response (the
// declaration's `input.response` selector) is walked in its own shape and
// every protected value replaced. Nothing found → silent (the common case:
// no rewrite at all). A find is logged with the variable NAMES (verdict
// `redact`, the governing env-value row's id, `target` "(tool output)" — the
// output itself is never logged), then rendered through the `redact`
// template; `--shadow` logs and prints nothing. Only the env-value guard is
// bound, not a full dispatcher, through the same current-policy-then-baseline
// retry as every other path and over the same environment record. A walk
// that fails on both, or a render that fails, answers with the withheld
// response, never silence; a logging failure never costs the answer.
async function runPostTool(
  envelope: Record<string, unknown>,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  loaded: LoadResult,
  env: EnvRecord,
  shadow: boolean,
  build: BuildInfo,
): Promise<RunResult> {
  // `input.response` is guaranteed defined here: lint keeps it in lockstep
  // with `events.post_tool`, the only way this function is reached.
  const selector = protocol.input.response!;
  if (!Object.hasOwn(envelope, selector)) return SILENT;
  const response = envelope[selector];
  const mode = toLogMode(shadow);
  const withhold = async (error: unknown): Promise<RunResult> => {
    await logScrubbedWarning(POST_TOOL_FAILURE_WARNING, error, env, harness, mode);
    return shadow ? SILENT : withheldAnswer(protocol, response);
  };

  let outcome: { readonly redacted: RedactedResponse; readonly effectiveLoaded: LoadResult | undefined; };
  try {
    outcome = await withPolicyLikeRun(
      loaded,
      (policy) => createEnvValueGuard(policy.write_secret, env).redact,
      (redact, effectiveLoaded) => ({ redacted: redactResponse(response, redact), effectiveLoaded }),
      (error) => logScrubbedWarning(RETRY_WARNING, error, env, harness, mode),
    );
  } catch (error) {
    return withhold(error);
  }

  const { redacted: { response: rewritten, found }, effectiveLoaded } = outcome;
  if (found === undefined) return SILENT;
  await logEnvValueFinding(
    envelope,
    protocol,
    found,
    'redact',
    '(tool output)',
    harness,
    effectiveLoaded,
    mode,
    build,
  );
  if (shadow) return SILENT;
  try {
    return renderRedaction(protocol, rewritten);
  } catch (error) {
    return withhold(error);
  }
}

async function runFailedToolAlert(
  envelope: Record<string, unknown>,
  harness: HarnessDeclaration,
  protocol: HarnessProtocol,
  loaded: LoadResult,
  env: EnvRecord,
  shadow: boolean,
  build: BuildInfo,
): Promise<RunResult> {
  const selector = protocol.input.error!; // lint keeps it in lockstep with `events.post_tool_failure`
  const failedOutput = stringField(envelope, selector);
  if (failedOutput === undefined) return SILENT;
  const mode = toLogMode(shadow);
  let outcome: { readonly finding: EnvValueFinding | undefined; readonly effectiveLoaded: LoadResult | undefined; };
  try {
    outcome = await withPolicyLikeRun(
      loaded,
      (policy) => createEnvValueGuard(policy.write_secret, env),
      (guard, effectiveLoaded) => ({ finding: guard.find(failedOutput), effectiveLoaded }),
      () => logFailureAlertWarning(FAILED_TOOL_ALERT_RETRY_WARNING, harness, loaded, mode),
    );
  } catch {
    await logFailureAlertWarning(FAILED_TOOL_ALERT_CHECK_WARNING, harness, undefined, mode);
    return SILENT;
  }
  const { finding, effectiveLoaded } = outcome;
  if (finding === undefined) return SILENT;
  const names = finding.names.join(', ');
  const context = finding.names.length === 1
    ? `bouncer: the failed tool output above contains the value of ${names}, a protected environment variable. `
      + 'Do not repeat, store or send it; reference the variable by name.'
    : `bouncer: the failed tool output above contains the values of ${names}, protected environment variables. `
      + 'Do not repeat, store or send them; reference the variables by name.';
  let rendered: RunResult | undefined;
  let renderFailed = false;
  if (!shadow && protocol.output.flag === 'context') {
    try {
      rendered = renderFailureContext(protocol, context);
    } catch {
      renderFailed = true;
    }
  }
  await logEnvValueFinding(
    envelope,
    protocol,
    finding,
    'flag',
    '(failed tool output)',
    harness,
    effectiveLoaded,
    mode,
    build,
  );
  if (renderFailed) await logFailureAlertWarning(FAILED_TOOL_ALERT_RENDER_WARNING, harness, effectiveLoaded, mode);
  return rendered ?? SILENT;
}

export async function run(rawStdin: string, options?: RunOptions): Promise<RunResult> {
  const shadow = options?.shadow ?? false;
  const unrecognizedTokens = options?.unrecognizedTokens ?? [];
  const harnessId = options?.harness ?? DEFAULT_HARNESS_ID;
  const mode = toLogMode(shadow);
  const build = options?.build ?? currentBuild();

  // Loaded (and, on a broken overlay, silently fell back) before dispatch
  // — a policy-load warning is logged regardless of which event this turns
  // out to be, so "the overlay is broken" is visible even on a turn that
  // otherwise produces no verdict at all. Skipped when `harnessId` has no
  // declaration at all to resolve a log path from (ADR-0006 § 6).
  const loaded = await loadCurrentPolicy(harnessId);
  const harness = loaded.harness;
  if (harness !== undefined) {
    if (loaded.warnings.length > 0) await logPolicyWarnings(loaded.warnings, harness, loaded, mode);
    if (unrecognizedTokens.length > 0) {
      // Never disarms enforcement (shadow only ever activates on the exact
      // `--shadow` token — see RunOptions's own comment) — this is purely
      // making the mistake visible in the audit trail.
      await logPolicyWarnings(
        [
          `run: unrecognized argument(s) ${unrecognizedTokens.map((t) => JSON.stringify(t)).join(', ')} `
          + `— ignored, running in normal enforce mode`,
        ],
        harness,
        loaded,
        mode,
      );
    }
  }

  if (harness === undefined || harness.protocol === undefined) {
    const message = `harness ${JSON.stringify(harnessId)} has no usable protocol declaration — failing closed`;
    if (harness !== undefined) {
      try {
        await logPolicyWarnings([message], harness, loaded, mode);
      } catch {
        // Logging must never be what crashes the hook either.
      }
    }
    console.error(`${HOOK_NAME}: ${message}`);
    return { stdout: null, exit: 2 };
  }
  const protocol = harness.protocol;

  const input = parseEnvelope(rawStdin);
  if (input === null) return handleMalformedEnvelope(protocol, harness, loaded, shadow, mode);

  const eventName = stringField(input, protocol.input.event);
  if (protocol.events.session_start !== undefined && eventName === protocol.events.session_start) {
    return runSessionStart(harness, protocol, loaded, shadow, runDoctorChecks, build);
  }

  // Taken once; every policy binding reads this record (see RunOptions.env).
  const env = options?.env ?? process.env;
  // ADR-0008 § 9 events are routed before dispatchByEvent: one rewrites
  // successful output; the other applies the failed-output flag action.
  if (protocol.events.post_tool_failure !== undefined && eventName === protocol.events.post_tool_failure) {
    return runFailedToolAlert(input, harness, protocol, loaded, env, shadow, build);
  }
  if (protocol.events.post_tool !== undefined && eventName === protocol.events.post_tool) {
    return runPostTool(input, harness, protocol, loaded, env, shadow, build);
  }
  try {
    return await withPolicyLikeRun(
      loaded,
      (policy) => createDispatcher(policy, env),
      (dispatcher, effectiveLoaded) => dispatchByEvent(input, eventName, harness, protocol, dispatcher, effectiveLoaded, shadow, build),
      (error) => logScrubbedWarning(RETRY_WARNING, error, env, harness, mode),
    );
  } catch {
    // The baseline dispatcher is the vetted, tested set — it should
    // never throw. If it somehow does, silence is still strictly safer
    // than letting the process crash (a hard exit reads as "no hook ran
    // at all" — an accidental fail-open this catch exists to prevent).
    return SILENT;
  }
}
