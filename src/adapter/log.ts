// Verdict audit logging. Ported from the legacy hook boilerplate
// (byte-identical between the two prior generations — nothing to converge,
// it was always adapter/runtime plumbing) and adapted for the unified
// binary: one JSONL file per account instead of one per guard, with a
// `family` field on each entry so a single-process, six-family dispatch
// stays legible in the log. Declaration-routed since ticket 15a (ADR-0006
// § 8): every call names the TARGET harness, whose own `env`/`witness`
// resolves the log file, and every entry gains a `harness: "<id>"` field
// — an entry without one predates this ADR.

import { appendFile, mkdir, rename, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { buildIdentity, type BuildInfo, currentBuild } from '../build-info.ts';
import { BASELINE } from '../policy/baseline.ts';
import { policyDigest } from '../policy/digest.ts';
import type { LoadResult } from '../policy/load.ts';
import type { HarnessDeclaration } from '../policy/schema.ts';
import type { Family, Verdict } from '../types.ts';
import { HOOK_NAME } from './constants.ts';
import { hookLogPathFor } from './log-path.ts';

export const MAX_LOG_TARGET_LEN = 200;
export const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5 MB

export function truncateTarget(target: string): string {
  return target.length > MAX_LOG_TARGET_LEN
    ? `${target.slice(0, MAX_LOG_TARGET_LEN - 3)}...`
    : target;
}

async function rotateIfNeeded(logFile: string): Promise<void> {
  try {
    const s = await stat(logFile);
    if (s.size >= MAX_LOG_SIZE) {
      await rename(logFile, `${logFile}.1`);
    }
  } catch {
    // File doesn't exist yet or stat failed — nothing to rotate.
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

// Story 19: the first entry written to a NEW or freshly-ROTATED log file is
// a header record naming every override/relaxation active in the policy
// that produced the entry about to follow it, PLUS (ADR-0006 § 5) every
// harness this account's overlay declared or extended — so a client
// seat's log is self-documenting about how far its effective policy
// diverges from the vetted baseline, without having to separately run
// `rules list`/`harness list` at the same moment. Skipped entirely when
// nothing is active AND no harness is overlay-touched (nothing to
// announce) and when the caller has no LoadResult in scope (a direct
// logVerdict call outside a real policy-loaded run — the header is
// best-effort, not a hard requirement of the JSONL shape).
async function ensureAuditHeader(logFile: string, harness: HarnessDeclaration, loaded: LoadResult | undefined): Promise<void> {
  if (loaded === undefined) return;
  const overlayHarnessCount = loaded.overlayHarnessIds.length;
  if (loaded.activeOverrides.length === 0 && loaded.activeRelaxations.length === 0 && overlayHarnessCount === 0) return;
  if (await fileExists(logFile)) return;

  const header = {
    timestamp: new Date().toISOString(),
    harness: harness.id,
    kind: 'audit-header',
    overrides: loaded.activeOverrides.map((o) => ({ id: o.rule, action: o.action, reason: o.reason })),
    relaxations: loaded.activeRelaxations.map((r) => ({ id: `${r.list}:${r.value}`, action: 'relax', reason: r.reason })),
    overlay_harnesses: loaded.overlayHarnessIds,
  };
  await appendFile(logFile, `${JSON.stringify(header)}\n`, { mode: 0o600 });
}

async function appendLogEntry(entry: Record<string, unknown>, harness: HarnessDeclaration, loaded?: LoadResult): Promise<void> {
  const logFile = hookLogPathFor(harness, HOOK_NAME);
  const line = `${JSON.stringify({ timestamp: new Date().toISOString(), harness: harness.id, ...entry })}\n`;

  try {
    // The log lives under the config dir, not beside a script — a fresh
    // account has no `logs/hooks/` directory yet.
    await mkdir(dirname(logFile), { recursive: true, mode: 0o700 });
    await rotateIfNeeded(logFile);
    await ensureAuditHeader(logFile, harness, loaded);
    await appendFile(logFile, line, { mode: 0o600 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[${HOOK_NAME}] log write failed: ${msg}`);
  }
}

// Ticket 08: shadow mode logs EVERY entry it produces exactly like a real
// run, plus this one extra field — the discriminator a reader (or
// `audit --diff`) uses to tell "what bouncer would have done" apart from
// "what bouncer actually enforced". Only ever "shadow" today (no
// "live"/"enforced" counterpart is written — a normal invocation's entries
// simply carry no `mode` key at all, unchanged from before this ticket).
export type LogMode = 'shadow';

// The `shadow: boolean -> LogMode | undefined` conversion every logVerdict/
// logPolicyWarnings call site in run.ts needs — one place instead of the
// same ternary recomputed at each call.
export function toLogMode(shadow: boolean): LogMode | undefined {
  return shadow ? 'shadow' : undefined;
}

export interface VerdictLogContext {
  readonly sessionId: string | null;
  readonly toolName: string | null;
  // Review round 1 P-4: Codex's own `permission_mode` (or any future
  // harness's equivalent field, via `[harness.protocol.input].permission`)
  // — logged verbatim when the envelope carried one, absent from the
  // entry entirely otherwise (claude-code's envelope carries none).
  // Never read for a decision anywhere in this codebase — see the 15b
  // report's grep proof.
  readonly permission?: string | null;
}

// Every verdict this adapter reaches gets logged — block/confirm/observe
// from PreToolUse, flag from UserPromptSubmit — including `observe` entries
// produced only for audit (never surfaced to the model). `context` carries
// the session_id/tool_name/permission the raw envelope's input map named,
// kept for context in the log line. `harness` is the TARGET harness this
// verdict was judged under — resolves the log path and stamps every entry.
// `loaded`, when given, is the policy load this verdict came from — passed
// through so a fresh/rotated file gets its Story 19 audit header. `mode`,
// when given, is ticket 08's shadow tag — `run()` passes it on EVERY log
// call it makes while `--shadow` is active, never only some of them.
export async function logVerdict(
  family: Family,
  context: VerdictLogContext,
  verdict: Verdict,
  harness: HarnessDeclaration,
  loaded?: LoadResult,
  mode?: LogMode,
  build: BuildInfo = currentBuild(),
): Promise<void> {
  const effectivePolicy = loaded?.policy ?? BASELINE.rules;
  const activeOverrides = loaded?.activeOverrides ?? [];
  const activeRelaxations = loaded?.activeRelaxations ?? [];

  await appendLogEntry({
    session_id: context.sessionId,
    tool_name: context.toolName,
    ...(context.permission !== undefined && context.permission !== null ? { permission: context.permission } : {}),
    family,
    verdict: verdict.verdict,
    rule_id: verdict.ruleId,
    target: truncateTarget(verdict.target),
    build: buildIdentity(build),
    policy: policyDigest(effectivePolicy, activeOverrides, activeRelaxations),
    ...(mode !== undefined ? { mode } : {}),
  }, harness, loaded);
}

// The "loud warning" AC2 requires: a rejected overlay (invalid TOML, a
// lint-failing rule or override, a wrong-shaped table) must be visible
// somewhere other than a verdict nobody asked for. This writes one entry
// per warning to the SAME audit log, kind-tagged so `rules list`/a future
// `doctor` can find it without parsing free-text `verdict` fields.
export async function logPolicyWarnings(
  warnings: readonly string[],
  harness: HarnessDeclaration,
  loaded?: LoadResult,
  mode?: LogMode,
): Promise<void> {
  for (const message of warnings) {
    // oxlint-disable-next-line no-await-in-loop
    await appendLogEntry({ kind: 'policy-warning', message, ...(mode !== undefined ? { mode } : {}) }, harness, loaded);
  }
}

// Ticket 08, decision 2: in shadow mode, SessionStart's own doctor verdict
// (what buildSessionStartContext would have put on stdout — a wiring
// scream, or an override/relaxation announcement) has nowhere else to go,
// since shadow suppresses that stdout entirely. Logged only when there
// WOULD have been something to say (`message` — the caller only calls this
// when buildSessionStartContext returned non-null); a fully healthy,
// nothing-to-announce SessionStart logs nothing, in shadow or not, the
// same "silence really means silence" contract SessionStart already has.
export async function logSessionStartShadow(message: string, harness: HarnessDeclaration, loaded?: LoadResult): Promise<void> {
  await appendLogEntry({ kind: 'sessionstart-shadow', message, mode: 'shadow' satisfies LogMode }, harness, loaded);
}
