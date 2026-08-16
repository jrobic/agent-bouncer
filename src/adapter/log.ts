// Verdict audit logging. Ported from the workstation hook boilerplate
// (byte-identical between the two prior generations — nothing to converge,
// it was always adapter/runtime plumbing) and adapted for the unified
// binary: one JSONL file per account instead of one per guard, with a
// `family` field on each entry so a single-process, five-family dispatch
// stays legible in the log.

import { appendFile, mkdir, rename, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Family, Verdict } from '../types.ts';
import { HOOK_NAME } from './constants.ts';
import { hookLogPath } from './log-path.ts';
import type { HookInput } from './protocol.ts';

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

// Every verdict this adapter reaches gets logged — block/confirm/observe
// from PreToolUse, flag from UserPromptSubmit — including `observe` entries
// produced only for audit (never surfaced to the model). `input` is the raw
// hook envelope, kept for session_id/tool_name context in the log line.
export async function logVerdict(
  family: Family,
  input: HookInput,
  verdict: Verdict,
): Promise<void> {
  const logFile = hookLogPath(HOOK_NAME);
  const entry = `${
    JSON.stringify({
      timestamp: new Date().toISOString(),
      session_id: input.session_id ?? null,
      tool_name: input.tool_name ?? null,
      family,
      verdict: verdict.verdict,
      rule_id: verdict.ruleId,
      target: truncateTarget(verdict.target),
    })
  }\n`;

  try {
    // The log lives under the config dir, not beside a script — a fresh
    // account has no `logs/hooks/` directory yet.
    await mkdir(dirname(logFile), { recursive: true, mode: 0o700 });
    await rotateIfNeeded(logFile);
    await appendFile(logFile, entry, { mode: 0o600 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[${HOOK_NAME}] log write failed: ${msg}`);
  }
}
