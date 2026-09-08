// PreToolUse / UserPromptSubmit dispatch: routes a NEUTRAL call (ADR-0006
// § 3 — commands, read/write path, pattern, text, urls, mcp name) to the
// right engine function(s), in the shape each function actually accepts.
// Nothing here names a harness, a tool, or a field any more — the tools
// map (src/adapter/neutral-call.ts) is what turns a harness's own
// envelope into this vocabulary; ticket 15a is what moved the CC-specific
// wiring (Read/Edit/Write/Grep/Glob/MultiEdit field names, `mcp__*`
// scoping) out of this module and into policy/harness/claude-code.toml.
//
// createDispatcher(policy) builds a dispatcher bound to a SPECIFIC policy
// (baseline, or a merged baseline+overlay+override set from
// src/policy/load.ts) — this is what makes the compiled binary actually
// respect an account's overlay: run.ts loads the current policy once per
// invocation and dispatches through the checkers built from it, never
// through a module-level baseline-only binding. `inspectPreToolUse` etc.
// exported below are the baseline-bound convenience form, for callers that
// don't need overlay awareness (the fixture set, most tests).

import { createCommandChecker } from '../command-rules.ts';
import { createCheckMcpWrite } from '../mcp-write-rules.ts';
import { BASELINE } from '../policy/baseline.ts';
import type { RulesPolicy } from '../policy/schema.ts';
import { createScanPrompt } from '../prompt-rules.ts';
import { createProtectedWriteChecker } from '../protected-write-rules.ts';
import { createSecretChecker } from '../secret-rules.ts';
import { type Family, type Verdict, VERDICT_SEVERITY } from '../types.ts';
import { createScanSecrets } from '../write-secret-rules.ts';
import type { NeutralCall } from './neutral-call.ts';
import { canonicalizePath } from './paths.ts';

export interface FamilyVerdict {
  readonly family: Family;
  readonly verdict: Verdict;
}

export interface Dispatcher {
  readonly inspectPreToolUse: (call: NeutralCall) => Promise<FamilyVerdict | null>;
  readonly classifyObserve: (call: NeutralCall) => FamilyVerdict | null;
  readonly inspectUserPromptSubmit: (prompt: string) => readonly Verdict[];
}

// Severity ordering across families — NOT first-match-wins. A single tool
// call can legitimately trigger more than one family at once: `git config
// credential.helper store` is both an unsafe git subcommand (command
// family, confirm) AND a credential leak (secret family, block). The
// workstation ran these as independent, separately-registered hooks, and
// Claude Code denies a tool call if ANY registered hook denies it — the
// strictest verdict wins regardless of which hook happened to run first.
// Unifying six families into one dispatch must preserve that property:
// checking command before secret must never let a stricter secret-family
// block go unheard just because command found a milder confirm first.
// VERDICT_SEVERITY lives in src/types.ts so every engine family ranks the
// shared VerdictKind vocabulary identically.
// `flag` is not part of this ordering at all — a PreToolUse family that
// emits `flag` is a routing bug (flag belongs to UserPromptSubmit only; see
// degrade.ts's own guard). Giving it severity 0 and letting the max-reduce
// silently swallow it whenever a block/confirm co-occurs would hide
// exactly that bug. Every hit is checked for `flag` BEFORE ranking,
// independent of whether anything stricter also fired.
// Exported for its own unit test (tests/adapter-dispatch.test.ts): no
// current PreToolUse family actually emits `flag`, so the misrouting guard
// below can only be exercised directly, with a hand-built FamilyVerdict —
// there is no real input that reaches it through inspectPreToolUse today.
export function strictestOf(hits: readonly FamilyVerdict[]): FamilyVerdict | null {
  const misrouted = hits.find((hit) => hit.verdict.verdict === 'flag');
  if (misrouted) {
    throw new Error(
      `inspectPreToolUse: family "${misrouted.family}" emitted a "flag" verdict `
        + `(ruleId ${misrouted.verdict.ruleId}) — flag belongs to UserPromptSubmit only`,
    );
  }
  if (hits.length === 0) return null;
  return hits.reduce((strictest, hit) =>
    VERDICT_SEVERITY[hit.verdict.verdict] > VERDICT_SEVERITY[strictest.verdict.verdict] ? hit : strictest
  );
}

/**
 * Builds a full dispatcher — {inspectPreToolUse, classifyObserve,
 * inspectUserPromptSubmit} — bound to the given policy (baseline, or a
 * merged baseline+overlay+override set from src/policy/load.ts). This is
 * what the adapter's run.ts uses for real, per-invocation, overlay-aware
 * dispatch.
 */
export function createDispatcher(policy: RulesPolicy): Dispatcher {
  const command = createCommandChecker(policy.command);
  const secret = createSecretChecker(policy.secret, policy.command.git.config_read_modes);
  const protectedWrite = createProtectedWriteChecker(policy.protected_write, policy.harness);
  const checkMcpWriteBound = createCheckMcpWrite(policy.mcp_write.read_prefixes);
  const scanSecretsBound = createScanSecrets(policy.write_secret);
  const scanPromptBound = createScanPrompt(policy.prompt);

  function inspectCommandFamily(call: NeutralCall): FamilyVerdict | null {
    for (const cmd of call.commands) {
      const verdict = command.checkBash(cmd);
      if (verdict) return { family: 'command', verdict };
    }
    return null;
  }

  async function secretPathHit(path: string): Promise<FamilyVerdict | null> {
    const verdict = secret.checkPath(await canonicalizePath(path));
    return verdict ? { family: 'secret', verdict } : null;
  }

  // Every surface the secret family covers (ADR-0006 § 3): commands
  // (Bash-shaped strings), `pattern` matched literally (Glob only, checked
  // before `path` so a malicious pattern can't hide behind an innocuous
  // path), `path` after canonicalisation, and urls. A row rarely
  // populates more than one of these — `ctx_execute_file` (commands +
  // path) is the one exception, and command order matches the pre-15a
  // extractTargets/inspectSecretFamily order exactly (commands, then
  // paths, then urls).
  async function inspectSecretFamily(call: NeutralCall): Promise<FamilyVerdict | null> {
    for (const cmd of call.commands) {
      const verdict = secret.checkSecretBash(cmd);
      if (verdict) return { family: 'secret', verdict };
    }
    if (call.pattern !== null) {
      const verdict = secret.checkPath(call.pattern);
      if (verdict) return { family: 'secret', verdict };
    }
    if (call.path !== null) {
      const hit = await secretPathHit(call.path);
      if (hit) return hit;
    }
    for (const url of call.urls) {
      const verdict = secret.checkUrl(url);
      if (verdict) return { family: 'secret', verdict };
    }
    return null;
  }

  // Protected-write reaches `path` only for a `write` role row (mirrors
  // the pre-15a PROTECTED_WRITE_FILE_PATH_FIELD map, which deliberately
  // excluded Read) and `commands` for any row that populated them
  // (Bash-shaped writes, `checkBashWrites` parses shell syntax a
  // structured `path` never needs) — a row supplies at most one of the
  // two in practice, so checking both unconditionally reproduces the
  // pre-15a either/or branching without a role check on the command loop.
  async function inspectProtectedWriteFamily(call: NeutralCall): Promise<FamilyVerdict | null> {
    if (call.role === 'write' && call.path !== null) {
      const verdict = await protectedWrite.checkPath(call.path);
      if (verdict) return { family: 'protected-write', verdict };
    }
    for (const cmd of call.commands) {
      // Sequential on purpose: the first protected target preserves the
      // command's source order and avoids canonicalizing later candidates.
      // oxlint-disable-next-line no-await-in-loop
      const verdict = await protectedWrite.checkBashWrites(cmd);
      if (verdict) return { family: 'protected-write', verdict };
    }
    return null;
  }

  function inspectWriteSecretFamily(call: NeutralCall): FamilyVerdict | null {
    if (call.text === null) return null;
    const target = call.path ?? `(${call.toolName})`;
    const verdict = scanSecretsBound(call.text, target);
    return verdict ? { family: 'write-secret', verdict } : null;
  }

  // Exact tool rows win over the `mcp__*` glob row at selector-resolution
  // time (src/adapter/neutral-call.ts's findToolRow) — a context-mode
  // tool declared with role "command" never reaches here at all, so this
  // needs no separate exclusion the way the pre-15a isGuardedToolName
  // check did.
  function inspectMcpWriteFamily(call: NeutralCall): FamilyVerdict | null {
    if (call.mcpName === null) return null;
    const verdict = checkMcpWriteBound(call.mcpName);
    return verdict ? { family: 'mcp-write', verdict } : null;
  }

  async function inspectPreToolUse(call: NeutralCall): Promise<FamilyVerdict | null> {
    const hits: FamilyVerdict[] = [];

    const commandHit = inspectCommandFamily(call);
    if (commandHit) hits.push(commandHit);

    const secretHit = await inspectSecretFamily(call);
    if (secretHit) hits.push(secretHit);

    const protectedWriteHit = await inspectProtectedWriteFamily(call);
    if (protectedWriteHit) hits.push(protectedWriteHit);

    const writeSecretHit = inspectWriteSecretFamily(call);
    if (writeSecretHit) hits.push(writeSecretHit);

    const mcpWriteHit = inspectMcpWriteFamily(call);
    if (mcpWriteHit) hits.push(mcpWriteHit);

    return strictestOf(hits);
  }

  // Called only when inspectPreToolUse found nothing to block/confirm on a
  // command-shaped call — classifies whether the allow is worth an audit
  // log entry (a named conditional git rule fired) versus fully silent
  // (safe_subcommands, or not git at all). Never changes the permission
  // outcome, which inspectPreToolUse already settled.
  function classifyObserve(call: NeutralCall): FamilyVerdict | null {
    for (const cmd of call.commands) {
      const verdict = command.classifyGitAllow(cmd);
      if (verdict) return { family: 'command', verdict };
    }
    return null;
  }

  function inspectUserPromptSubmit(prompt: string): readonly Verdict[] {
    return scanPromptBound(prompt);
  }

  return { inspectPreToolUse, classifyObserve, inspectUserPromptSubmit };
}

const BASELINE_DISPATCHER = createDispatcher(BASELINE.rules);

/** Uses the embedded baseline (no overlay awareness) — for callers that
 * don't need it: the fixture set, most tests. */
export const inspectPreToolUse = BASELINE_DISPATCHER.inspectPreToolUse;
/** Uses the embedded baseline. */
export const classifyObserve = BASELINE_DISPATCHER.classifyObserve;
/** Uses the embedded baseline. */
export const inspectUserPromptSubmit = BASELINE_DISPATCHER.inspectUserPromptSubmit;
