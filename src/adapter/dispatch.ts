// PreToolUse / UserPromptSubmit dispatch: routes a hook envelope to the
// right engine function(s) for its tool name, in the shape each function
// actually accepts. This is CC-specific tool-name wiring (Read/Edit/Write/
// Grep/Glob/MultiEdit field names, `mcp__*` scoping) — the reason it lives
// in the adapter and not in src/*.ts: ticket 03 deliberately stopped at
// target extraction and left this per-tool dispatch unbuilt.

import { checkBash, classifyGitAllow } from '../command-rules.ts';
import { checkMcpWrite } from '../mcp-write-rules.ts';
import { scanPrompt } from '../prompt-rules.ts';
import { checkPath, checkSecretBash, checkUrl } from '../secret-rules.ts';
import { extractTargets, type GuardedToolCall, isGuardedToolName, readStringField } from '../targets.ts';
import type { Family, Verdict, VerdictKind } from '../types.ts';
import { scanSecrets } from '../write-secret-rules.ts';
import { HOOK_NAME } from './constants.ts';
import { canonicalizePath } from './paths.ts';
import type { HookInput } from './protocol.ts';

export interface FamilyVerdict {
  readonly family: Family;
  readonly verdict: Verdict;
}

// extractTargets speaks the engine's narrower GuardedToolCall, not the full
// CC envelope — this is the one place that maps down between them.
function toGuardedCall(input: HookInput): GuardedToolCall {
  return { toolName: input.tool_name, toolInput: input.tool_input };
}

// Bash and the context-mode sandbox tools carry commands, paths, and urls
// under one shape — the command family only ever judges commands.
function inspectCommandFamily(input: HookInput): FamilyVerdict | null {
  const { commands } = extractTargets(toGuardedCall(input), HOOK_NAME);
  for (const cmd of commands) {
    const verdict = checkBash(cmd);
    if (verdict) return { family: 'command', verdict };
  }
  return null;
}

// The secret family covers three surfaces: commands/paths/urls reachable
// through Bash or a context-mode tool (extractTargets), plus the native CC
// file tools (Read/Edit/MultiEdit/Write/NotebookEdit/Grep/Glob), whose path
// fields extractTargets does not know about — ticket 03 scoped it to Bash +
// context-mode only.
const NATIVE_FILE_PATH_FIELD: Readonly<Record<string, string>> = {
  Read: 'file_path',
  Edit: 'file_path',
  MultiEdit: 'file_path',
  Write: 'file_path',
  NotebookEdit: 'notebook_path',
};

// Canonicalizes then checks a single path, wrapped as a `secret` family hit
// — the one pattern every native-file-tool branch below needs, so it is
// named once instead of repeated at each of Read/Edit/MultiEdit/Write/
// NotebookEdit, Grep, Glob (twice), and the guarded-tool paths loop.
async function secretPathHit(path: string): Promise<FamilyVerdict | null> {
  const verdict = checkPath(await canonicalizePath(path));
  return verdict ? { family: 'secret', verdict } : null;
}

async function inspectSecretFamily(input: HookInput): Promise<FamilyVerdict | null> {
  const tool = input.tool_name;

  if (tool !== undefined && tool in NATIVE_FILE_PATH_FIELD) {
    const ti = input.tool_input ?? {};
    const path = readStringField(ti, NATIVE_FILE_PATH_FIELD[tool]!, HOOK_NAME);
    return path === null ? null : secretPathHit(path);
  }

  if (tool === 'Grep') {
    const path = readStringField(input.tool_input ?? {}, 'path', HOOK_NAME);
    return path === null ? null : secretPathHit(path);
  }

  if (tool === 'Glob') {
    const ti = input.tool_input ?? {};
    const pattern = readStringField(ti, 'pattern', HOOK_NAME);
    const rawPath = readStringField(ti, 'path', HOOK_NAME);
    const patternHit = pattern !== null ? checkPath(pattern) : null;
    if (patternHit) return { family: 'secret', verdict: patternHit };
    return rawPath !== null ? secretPathHit(rawPath) : null;
  }

  if (isGuardedToolName(tool)) {
    const { commands, paths, urls } = extractTargets(toGuardedCall(input), HOOK_NAME);
    for (const cmd of commands) {
      const verdict = checkSecretBash(cmd);
      if (verdict) return { family: 'secret', verdict };
    }
    for (const path of paths) {
      // Sequential on purpose: the first denial ends the inspection, and a
      // guarded tool call rarely names more than a couple of paths.
      // oxlint-disable-next-line no-await-in-loop
      const hit = await secretPathHit(path);
      if (hit) return hit;
    }
    for (const url of urls) {
      const verdict = checkUrl(url);
      if (verdict) return { family: 'secret', verdict };
    }
  }

  return null;
}

// Text about to be written, per tool — mirrors the workstation
// guard-write-secret dispatch (Write.content, Edit.new_string,
// MultiEdit.edits[].new_string joined).
function writeSecretText(tool: string | undefined, ti: Record<string, unknown>): string | null {
  if (tool === 'Write') {
    return readStringField(ti, 'content', HOOK_NAME);
  }
  if (tool === 'Edit') {
    return readStringField(ti, 'new_string', HOOK_NAME);
  }
  if (tool === 'MultiEdit') {
    const edits = Array.isArray(ti['edits']) ? (ti['edits'] as unknown[]) : [];
    return edits
      .map((edit) =>
        edit && typeof edit === 'object' && typeof (edit as { new_string?: unknown }).new_string === 'string'
          ? (edit as { new_string: string }).new_string
          : ''
      )
      .join('\n');
  }
  return null;
}

function inspectWriteSecretFamily(input: HookInput): FamilyVerdict | null {
  const ti = input.tool_input ?? {};
  const text = writeSecretText(input.tool_name, ti);
  if (text === null) return null;
  const target = readStringField(ti, 'file_path', HOOK_NAME) ?? `(${input.tool_name})`;
  const verdict = scanSecrets(text, target);
  return verdict ? { family: 'write-secret', verdict } : null;
}

// Every `mcp__*` tool NOT already claimed by the context-mode sandbox
// (command/secret family above) is a generic MCP call. Order matters: this
// must run after the context-mode check, or `ctx_execute` (itself
// `mcp__plugin_context-mode_context-mode__ctx_execute`) would be judged as
// a generic MCP write instead of routing to its own command/secret family.
function inspectMcpWriteFamily(input: HookInput): FamilyVerdict | null {
  const tool = input.tool_name;
  if (tool === undefined || !tool.startsWith('mcp__') || isGuardedToolName(tool)) return null;
  const verdict = checkMcpWrite(tool);
  return verdict ? { family: 'mcp-write', verdict } : null;
}

// Severity ordering across families — NOT first-match-wins. A single tool
// call can legitimately trigger more than one family at once: `git config
// credential.helper store` is both an unsafe git subcommand (command
// family, confirm) AND a credential leak (secret family, block). The
// workstation ran these as independent, separately-registered hooks, and
// Claude Code denies a tool call if ANY registered hook denies it — the
// strictest verdict wins regardless of which hook happened to run first.
// Unifying five families into one dispatch must preserve that property:
// checking command before secret must never let a stricter secret-family
// block go unheard just because command found a milder confirm first.
//
// Typed as a total map over VerdictKind (not `Record<string, number>`): a
// future fifth verdict kind added to the union without a line here becomes
// a tsc error, not a silent `undefined` at runtime.
const SEVERITY: Record<VerdictKind, number> = { block: 3, confirm: 2, observe: 1, flag: 0 };

// `flag` is not part of this ordering at all — a PreToolUse family that
// emits `flag` is a routing bug (flag belongs to UserPromptSubmit only; see
// degradeToClaudeCode's own guard). Giving it severity 0 and letting the
// max-reduce silently swallow it whenever a block/confirm co-occurs would
// hide exactly that bug. Every hit is checked for `flag` BEFORE ranking,
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
    SEVERITY[hit.verdict.verdict] > SEVERITY[strictest.verdict.verdict] ? hit : strictest
  );
}

// PreToolUse: every applicable family is evaluated (a tool call may match
// more than one), and the strictest verdict wins. See strictestOf() above.
export async function inspectPreToolUse(input: HookInput): Promise<FamilyVerdict | null> {
  const hits: FamilyVerdict[] = [];

  const commandHit = inspectCommandFamily(input);
  if (commandHit) hits.push(commandHit);

  const secretHit = await inspectSecretFamily(input);
  if (secretHit) hits.push(secretHit);

  const writeSecretHit = inspectWriteSecretFamily(input);
  if (writeSecretHit) hits.push(writeSecretHit);

  const mcpWriteHit = inspectMcpWriteFamily(input);
  if (mcpWriteHit) hits.push(mcpWriteHit);

  return strictestOf(hits);
}

// Called only when inspectPreToolUse found nothing to block/confirm on a
// command-shaped call — classifies whether the allow is worth an audit log
// entry (a named conditional git rule fired) versus fully silent
// (SAFE_GIT_SUBCOMMANDS, or not git at all). Never changes the permission
// outcome, which inspectPreToolUse already settled.
export function classifyObserve(input: HookInput): FamilyVerdict | null {
  const { commands } = extractTargets(toGuardedCall(input), HOOK_NAME);
  for (const cmd of commands) {
    const verdict = classifyGitAllow(cmd);
    if (verdict) return { family: 'command', verdict };
  }
  return null;
}

export function inspectUserPromptSubmit(input: HookInput): readonly Verdict[] {
  return scanPrompt(input.prompt ?? '');
}
