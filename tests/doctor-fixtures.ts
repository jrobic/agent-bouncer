// Shared scratch-settings fixtures for the doctor test seam (ticket 07) —
// tests/adapter-doctor.test.ts, tests/adapter-run-sessionstart.test.ts, and
// tests/cli-commands-doctor.test.ts all built the same three literals
// independently before this round; a prior review round flagged the drift
// risk (FULL_MATCHER hand-typed as a THIRD copy of the tool list doctor.ts
// itself checks against). FULL_MATCHER is now built FROM the embedded
// claude-code baseline declaration's own `protocol.tools` map (ADR-0006
// § 3), through the SAME representativeToolNames the hook-file codec's
// own coverage check uses (src/adapter/codecs/wiring/hook-file.ts) — one source,
// not a dual that can silently fall out of step with the real check.
//
// This file also doubles as the tracked example doctor.ts's own comment
// points readers at: scratch/demo-settings.json is real but gitignored (a
// clone has no copy of it), while this fixture ships with the repo.

import { buildCanaryCommand } from '../src/adapter/canary.ts';
import { representativeToolNames } from '../src/adapter/codecs/wiring/hook-file.ts';
import { BASELINE } from '../src/policy/baseline.ts';

const CLAUDE_CODE_PROTOCOL = BASELINE.rules.harness.find((h) => h.id === 'claude-code')!.protocol!;

export const BOUNCER_COMMAND = '/fake/checkout/dist/bouncer run';
export const CANARY_COMMAND = buildCanaryCommand('/fake/checkout/dist/bouncer');

// Paired beside a primary hook, but not a shell liveness probe. The doctor
// must not infer semantics from the incidental word "ping".
export const PING_WORD_COMMAND = 'printf ping';

// Ticket 08: shadow-mode wiring — same binary, same `run` arg
// (pointsAtBouncer only requires 'run' among the args, so this already
// counts as wired), with `--shadow` appended.
export const BOUNCER_SHADOW_COMMAND = '/fake/checkout/dist/bouncer run --shadow';

// Ticket 08 review round: a typo'd flag in the LIVE wiring — still
// "points at bouncer" (pointsAtBouncer only checks for 'run'), but the
// wiring check should fail loudly on the unrecognized token.
export const BOUNCER_TYPO_COMMAND = '/fake/checkout/dist/bouncer run --shadwo';

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// A matcher that covers every tool doctor.ts's own PreToolUse coverage
// check expects — derived, not hand-typed, so this fixture cannot drift
// out of sync with the list it exists to satisfy.
export const FULL_MATCHER = representativeToolNames(CLAUDE_CODE_PROTOCOL.tools).map(escapeRegExp).join('|');

export const HEALTHY_HOOKS = {
  PreToolUse: [
    { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
    { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: CANARY_COMMAND }] },
  ],
  UserPromptSubmit: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
  SessionStart: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
};

// Ticket 15b: the same shared-fixture discipline, for codex-hooks
// (ADR-0006 § 6) — tests/fixtures-protocol.test.ts's codex.json replay
// reuses these rather than a second hand-typed copy.
const CODEX_PROTOCOL = BASELINE.rules.harness.find((h) => h.id === 'codex')!.protocol!;

export const CODEX_BOUNCER_COMMAND = '/fake/checkout/dist/bouncer run --harness codex';
export const CODEX_CANARY_COMMAND = buildCanaryCommand('/fake/checkout/dist/bouncer');
export const CODEX_FULL_MATCHER = representativeToolNames(CODEX_PROTOCOL.tools).map(escapeRegExp).join('|');

export const CODEX_HEALTHY_HOOKS = {
  PreToolUse: [
    { matcher: CODEX_FULL_MATCHER, hooks: [{ type: 'command', command: CODEX_BOUNCER_COMMAND }] },
    { matcher: CODEX_FULL_MATCHER, hooks: [{ type: 'command', command: CODEX_CANARY_COMMAND }] },
  ],
  UserPromptSubmit: [{ hooks: [{ type: 'command', command: CODEX_BOUNCER_COMMAND }] }],
  SessionStart: [{ hooks: [{ type: 'command', command: CODEX_BOUNCER_COMMAND }] }],
};

// codex-hooks' own trust ledger (ADR-0006 § 6): every bouncer-pointing
// handler above (never the canary — `sh -c ...`, not a `bouncer run`
// command) needs a `[hooks.state."<hooksJsonPath>:<event_snake>:<i>:<j>"]`
// record before doctor considers it guarded — this builds that table for
// a given hooks.json path, so a caller only ever states WHERE the file
// will live, never re-derives the key format by hand.
export function codexTrustToml(hooksJsonPath: string): string {
  const entries: readonly [event: string, index: number][] = [
    ['pre_tool_use', 0],
    ['user_prompt_submit', 0],
    ['session_start', 0],
  ];
  return entries.map(([event, index]) =>
    `[hooks.state."${hooksJsonPath}:${event}:${index}:0"]\ntrusted_hash = "sha256:${'a'.repeat(64)}"\n`
  )
    .join('\n');
}
