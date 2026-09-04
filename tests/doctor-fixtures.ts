// Shared scratch-settings fixtures for the doctor test seam (ticket 07) —
// tests/adapter-doctor.test.ts, tests/adapter-run-sessionstart.test.ts, and
// tests/cli-commands-doctor.test.ts all built the same three literals
// independently before this round; a prior review round flagged the drift
// risk (FULL_MATCHER hand-typed as a THIRD copy of the tool list doctor.ts
// itself checks against). FULL_MATCHER is now built FROM
// src/adapter/doctor.ts's own EXPECTED_PRETOOLUSE_TOOLS — one source, not
// a dual that can silently fall out of step with the real check.
//
// This file also doubles as the tracked example doctor.ts's own comment
// points readers at: scratch/demo-settings.json is real but gitignored (a
// clone has no copy of it), while this fixture ships with the repo.

import { buildCanaryCommand } from '../src/adapter/canary.ts';
import { EXPECTED_PRETOOLUSE_TOOLS } from '../src/adapter/doctor.ts';

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
export const FULL_MATCHER = EXPECTED_PRETOOLUSE_TOOLS.map(escapeRegExp).join('|');

export const HEALTHY_HOOKS = {
  PreToolUse: [
    { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: BOUNCER_COMMAND }] },
    { matcher: FULL_MATCHER, hooks: [{ type: 'command', command: CANARY_COMMAND }] },
  ],
  UserPromptSubmit: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
  SessionStart: [{ hooks: [{ type: 'command', command: BOUNCER_COMMAND }] }],
};
