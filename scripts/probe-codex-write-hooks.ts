#!/usr/bin/env bun
// Helper for scripts/probe-codex.sh: writes $PROBE_HOME/hooks.json for
// one probe scenario. Takes the canary command as an argument (derived
// ONCE, in setup, against the PLAIN bouncer binary — see
// scripts/probe-codex.sh's own cmd_setup) rather than re-deriving it via
// `doctor --print-canary` on every call: several probes swap the
// PreToolUse command for a tee wrapper or a throwaway hook script whose
// executable basename isn't literally `bouncer`, which `doctor`'s own
// pointsAtBouncer check would never recognize as a primary entry to
// derive a canary FROM — the canary itself never changes (it always
// names the same real binary path), only the primary entry does.
//
// Usage: bun run scripts/probe-codex-write-hooks.ts <probeHome> <preToolUseCommand> <canaryCommand> [includeUserPromptSubmit=yes|no]

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { harnessCaptureFor } from './harness-capture-config.ts';

const [, , probeHome, preToolUseCommand, canaryCommand, includeUserPromptSubmitArg] = process.argv;
if (probeHome === undefined || preToolUseCommand === undefined || canaryCommand === undefined) {
  console.error('usage: probe-codex-write-hooks.ts <probeHome> <preToolUseCommand> <canaryCommand> [includeUserPromptSubmit=yes|no]');
  process.exit(1);
}
const includeUserPromptSubmit = includeUserPromptSubmitArg !== 'no';
const hooksPath = join(probeHome, 'hooks.json');
// Review round 1 S-7: was an independent hand-typed copy of the matcher
// regex — now the SAME derivation scripts/capture-protocol.ts uses,
// imported rather than retyped.
const MATCHER = harnessCaptureFor('codex').matcher;

const doc = {
  hooks: {
    PreToolUse: [
      { matcher: MATCHER, hooks: [{ type: 'command', command: preToolUseCommand }] },
      { matcher: MATCHER, hooks: [{ type: 'command', command: canaryCommand }] },
    ],
    ...(includeUserPromptSubmit ? { UserPromptSubmit: [{ hooks: [{ type: 'command', command: preToolUseCommand }] }] } : {}),
    SessionStart: [{ hooks: [{ type: 'command', command: preToolUseCommand }] }],
  },
};
writeFileSync(hooksPath, JSON.stringify(doc, null, 2));
console.log(`wrote ${hooksPath}`);
