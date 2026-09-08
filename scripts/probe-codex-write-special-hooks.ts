#!/usr/bin/env bun
// Helper for scripts/probe-codex.sh's probes 9 and 10 — two hooks.json
// shapes that don't fit write_hooks_json's own "primary + canary +
// UserPromptSubmit + SessionStart, all pointing at the same command"
// pattern:
//   canary-only   — PreToolUse carries ONLY a broken canary (a
//                   non-executable binary path); SessionStart still
//                   points at the real bouncer, so `codex exec`'s own
//                   session can start normally while the canary alone is
//                   what's under test.
//   bad-harness   — PreToolUse points at a real bouncer binary with an
//                   UNDECLARED --harness id, the exit-2 fail-closed case.
//
// Usage:
//   bun run scripts/probe-codex-write-special-hooks.ts canary-only <probeHome> <canaryCommand> <sessionStartCommand>
//   bun run scripts/probe-codex-write-special-hooks.ts bad-harness <probeHome> <preToolUseCommand>

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { harnessCaptureFor } from './harness-capture-config.ts';

// Review round 1 S-7: was an independent hand-typed copy of the matcher
// regex — now the SAME derivation scripts/capture-protocol.ts uses,
// imported rather than retyped.
const MATCHER = harnessCaptureFor('codex').matcher;
const [, , mode, probeHome, ...rest] = process.argv;

if (mode === 'canary-only') {
  const [canaryCommand, sessionStartCommand] = rest;
  if (probeHome === undefined || canaryCommand === undefined || sessionStartCommand === undefined) {
    console.error('usage: probe-codex-write-special-hooks.ts canary-only <probeHome> <canaryCommand> <sessionStartCommand>');
    process.exit(1);
  }
  const doc = {
    hooks: {
      PreToolUse: [{ matcher: MATCHER, hooks: [{ type: 'command', command: canaryCommand }] }],
      SessionStart: [{ hooks: [{ type: 'command', command: sessionStartCommand }] }],
    },
  };
  writeFileSync(join(probeHome, 'hooks.json'), JSON.stringify(doc, null, 2));
  console.log(`wrote ${join(probeHome, 'hooks.json')} (canary-only)`);
} else if (mode === 'bad-harness') {
  const [preToolUseCommand] = rest;
  if (probeHome === undefined || preToolUseCommand === undefined) {
    console.error('usage: probe-codex-write-special-hooks.ts bad-harness <probeHome> <preToolUseCommand>');
    process.exit(1);
  }
  const doc = { hooks: { PreToolUse: [{ matcher: MATCHER, hooks: [{ type: 'command', command: preToolUseCommand }] }] } };
  writeFileSync(join(probeHome, 'hooks.json'), JSON.stringify(doc, null, 2));
  console.log(`wrote ${join(probeHome, 'hooks.json')} (bad-harness)`);
} else {
  console.error(`unknown mode: ${JSON.stringify(mode)} (expected canary-only|bad-harness)`);
  process.exit(1);
}
