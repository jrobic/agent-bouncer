#!/usr/bin/env bun
// Helper for scripts/probe-codex.sh's cmd_setup: derives the real canary
// command ONCE against the plain bouncer binary (never hand-typed,
// mirrors scripts/capture-protocol.ts's own approach) and caches it to
// $PROBE_HOME/canary-command.txt for every later write_hooks_json call.
//
// Usage: bun run scripts/probe-codex-derive-canary.ts <probeHome> <bouncerBin>

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { harnessCaptureFor } from './harness-capture-config.ts';

const [, , probeHome, bouncerBin] = process.argv;
if (probeHome === undefined || bouncerBin === undefined) {
  console.error('usage: probe-codex-derive-canary.ts <probeHome> <bouncerBin>');
  process.exit(1);
}
// Review round 1 S-7: was an independent hand-typed copy of the matcher
// regex — now the SAME derivation scripts/capture-protocol.ts uses,
// imported rather than retyped.
const matcher = harnessCaptureFor('codex').matcher;
const primary = `${bouncerBin} run --harness codex`;

writeFileSync(join(probeHome, 'hooks.json'),
  JSON.stringify({ hooks: { PreToolUse: [{ matcher, hooks: [{ type: 'command', command: primary }] }] } }, null, 2));

const proc = Bun.spawnSync({
  cmd: [bouncerBin, 'doctor', '--print-canary', '--harness', 'codex'],
  env: { ...process.env, CODEX_HOME: probeHome },
  stdout: 'pipe',
  stderr: 'pipe',
});
if (proc.exitCode !== 0) {
  console.error(`doctor --print-canary failed: ${proc.stderr.toString('utf8')}`);
  process.exit(1);
}
const entry = JSON.parse(proc.stdout.toString('utf8')) as { hooks: readonly { command: string; }[]; };
writeFileSync(join(probeHome, 'canary-command.txt'), entry.hooks[0]!.command);
console.log(`cached canary command to ${join(probeHome, 'canary-command.txt')}`);
