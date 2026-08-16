#!/usr/bin/env bun
// bouncer — single guard binary. `run` is the only subcommand this ticket
// builds: it speaks the Claude Code hook protocol end to end (stdin JSON,
// verdict on stdout, silent exit on allow). `check`/`rules`/`audit`/`doctor`
// are future tickets (06+), not stubbed here — an unimplemented subcommand
// name fails loudly rather than silently doing nothing.

import { HOOK_NAME } from './adapter/constants.ts';
import { run, type RunResult } from './adapter/run.ts';

// Reads stdin and runs it, with the read itself inside the same fail-open
// contract as a malformed envelope: an unreadable stdin (a broken pipe, a
// permissions error) must exit silently, never crash with a stack trace.
// Exported (and parameterized on the reader) so a test can simulate a
// throwing read without spawning a subprocess or fighting process.exit().
export async function readAndRun(readStdin: () => Promise<string>): Promise<RunResult> {
  let raw: string;
  try {
    raw = await readStdin();
  } catch {
    return { stdout: null };
  }
  return run(raw);
}

async function main(): Promise<void> {
  const [command] = Bun.argv.slice(2);

  if (command !== 'run') {
    console.error(
      command === undefined
        ? `${HOOK_NAME}: missing subcommand (expected: run)`
        : `${HOOK_NAME}: unknown subcommand ${JSON.stringify(command)} (expected: run)`,
    );
    process.exit(1);
  }

  const { stdout } = await readAndRun(() => Bun.stdin.text());
  if (stdout !== null) {
    process.stdout.write(stdout);
  }
  process.exit(0);
}

if (import.meta.main) {
  await main();
}
