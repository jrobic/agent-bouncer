#!/usr/bin/env bun
// bouncer — single guard binary. `run` speaks the Claude Code hook
// protocol end to end (stdin JSON, verdict on stdout, silent exit on
// allow). `check`, `rules lint`, and `rules list` are the policy-tooling
// subcommands (ticket 06) — dry-run, validate, and inspect the effective
// policy without a live session. `audit`/`doctor` are later tickets
// (10/07), not stubbed here — an unimplemented subcommand name fails
// loudly rather than silently doing nothing.

import { HOOK_NAME } from './adapter/constants.ts';
import { run, type RunResult } from './adapter/run.ts';
import { runCheck, runRulesLint, runRulesList } from './cli-commands.ts';

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

function usageError(command: string | undefined, expected: string): never {
  console.error(
    command === undefined
      ? `${HOOK_NAME}: missing subcommand (expected: ${expected})`
      : `${HOOK_NAME}: unknown subcommand ${JSON.stringify(command)} (expected: ${expected})`,
  );
  process.exit(1);
}

async function main(): Promise<void> {
  const [command, ...rest] = Bun.argv.slice(2);

  if (command === 'run') {
    const { stdout } = await readAndRun(() => Bun.stdin.text());
    if (stdout !== null) process.stdout.write(stdout);
    process.exit(0);
  }

  if (command === 'check') {
    const target = rest.join(' ');
    if (target.trim() === '') {
      console.error(`${HOOK_NAME}: check requires a command argument, e.g. check "git push"`);
      process.exit(1);
    }
    const { text, ok } = await runCheck(target);
    console.log(text);
    process.exit(ok ? 0 : 1);
  }

  if (command === 'rules') {
    const [sub] = rest;
    if (sub === 'lint') {
      const { text, ok } = await runRulesLint();
      console.log(text);
      process.exit(ok ? 0 : 1);
    }
    if (sub === 'list') {
      const { text, ok } = await runRulesList();
      console.log(text);
      process.exit(ok ? 0 : 1);
    }
    usageError(sub, 'lint | list');
  }

  usageError(command, 'run | check | rules');
}

if (import.meta.main) {
  await main();
}
