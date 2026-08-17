#!/usr/bin/env bun
// bouncer — single guard binary. `run` speaks the Claude Code hook
// protocol end to end (stdin JSON, verdict on stdout, silent exit on
// allow) — this is also how SessionStart reaches `doctor`'s wiring/policy/
// log check (ticket 07): no separate subcommand for the hook path, the
// same `run` envelope dispatch routes SessionStart to it. `check`,
// `rules lint`, `rules list`, and `doctor` are the policy/diagnostic
// tooling subcommands — dry-run, validate, and inspect without a live
// session. `audit` clusters the account's log for rule tuning.

import { HOOK_NAME } from './adapter/constants.ts';
import { run, type RunOptions, type RunResult } from './adapter/run.ts';
import { parseAuditArgs, parseDoctorArgs, runAudit, runCheck, runDoctor, runRulesLint, runRulesList } from './cli-commands.ts';

// Reads stdin and runs it, with the read itself inside the same fail-open
// contract as a malformed envelope: an unreadable stdin (a broken pipe, a
// permissions error) must exit silently, never crash with a stack trace.
// Exported (and parameterized on the reader) so a test can simulate a
// throwing read without spawning a subprocess or fighting process.exit().
export async function readAndRun(readStdin: () => Promise<string>, options?: RunOptions): Promise<RunResult> {
  let raw: string;
  try {
    raw = await readStdin();
  } catch {
    return { stdout: null };
  }
  return run(raw, options);
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
    // Ticket 08: `bouncer run --shadow` — visible and greppable in the
    // settings.json command string that invokes it (no magic env var).
    // Belt-and-suspenders on the "never emits, absolute" contract: run()
    // itself already returns SILENT on every path once shadow is set (see
    // adapter/run.ts), but the write is ALSO gated here, at the outermost
    // boundary, so a future path inside run() that forgets to check
    // `shadow` still cannot leak to stdout — this line is what makes that
    // structurally impossible rather than merely tested.
    //
    // Any OTHER token (a typo like `--shadwo`) is deliberately NOT treated
    // as shadow — enforcement is the safe default, a mistyped flag must
    // never silently disarm it — but it's not silently dropped either:
    // run() logs it as a policy-warning so the mistake is visible in the
    // audit trail (see RunOptions's own comment in adapter/run.ts).
    const shadow = rest.includes('--shadow');
    const unrecognizedTokens = rest.filter((t) => t !== '--shadow');
    const { stdout } = await readAndRun(() => Bun.stdin.text(), { shadow, unrecognizedTokens });
    if (stdout !== null && !shadow) process.stdout.write(stdout);
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

  if (command === 'audit') {
    const parsed = parseAuditArgs(rest);
    if (parsed.error !== undefined) {
      console.error(`${HOOK_NAME}: ${parsed.error}`);
      process.exit(1);
    }
    const { text, ok } = await runAudit(parsed.options);
    console.log(text);
    process.exit(ok ? 0 : 1);
  }

  if (command === 'doctor') {
    const parsed = parseDoctorArgs(rest);
    if (parsed.error !== undefined) {
      console.error(`${HOOK_NAME}: ${parsed.error}`);
      process.exit(1);
    }
    const { text, ok } = await runDoctor(parsed.settingsPath);
    console.log(text);
    process.exit(ok ? 0 : 1);
  }

  usageError(command, 'run | check | rules | audit | doctor');
}

if (import.meta.main) {
  await main();
}
