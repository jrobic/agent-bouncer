#!/usr/bin/env bun
// bouncer — single guard binary. `run` speaks a harness's declared
// protocol end to end (stdin JSON, verdict on stdout, silent exit on
// allow, default `claude-code` — ADR-0006) — this is also how SessionStart
// reaches `doctor`'s wiring/policy/log check (ticket 07): no separate
// subcommand for the hook path, the same `run` envelope dispatch routes
// SessionStart to it. `check`, `rules lint`, `rules list`, `doctor`, and
// `harness list` are the policy/diagnostic tooling subcommands — dry-run,
// validate, and inspect without a live session. `audit` clusters the
// account's log for rule tuning. `--harness <id>` (default `claude-code`)
// is accepted by `run`, `check`, `doctor`, and `audit`.

import { HOOK_NAME } from './adapter/constants.ts';
import { run, type RunOptions, type RunResult } from './adapter/run.ts';
import {
  extractHarnessFlag,
  parseAuditArgs,
  parseDoctorArgs,
  runAudit,
  runCheck,
  runDoctor,
  runHarnessList,
  runHarnessShim,
  runPing,
  runPrintCanary,
  runRulesLint,
  runRulesList,
} from './cli-commands.ts';

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
    const harnessFlag = extractHarnessFlag(rest);
    if (harnessFlag.error !== undefined) {
      console.error(`${HOOK_NAME}: ${harnessFlag.error}`);
      process.exit(1);
    }
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
    const shadow = harnessFlag.rest.includes('--shadow');
    const unrecognizedTokens = harnessFlag.rest.filter((t) => t !== '--shadow');
    const { stdout, exit } = await readAndRun(() => Bun.stdin.text(), {
      shadow,
      unrecognizedTokens,
      ...(harnessFlag.harness !== undefined ? { harness: harnessFlag.harness } : {}),
    });
    // ADR-0006 § 6: an unknown/protocol-less harness's exit 2 is a
    // wiring-configuration failure, not a verdict shadow ever suppresses
    // — it propagates even under --shadow (stdout stays gated on shadow
    // regardless, unaffected here since that path never sets stdout).
    if (stdout !== null && !shadow) process.stdout.write(stdout);
    process.exit(exit ?? 0);
  }

  if (command === 'ping') {
    const { ok } = await runPing();
    process.exit(ok ? 0 : 1);
  }

  if (command === 'check') {
    const harnessFlag = extractHarnessFlag(rest);
    if (harnessFlag.error !== undefined) {
      console.error(`${HOOK_NAME}: ${harnessFlag.error}`);
      process.exit(1);
    }
    const target = harnessFlag.rest.join(' ');
    if (target.trim() === '') {
      console.error(`${HOOK_NAME}: check requires a command argument, e.g. check "git push"`);
      process.exit(1);
    }
    const { text, ok } = await runCheck(target, harnessFlag.harness);
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

  if (command === 'harness') {
    const [sub, harnessId] = rest;
    if (sub === 'list') {
      const { text, ok } = await runHarnessList();
      console.log(text);
      process.exit(ok ? 0 : 1);
    }
    if (sub === 'shim') {
      if (harnessId === undefined) {
        console.error(`${HOOK_NAME}: harness shim requires an id argument, e.g. harness shim pi-agent`);
        process.exit(1);
      }
      const { text, ok } = runHarnessShim(harnessId);
      // Byte-exact on success (see runHarnessShim's own comment):
      // process.stdout.write, never console.log, so a shell redirect
      // (`> extensions/bouncer.ts`) never gains an extra trailing
      // newline `doctor`'s own drift check would then see as a
      // mismatch against every future re-render. The failure case has
      // no such contract — printed the same way as every other
      // subcommand's own usage/error text.
      if (ok) process.stdout.write(text);
      else console.log(text);
      process.exit(ok ? 0 : 1);
    }
    usageError(sub, 'list | shim <id>');
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
    if (parsed.printCanary) {
      const printed = await runPrintCanary(parsed.settingsPath, parsed.harness);
      if (!printed.ok) {
        console.error(`${HOOK_NAME}: ${printed.error}`);
        process.exit(1);
      }
      console.log(printed.text);
      process.exit(0);
    }
    const { text, ok } = await runDoctor(parsed.settingsPath, parsed.harness);
    console.log(text);
    process.exit(ok ? 0 : 1);
  }

  usageError(command, 'run | ping | check | rules | harness | audit | doctor');
}

if (import.meta.main) {
  await main();
}
