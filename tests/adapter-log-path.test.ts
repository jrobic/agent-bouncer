import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { configDirFor, hookLogPathFor } from '../src/adapter/log-path.ts';
import { loadCurrentPolicy } from '../src/adapter/policy.ts';
import { run } from '../src/adapter/run.ts';
import { BASELINE } from '../src/policy/baseline.ts';

// Workstation delta: per-account log routing. The property under test is
// "two accounts, two logs" — CLAUDE_CONFIG_DIR is how a second account
// (a client seat running the same binary through an absolute path) tells
// the engine which tree its own state lives in. Without honoring it, a
// second account's denials would land in the primary account's log file.
//
// Exercises the embedded claude-code baseline declaration directly
// (env = ["CLAUDE_CONFIG_DIR"], witness = "~/.claude") through the
// generic, declaration-driven configDirFor/hookLogPathFor (ADR-0006 § 8)
// — Claude Code's OWN routing is unchanged, only the function names and
// their harness-declaration parameter are new.

const CLAUDE_CODE_HARNESS = BASELINE.rules.harness.find((h) => h.id === 'claude-code')!;
const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;

afterEach(() => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
});

describe('configDirFor(claude-code): no override', () => {
  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is unset', () => {
    delete process.env.CLAUDE_CONFIG_DIR;
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve(homedir(), '.claude'));
  });

  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is empty', () => {
    process.env.CLAUDE_CONFIG_DIR = '';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve(homedir(), '.claude'));
  });

  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is blank', () => {
    process.env.CLAUDE_CONFIG_DIR = '   ';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve(homedir(), '.claude'));
  });
});

describe('configDirFor(claude-code): CLAUDE_CONFIG_DIR override (second account / client seat)', () => {
  test('an absolute override is used verbatim (resolved)', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/client-seat/.claude-client';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve('/tmp/client-seat/.claude-client'));
  });

  test('a trailing slash is normalized away', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/client-seat/.claude-client/';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve('/tmp/client-seat/.claude-client'));
  });

  test('a leading ~ is expanded against the home directory', () => {
    process.env.CLAUDE_CONFIG_DIR = '~/.claude-work';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve(homedir(), '.claude-work'));
  });

  test('bare ~ expands to the home directory itself', () => {
    process.env.CLAUDE_CONFIG_DIR = '~';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve(homedir()));
  });

  test('a relative override resolves against the current working directory', () => {
    process.env.CLAUDE_CONFIG_DIR = 'relative-config-dir';
    expect(configDirFor(CLAUDE_CODE_HARNESS)).toBe(resolve('relative-config-dir'));
  });
});

describe('hookLogPathFor(claude-code): per-account routing', () => {
  test('nests under configDirFor()/logs/hooks/<hookName>.log', () => {
    delete process.env.CLAUDE_CONFIG_DIR;
    expect(hookLogPathFor(CLAUDE_CODE_HARNESS, 'command-guard')).toBe(
      join(resolve(homedir(), '.claude'), 'logs', 'hooks', 'command-guard.log'),
    );
  });

  test('two accounts (two CLAUDE_CONFIG_DIR values) never share a log file for the same hook', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-a/.claude';
    const accountA = hookLogPathFor(CLAUDE_CODE_HARNESS, 'command-guard');

    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-b/.claude';
    const accountB = hookLogPathFor(CLAUDE_CODE_HARNESS, 'command-guard');

    expect(accountA).not.toBe(accountB);
    expect(accountA).toBe(resolve('/tmp/account-a/.claude', 'logs', 'hooks', 'command-guard.log'));
    expect(accountB).toBe(resolve('/tmp/account-b/.claude', 'logs', 'hooks', 'command-guard.log'));
  });

  test('different hook names never share a log file for the same account', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-a/.claude';
    expect(hookLogPathFor(CLAUDE_CODE_HARNESS, 'command-guard')).not.toBe(hookLogPathFor(CLAUDE_CODE_HARNESS, 'secret-guard'));
  });
});

describe('ADR-0006 § 8: declaration-driven routing — Codex, via a test overlay protocol', () => {
  test('the log lands under $CODEX_HOME/logs/hooks/bouncer.log and the profile layer is read from $CODEX_HOME/bouncer/', async () => {
    const home = mkdtempSync(join(tmpdir(), 'bouncer-codex-routing-home-'));
    const codexHome = mkdtempSync(join(tmpdir(), 'bouncer-codex-routing-codexhome-'));
    const commonHarnessDir = join(home, '.agents', 'bouncer', 'harness.d');
    mkdirSync(commonHarnessDir, { recursive: true });
    // Extends the BASELINE codex declaration (dir/env/witness/protocol
    // already declared as of 15b) with a protocol-only addition — a
    // minimal stdin-json table reusing claude-code's own envelope shape,
    // proving nothing about codex's REAL wiring (codex-hooks, 15b's own
    // codex.toml), only that routing follows the declaration once one
    // exists. `confirm = "deny"` (not "ask"): the real baseline codex
    // protocol is `confirm = "deny"` (ADR-0006 § 4 rule 6, fact 3 for
    // Codex — a baseline "deny" is a measured fact an overlay may not
    // relax to "ask"), so this test overlay must agree or its own
    // `[[harness]]` block gets rejected as a unit by that rule, exactly
    // as any other confirm=ask overlay on codex now would; no
    // `[harness.protocol.output.ask]` table either, which would be a
    // dead template once nothing maps to "ask".
    writeFileSync(
      join(commonHarnessDir, 'codex.toml'),
      [
        '[[harness]]',
        'id = "codex"',
        'env = ["CODEX_HOME"]',
        '',
        '[harness.protocol]',
        'transport = "stdin-json"',
        '',
        '[harness.protocol.input]',
        'event = "hook_event_name"',
        'tool = "tool_name"',
        'input = "tool_input"',
        'session = "session_id"',
        'prompt = "prompt"',
        'cwd = "cwd"',
        '',
        '[harness.protocol.events]',
        'pre_tool = "PreToolUse"',
        'prompt = "UserPromptSubmit"',
        'session_start = "SessionStart"',
        '',
        '[harness.protocol.tools]',
        'Bash = { role = "command", command = "command" }',
        '',
        '[harness.protocol.output]',
        'block = "deny"',
        'confirm = "deny"',
        'observe = "silent"',
        'flag = "context"',
        'on_malformed = "allow"',
        '',
        '[harness.protocol.output.deny]',
        'stdout = \'{"decision":"deny","reason":${reason}}\'',
        '[harness.protocol.output.context]',
        'stdout = \'{"context":${context}}\'',
        '[harness.protocol.output.session_start]',
        'stdout = \'{"context":${context}}\'',
        '',
      ].join('\n'),
      'utf8',
    );

    const originalHome = process.env.HOME;
    const originalCodexHome = process.env.CODEX_HOME;
    const originalConfigDir = process.env.CLAUDE_CONFIG_DIR;
    process.env.HOME = home;
    process.env.CODEX_HOME = codexHome;
    delete process.env.CLAUDE_CONFIG_DIR;
    try {
      const envelope = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
      const result = await run(envelope, { harness: 'codex' });
      expect(result.stdout).not.toBeNull();
      expect(JSON.parse(result.stdout!)).toEqual({ decision: 'deny', reason: 'rm-rf-dangerous: rm -rf targeting a dangerous path: /' });

      const logPath = join(codexHome, 'logs', 'hooks', 'bouncer.log');
      const logLine = JSON.parse(readFileSync(logPath, 'utf8').trim().split('\n')[0]!);
      expect(logLine.harness).toBe('codex');

      // The profile layer is read from $CODEX_HOME/bouncer/ — proven
      // directly against loadCurrentPolicy's own layer report (an
      // `[[override]]` on `rm-rf-dangerous` cannot prove this: that
      // ruleId is a hardcoded structural check in command-rules.ts, not
      // a resolvable regex-table row — orthogonal to this ticket).
      const codexProfileDir = join(codexHome, 'bouncer');
      mkdirSync(codexProfileDir, { recursive: true });
      writeFileSync(
        join(codexProfileDir, 'policy.toml'),
        '[[rules.command.bash]]\nid = "codex-profile-test-rule"\nregex = "codex-profile-trigger"\nreason = "codex profile test rule"\n',
        'utf8',
      );
      const loaded = await loadCurrentPolicy('codex');
      expect(loaded.layers.find((l) => l.name === 'profile')?.root).toBe(codexProfileDir);
      expect(loaded.policy.command.bash.map((r) => r.id)).toContain('codex-profile-test-rule');
    } finally {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
      if (originalCodexHome === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = originalCodexHome;
      if (originalConfigDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = originalConfigDir;
    }
  });

  test('Claude Code routing is unchanged by the presence of a codex declaration', async () => {
    const home = mkdtempSync(join(tmpdir(), 'bouncer-cc-unchanged-home-'));
    const claudeConfigDir = mkdtempSync(join(tmpdir(), 'bouncer-cc-unchanged-config-'));
    const originalHome = process.env.HOME;
    const originalConfigDir = process.env.CLAUDE_CONFIG_DIR;
    process.env.HOME = home;
    process.env.CLAUDE_CONFIG_DIR = claudeConfigDir;
    try {
      const envelope = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
      const result = await run(envelope);
      expect(JSON.parse(result.stdout!).hookSpecificOutput.permissionDecision).toBe('deny');
      const logPath = join(claudeConfigDir, 'logs', 'hooks', 'bouncer.log');
      expect(readFileSync(logPath, 'utf8').trim().length).toBeGreaterThan(0);
    } finally {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
      if (originalConfigDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
      else process.env.CLAUDE_CONFIG_DIR = originalConfigDir;
    }
  });
});
