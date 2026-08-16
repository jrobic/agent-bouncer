import { afterEach, describe, expect, test } from 'bun:test';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { configDir, hookLogPath } from '../src/log-path.ts';

// Workstation delta: per-account log routing. The property under test is
// "two accounts, two logs" — CLAUDE_CONFIG_DIR is how a second account
// (a client seat running the same binary through an absolute path) tells
// the engine which tree its own state lives in. Without honoring it, a
// second account's denials would land in the primary account's log file.

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;

afterEach(() => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
});

describe('configDir: no override', () => {
  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is unset', () => {
    delete process.env.CLAUDE_CONFIG_DIR;
    expect(configDir()).toBe(resolve(homedir(), '.claude'));
  });

  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is empty', () => {
    process.env.CLAUDE_CONFIG_DIR = '';
    expect(configDir()).toBe(resolve(homedir(), '.claude'));
  });

  test('resolves to ~/.claude when CLAUDE_CONFIG_DIR is blank', () => {
    process.env.CLAUDE_CONFIG_DIR = '   ';
    expect(configDir()).toBe(resolve(homedir(), '.claude'));
  });
});

describe('configDir: CLAUDE_CONFIG_DIR override (second account / client seat)', () => {
  test('an absolute override is used verbatim (resolved)', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/client-seat/.claude-client';
    expect(configDir()).toBe(resolve('/tmp/client-seat/.claude-client'));
  });

  test('a trailing slash is normalized away', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/client-seat/.claude-client/';
    expect(configDir()).toBe(resolve('/tmp/client-seat/.claude-client'));
  });

  test('a leading ~ is expanded against the home directory', () => {
    process.env.CLAUDE_CONFIG_DIR = '~/.claude-work';
    expect(configDir()).toBe(resolve(homedir(), '.claude-work'));
  });

  test('bare ~ expands to the home directory itself', () => {
    process.env.CLAUDE_CONFIG_DIR = '~';
    expect(configDir()).toBe(resolve(homedir()));
  });

  test('a relative override resolves against the current working directory', () => {
    process.env.CLAUDE_CONFIG_DIR = 'relative-config-dir';
    expect(configDir()).toBe(resolve('relative-config-dir'));
  });
});

describe('hookLogPath: per-account routing', () => {
  test('nests under configDir()/logs/hooks/<hookName>.log', () => {
    delete process.env.CLAUDE_CONFIG_DIR;
    expect(hookLogPath('command-guard')).toBe(
      join(resolve(homedir(), '.claude'), 'logs', 'hooks', 'command-guard.log'),
    );
  });

  test('two accounts (two CLAUDE_CONFIG_DIR values) never share a log file for the same hook', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-a/.claude';
    const accountA = hookLogPath('command-guard');

    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-b/.claude';
    const accountB = hookLogPath('command-guard');

    expect(accountA).not.toBe(accountB);
    expect(accountA).toBe(resolve('/tmp/account-a/.claude', 'logs', 'hooks', 'command-guard.log'));
    expect(accountB).toBe(resolve('/tmp/account-b/.claude', 'logs', 'hooks', 'command-guard.log'));
  });

  test('different hook names never share a log file for the same account', () => {
    process.env.CLAUDE_CONFIG_DIR = '/tmp/account-a/.claude';
    expect(hookLogPath('command-guard')).not.toBe(hookLogPath('secret-guard'));
  });
});
