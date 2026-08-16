// `check`, `rules lint`, `rules list` — tested at the command-function
// level (src/cli-commands.ts), not by spawning the compiled binary: same
// discipline as tests/cli.test.ts for `run`.

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCheck, runRulesLint, runRulesList } from '../src/cli-commands.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function freshAccountDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-cli-test-'));
  cleanupDirs.push(dir);
  process.env.CLAUDE_CONFIG_DIR = dir;
  return dir;
}

async function writeOverlay(accountDir: string, text: string): Promise<void> {
  await mkdir(join(accountDir, 'bouncer'), { recursive: true });
  await writeFile(join(accountDir, 'bouncer', 'policy.toml'), text, 'utf8');
}

describe('runCheck: dry-runs a command without a session', () => {
  test('a protected git command reproduces the live confirm verdict with its rule id', async () => {
    await freshAccountDir();
    const { text, ok } = await runCheck('git push');
    expect(ok).toBe(true);
    expect(text).toContain('confirm');
    expect(text).toContain('git-protected');
  });

  test('a destructive command reproduces the live block verdict', async () => {
    await freshAccountDir();
    const { text } = await runCheck('rm -rf /');
    expect(text).toContain('block');
    expect(text).toContain('rm-rf-dangerous');
  });

  test('a clean command reports allow', async () => {
    await freshAccountDir();
    const { text } = await runCheck('ls -la');
    expect(text.trim()).toBe('allow');
  });
});

describe('runRulesLint', () => {
  test('no overlay present: OK, baseline only', async () => {
    await freshAccountDir();
    const { text, ok } = await runRulesLint();
    expect(ok).toBe(true);
    expect(text).toContain('OK');
    expect(text).toContain('baseline only');
  });

  test('a valid overlay: OK', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = "test reason"\n',
    );
    const { text, ok } = await runRulesLint();
    expect(ok).toBe(true);
    expect(text).toContain('OK');
  });

  test('a lookaround regex fails lint', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[rules.command.bash]]\nid = "bad"\nregex = "foo(?=bar)"\nreason = "should never load"\n',
    );
    const { text, ok } = await runRulesLint();
    expect(ok).toBe(false);
    expect(text).toContain('FAILED');
    expect(text).toContain('lookaround');
  });

  test('an override with an empty reason fails lint', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(dir, '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = ""\n');
    const { ok } = await runRulesLint();
    expect(ok).toBe(false);
  });
});

describe('runRulesList', () => {
  test('lists every baseline rule with provenance "baseline"', async () => {
    await freshAccountDir();
    const { text, ok } = await runRulesList();
    expect(ok).toBe(true);
    expect(text).toContain('rule command.bash mkfs baseline');
    expect(text).toContain('rule secret.path dotenv baseline');
    expect(text).toMatch(/^summary: \d+ rules, 0 overrides active/m);
  });

  test('an active override is visible with its provenance and reason, counted in the summary', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = "not relevant to our sandbox"\n',
    );
    const { text } = await runRulesList();
    expect(text).toMatch(/^summary: \d+ rules, 1 overrides active/m);
    expect(text).toContain('override disable mkfs — not relevant to our sandbox');
    // The disabled rule itself no longer appears in the effective list.
    expect(text).not.toContain('rule command.bash mkfs baseline');
  });

  test('a broken overlay is reported via a warning line, baseline rules still listed', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(dir, 'not valid toml {{{');
    const { text } = await runRulesList();
    expect(text).toContain('warning:');
    expect(text).toContain('rule command.bash mkfs baseline');
  });
});
