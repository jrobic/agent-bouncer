// `check`, `rules lint`, `rules list` — tested at the command-function
// level (src/cli-commands.ts), not by spawning the compiled binary: same
// discipline as tests/cli.test.ts for `run`.

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCheck, runPing, runRulesLint, runRulesList } from '../src/cli-commands.ts';
import type { CommandResult } from '../src/cli-commands.ts';

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

  test('an applied harness extension changes the persistent write boundary', async () => {
    const dir = await freshAccountDir();
    const command = 'echo x > ~/.claude-x/settings.json';

    await expect(runCheck(command)).resolves.toMatchObject({ text: 'allow' });
    await writeOverlay(
      dir,
      '[[harness]]\nid = "claude-code"\ndir = ["(^|/)\\\\.claude-x"]\nwitness = "~/.claude-x"\n',
    );

    await expect(runCheck(command)).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-harness-settings]'),
    });
    await expect(runRulesList()).resolves.toMatchObject({
      text: expect.stringContaining(
        'rule protected_write harness-settings baseline+overlay [profile:policy.toml] [harness:claude-code]',
      ),
    });
  });
  test('expands only the eligible fragments of a concatenated shell token', async () => {
    await freshAccountDir();

    await expect(runCheck('rm -rf "$CLAUDE_CONFIG_DIR"\'/hooks\'')).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-harness-hooks]'),
    });
    await expect(runCheck('rm -rf ~/.{claude,codex}\'/hooks\'')).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-harness-hooks]'),
    });
    await expect(runCheck('rm -rf \'$CLAUDE_CONFIG_DIR\'"/hooks"')).resolves.toMatchObject({ text: 'allow' });
    await expect(runCheck('rm -rf "$CLAUDE_CONFIG_DIR/hooks"')).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-harness-hooks]'),
    });
  });

  test('keeps literal syntax literal while expanding declared environment and brace fragments', async () => {
    await freshAccountDir();

    await expect(runCheck('rm -rf $CLAUDE_CONFIG_DIR')).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-claude-code-config-dir]'),
    });
    await expect(runCheck('rm -rf $CONFIG')).resolves.toMatchObject({ text: 'allow' });
    await expect(runCheck('rm -rf \'$CLAUDE_CONFIG_DIR\'')).resolves.toMatchObject({ text: 'allow' });
    await expect(runCheck('rm -rf \\$CLAUDE_CONFIG_DIR')).resolves.toMatchObject({ text: 'allow' });
    await expect(runCheck('rm -rf ~/.{claude,codex}')).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-claude-code-config-dir]'),
    });
    await expect(runCheck('rm -rf \'~/.{claude,codex}\'')).resolves.toMatchObject({ text: 'allow' });
    await expect(runCheck('rm -rf ~/.\\{claude,codex\\}')).resolves.toMatchObject({ text: 'allow' });
  });

  test.each([
    ['optional group', '(^|/)\\\\.group(-agent)?', '~/.group-agent', 'GROUP_AGENT_HOME'],
    ['alternation', '(^|/)\\\\.(alternate|variant)-agent', '~/.alternate-agent', 'ALTERNATE_AGENT_HOME'],
    ['character class', '(^|/)\\\\.numeric-[0-9]+', '~/.numeric-7', 'NUMERIC_AGENT_HOME'],
    ['absolute path', '^/var/lib/absolute-[0-9]+', '/var/lib/absolute-7', 'ABSOLUTE_AGENT_HOME'],
  ])('uses the derived rule matcher for a %s witness through runCheck', async (_kind, dir, witness, env) => {
    const accountDir = await freshAccountDir();
    await writeOverlay(
      accountDir,
      `[[harness]]\nid = "shape-agent"\ndir = ["${dir}"]\nwitness = "${witness}"\nenv = ["${env}"]\nreason = "Shape witness"\n\n[[harness.persistent]]\nid = "shape-settings"\npath = "config\\\\.json$"\nreason = "Shape settings"\n`,
    );

    await expect(runCheck(`echo x > $${env}/config.json`)).resolves.toMatchObject({
      text: expect.stringContaining('confirm [bash-shape-settings]'),
    });
  });

  // Review round 4 R4-1: `check` built its input bag with the LITERAL
  // key `command`, ignoring the row's own `command` selector — worked
  // only by coincidence for a row whose selector happened to be named
  // `command` (round 3's own test used exactly such a row, so it could
  // not see this). These three prove the fix places the dry-run string
  // at the row's OWN selector, whatever shape it is: a plain key
  // different from `command`, a selector containing a literal dot, and
  // a `[]` array selector — reproducing the review's own `mini`
  // scenario (`sh = { role = "command", command = "cmd" }`) plus the
  // two other selector shapes it asked for. A brand-new harness id must
  // be declared through the COMMON layer (never the profile alone — its
  // own profile root can't resolve until its declaration is known), so
  // each case manages its own throwaway HOME rather than reusing
  // freshAccountDir()'s CLAUDE_CONFIG_DIR-only setup.
  async function checkThroughCommandSelector(harnessId: string, toolsLine: string, command: string): Promise<CommandResult> {
    const ORIGINAL_HOME = process.env.HOME;
    const home = await mkdtemp(join(tmpdir(), 'bouncer-check-tool-row-'));
    cleanupDirs.push(home);
    await mkdir(join(home, '.agents', 'bouncer', 'harness.d'), { recursive: true });
    await writeFile(
      join(home, '.agents', 'bouncer', 'harness.d', `${harnessId}.toml`),
      `
      [[harness]]
      id = "${harnessId}"
      dir = ["(^|/)\\\\.${harnessId}"]
      witness = "~/.${harnessId}"
      env = ["${harnessId.toUpperCase()}_HOME"]
      reason = "test"

      [harness.protocol]
      transport = "stdin-json"

      [harness.protocol.input]
      event = "hook_event_name"
      tool = "tool_name"
      input = "tool_input"
      session = "session_id"
      cwd = "cwd"

      [harness.protocol.events]
      pre_tool = "PreToolUse"

      [harness.protocol.tools]
      ${toolsLine}

      [harness.protocol.output]
      block = "deny"
      confirm = "deny"
      observe = "silent"
      flag = "silent"
      on_malformed = "allow"

      [harness.protocol.output.deny]
      stdout = '{"decision":"deny"}'
      `,
      'utf8',
    );
    process.env.HOME = home;
    try {
      return await runCheck(command, harnessId);
    } finally {
      process.env.HOME = ORIGINAL_HOME;
    }
  }

  test('the review\'s own "mini" scenario: a plain selector different from "command" ("cmd")', async () => {
    const { text, ok } = await checkThroughCommandSelector('mini', 'sh = { role = "command", command = "cmd" }', 'rm -rf /');
    expect(ok).toBe(true);
    expect(text).toContain('block [rm-rf-dangerous]');
    expect(text).toContain('→ deny (mini)');
  });

  test('a selector containing a literal dot places the command at that exact flat key', async () => {
    const { text, ok } = await checkThroughCommandSelector(
      'dotty',
      'sh = { role = "command", command = "payload.cmd" }',
      'rm -rf /',
    );
    expect(ok).toBe(true);
    expect(text).toContain('block [rm-rf-dangerous]');
    expect(text).toContain('→ deny (dotty)');
  });

  test('a `[]` array selector wraps the command in a one-element array', async () => {
    const { text, ok } = await checkThroughCommandSelector(
      'batchy',
      'sh = { role = "command", command = "commands[].command" }',
      'rm -rf /',
    );
    expect(ok).toBe(true);
    expect(text).toContain('block [rm-rf-dangerous]');
    expect(text).toContain('→ deny (batchy)');
  });

  test('claude-code output is unchanged by the selector fix', async () => {
    await freshAccountDir();
    const { text } = await runCheck('rm -rf /');
    expect(text).toBe('block [rm-rf-dangerous] rm -rf targeting a dangerous path: / → deny (claude-code)');
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

  test('rejects a witness that only matches a directory prefix', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[harness]]\nid = "numeric-agent"\ndir = ["(^|/)\\\\.numeric-[0-9]+"]\nwitness = "~/.numeric-7oops"\nenv = ["NUMERIC_AGENT_HOME"]\nreason = "Numeric agent configuration"\n',
    );

    await expect(runRulesLint()).resolves.toMatchObject({
      ok: false,
      text: expect.stringContaining('declare witness'),
    });
  });
});

describe('runRulesList', () => {
  test('lists every baseline rule with provenance "baseline"', async () => {
    await freshAccountDir();
    const { text, ok } = await runRulesList();
    expect(ok).toBe(true);
    expect(text).toContain('rule command.bash mkfs baseline');
    expect(text).toContain('rule secret.path dotenv baseline');
    expect(text).toContain('rule protected_write claude-code-config-dir baseline [harness:claude-code]');
    expect(text).toMatch(/^summary: 99 rules, 0 overrides active/m);
  });

  test('lists a new overlay harness and its companion normal rule as overlay', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[harness]]\nid = "new-agent"\ndir = ["(^|/)\\\\.new-agent"]\nwitness = "~/.new-agent"\nenv = ["NEW_AGENT_HOME"]\nreason = "New agent configuration"\n\n[[harness.persistent]]\nid = "new-agent-settings"\npath = "settings\\\\.json$"\nreason = "New agent settings"\n\n[[rules.command.bash]]\nid = "new-agent-command"\nregex = "^new-agent-command"\nreason = "New agent command"\n',
    );

    await expect(runRulesList()).resolves.toMatchObject({
      text: expect.stringContaining(
        'rule protected_write new-agent-config-dir overlay [profile:policy.toml] [harness:new-agent]',
      ),
    });
    await expect(runRulesList()).resolves.toMatchObject({
      text: expect.stringContaining(
        'rule protected_write new-agent-settings overlay [profile:policy.toml] [harness:new-agent]',
      ),
    });
    await expect(runRulesList()).resolves.toMatchObject({
      text: expect.stringContaining('rule command.bash new-agent-command overlay [profile:policy.toml]'),
    });
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

  test('an overlay rule\'s provenance names its source file (ticket 12)', async () => {
    const dir = await freshAccountDir();
    await writeOverlay(
      dir,
      '[[rules.command.bash]]\nid = "block-npm-publish"\nregex = "npm publish"\nreason = "test"\n',
    );
    const { text } = await runRulesList();
    expect(text).toContain('rule command.bash block-npm-publish overlay [profile:policy.toml]');
  });

  test('a policy.d rule\'s provenance names its file, and an override/relax from policy.d does too', async () => {
    const dir = await freshAccountDir();
    await mkdir(join(dir, 'bouncer', 'policy.d'), { recursive: true });
    await writeFile(
      join(dir, 'bouncer', 'policy.d', '10-npm.toml'),
      '[[rules.command.bash]]\nid = "block-npm-publish"\nregex = "npm publish"\nreason = "test"\n\n'
        + '[[override]]\nrule = "mkfs"\naction = "disable"\nreason = "test"\n\n'
        + '[[relax]]\nlist = "command.git.safe_subcommands"\nvalue = "push"\nreason = "test"\n',
      'utf8',
    );
    const { text } = await runRulesList();
    // Layer-qualified (ticket 20, ADR-0001): loadCurrentPolicy() always
    // reads the account's overlay as the "profile" layer now.
    expect(text).toContain('rule command.bash block-npm-publish overlay [profile:policy.d/10-npm.toml]');
    expect(text).toContain('override disable mkfs — test [profile:policy.d/10-npm.toml]');
    expect(text).toContain('overlay-relax command.git.safe_subcommands push — test [profile:policy.d/10-npm.toml]');
  });
});

describe('runPing', () => {
  test('loads a healthy account policy silently', async () => {
    await freshAccountDir();
    await expect(runPing()).resolves.toEqual({ text: '', ok: true });
  });

  test('fails silently when the configured account root cannot be read', async () => {
    const dir = await freshAccountDir();
    const unreadableConfigRoot = join(dir, 'not-a-directory');
    await writeFile(unreadableConfigRoot, '', 'utf8');
    process.env.CLAUDE_CONFIG_DIR = unreadableConfigRoot;
    await expect(runPing()).resolves.toEqual({ text: '', ok: false });
  });

  test('keeps the embedded baseline runnable when the overlay is rejected', async () => {
    const accountDir = await freshAccountDir();
    await writeOverlay(accountDir, 'not valid toml {{{');
    await expect(runPing()).resolves.toEqual({ text: '', ok: true });
  });
});
