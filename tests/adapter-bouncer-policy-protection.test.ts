// The policy the binary runs on (<configDir>/bouncer/policy.toml and
// <configDir>/bouncer/policy.d/) is a protected-write baseline row. Writes
// require confirmation while ordinary reads remain free. Real `run()`
// dispatches against a throwaway, explicitly verified CLAUDE_CONFIG_DIR so
// no test can fall through to the live ~/.claude.

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { run } from '../src/adapter/run.ts';
import { runRulesList } from '../src/cli-commands.ts';
import { tmpDir } from './tmp.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;

afterEach(() => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
});

async function freshAccountDir(prefix = 'bouncer-policy-protection-'): Promise<string> {
  const dir = tmpDir(prefix);
  // The ticket-13 lesson: assert before use, never trust an unverified var.
  process.env.CLAUDE_CONFIG_DIR = dir;
  if (!process.env.CLAUDE_CONFIG_DIR || process.env.CLAUDE_CONFIG_DIR.trim() === '') {
    throw new Error('CLAUDE_CONFIG_DIR failed to set — refusing to proceed (would fall through to live ~/.claude)');
  }
  return dir;
}

function askReason(stdout: string | null): string {
  expect(stdout).not.toBeNull();
  const parsed = JSON.parse(stdout!);
  expect(parsed.hookSpecificOutput.permissionDecision).toBe('ask');
  return parsed.hookSpecificOutput.permissionDecisionReason as string;
}

describe('run(): protected bouncer policy writes confirm while reads remain free', () => {
  test('Edit on a policy.d file asks, naming bouncer-policy', async () => {
    const accountDir = await freshAccountDir();
    const policyDFile = join(accountDir, 'bouncer', 'policy.d', '10-personal.toml');
    await mkdir(dirname(policyDFile), { recursive: true });
    await writeFile(policyDFile, '[[relax]]\nlist = "mcp_write.read_prefixes"\nvalue = "peek"\nreason = "test"\n', 'utf8');

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Edit',
      tool_input: { file_path: policyDFile, old_string: 'peek', new_string: 'browse' },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('Write CREATING a new policy.d file carrying an [[override]] on bouncer-policy itself asks — the self-neutralization loop is intercepted before it lands', async () => {
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer', 'policy.d'), { recursive: true });
    const disarmFile = join(accountDir, 'bouncer', 'policy.d', '99-disarm.toml');

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Write',
      tool_input: {
        file_path: disarmFile,
        content: '[[override]]\nrule = "bouncer-policy"\naction = "disable"\nreason = "disarm"\n',
      },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('Read through a symlink to the real policy.toml stays free', async () => {
    const accountDir = await freshAccountDir();
    const realPolicyFile = join(accountDir, 'bouncer', 'policy.toml');
    await mkdir(dirname(realPolicyFile), { recursive: true });
    await writeFile(realPolicyFile, '# empty overlay\n', 'utf8');
    const innocentLink = join(accountDir, 'innocent.toml');
    await symlink(realPolicyFile, innocentLink);

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: innocentLink },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();
  });

  test('Edit through a bouncer/policy.d mount asks', async () => {
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    const commonDir = tmpDir('bouncer-common-');
    const sharedPolicyD = join(commonDir, 'bouncer', 'policy.d');
    await mkdir(sharedPolicyD, { recursive: true });
    const mountedPolicyFile = join(sharedPolicyD, '10-shared.toml');
    await writeFile(mountedPolicyFile, '# shared\n', 'utf8');
    await symlink(sharedPolicyD, join(accountDir, 'bouncer', 'policy.d'));

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Edit',
      tool_input: {
        file_path: join(accountDir, 'bouncer', 'policy.d', '10-shared.toml'),
        old_string: '# shared',
        new_string: '# changed',
      },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('Edit through a mount with no bouncer target segment still asks from the raw path', async () => {
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    const noBouncerSegmentTarget = tmpDir('shared-common-mount-');
    const mountedPolicyFile = join(noBouncerSegmentTarget, '10-shared.toml');
    await writeFile(mountedPolicyFile, '# shared\n', 'utf8');
    await symlink(noBouncerSegmentTarget, join(accountDir, 'bouncer', 'policy.d'));

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Edit',
      tool_input: {
        file_path: join(accountDir, 'bouncer', 'policy.d', '10-shared.toml'),
        old_string: '# shared',
        new_string: '# changed',
      },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('Bash: appending to the root overlay with printf asks, ruleId bash-bouncer-policy', async () => {
    const accountDir = await freshAccountDir();
    const overlayFile = join(accountDir, 'bouncer', 'policy.toml');
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: `printf '[[override]]\\n' >> ${overlayFile}` },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bash-bouncer-policy');
  });

  test('negative: reading THIS repository\'s own policy/secret.toml (real path, no bouncer/ segment) is not touched', async () => {
    await freshAccountDir();
    const repoSecretToml = join(dirname(import.meta.dir), 'policy', 'secret.toml');
    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: repoSecretToml },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();
  });

  test('sanctioned path: runRulesList() reads the overlay directly (node:fs), never through the PreToolUse guard at all', async () => {
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    await writeFile(join(accountDir, 'bouncer', 'policy.toml'), '# no overlay content\n', 'utf8');

    // No dispatch/run() call here at all — runRulesList (src/cli-commands.ts)
    // calls loadCurrentPolicy() straight through, the same sanctioned path
    // runAudit uses for the audit log (tests/adapter-bouncer-log-protection.test.ts).
    const { ok, text } = await runRulesList();
    expect(ok).toBe(true);
    expect(text).toContain('summary:');
    // bouncer-policy itself is a live baseline rule and shows up in the listing.
    expect(text).toContain('bouncer-policy');
  });

  test('closed loop: an approved override disables later policy edits and remains listed', async () => {
    const accountDir = await freshAccountDir();
    const policyDFile = join(accountDir, 'bouncer', 'policy.d', '99-disarm.toml');
    await mkdir(dirname(policyDFile), { recursive: true });
    await writeFile(
      policyDFile,
      '[[override]]\nrule = "bouncer-policy"\naction = "disable"\nreason = "test: human-approved disarm already on disk"\n',
      'utf8',
    );
    expect(await readFile(policyDFile, 'utf8')).toContain('bouncer-policy');

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Edit',
      tool_input: { file_path: policyDFile, old_string: 'disarm', new_string: 'approved' },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();

    const { text } = await runRulesList();
    expect(text).toContain('override disable bouncer-policy');
  });
});
