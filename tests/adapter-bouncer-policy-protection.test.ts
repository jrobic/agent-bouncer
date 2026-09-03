// Ticket 19: the policy the binary RUNS ON (<configDir>/bouncer/policy.toml
// and <configDir>/bouncer/policy.d/, src/adapter/policy.ts's
// overlayPath/overlayDirPath) is now a baseline secret.path rule
// (bouncer-policy, verdict "confirm") — the disarmament counterpart of
// bouncer-audit-log (tests/adapter-bouncer-log-protection.test.ts), which
// this file is modeled on. Real `run()` dispatch, a REAL on-disk overlay
// under a throwaway, EXPLICITLY VERIFIED CLAUDE_CONFIG_DIR — same
// ticket-13 lesson: an unverified, accidentally-empty CLAUDE_CONFIG_DIR
// falls through to the real live ~/.claude.

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { run } from '../src/adapter/run.ts';
import { runRulesList } from '../src/cli-commands.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const cleanupDirs: string[] = [];

afterEach(async () => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function freshAccountDir(prefix = 'bouncer-policy-protection-'): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  cleanupDirs.push(dir);
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

describe('run(): Edit/Write/Read on the live policy overlay confirms, under a real custom CLAUDE_CONFIG_DIR', () => {
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

  test('Read via a symlink pointing AT the real policy.toml also asks (realpath resolution, not the literal path)', async () => {
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
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('the dotfiles mount layout (bouncer/policy.d itself a symlink to a shared bouncer/policy.d elsewhere) still asks — realpath resolves through the directory symlink too', async () => {
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    // The shared mount target ALSO carries a `bouncer/` segment in its own
    // real path (mirrors the actual dotfiles common mount) — this is
    // the case the rule is built to survive.
    const commonDir = await mkdtemp(join(tmpdir(), 'bouncer-common-'));
    cleanupDirs.push(commonDir);
    const sharedPolicyD = join(commonDir, 'bouncer', 'policy.d');
    await mkdir(sharedPolicyD, { recursive: true });
    await writeFile(join(sharedPolicyD, '10-shared.toml'), '# shared\n', 'utf8');
    await symlink(sharedPolicyD, join(accountDir, 'bouncer', 'policy.d'));

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: join(accountDir, 'bouncer', 'policy.d', '10-shared.toml') },
    });
    const { stdout } = await run(envelope);
    expect(askReason(stdout)).toContain('bouncer-policy');
  });

  test('DOCUMENTED LIMIT: a mount target with NO bouncer/ segment in its real path escapes the rule after realpath — allow', async () => {
    // The flip side of the case above: the LITERAL requested path still
    // reads "bouncer/policy.d/…", but canonicalizePath's realpath resolves
    // it onto a target directory whose real path never contains a
    // `bouncer/` segment (e.g. an adapter mounting its overlay directly
    // under a differently-named shared dotfiles root, with no `bouncer/`
    // path component of its own). The rule anchors on the literal segment
    // (see policy/secret.toml's bouncer-policy comment, point (a)) — an
    // adapter whose overlay resolves elsewhere must carry the protection
    // along itself; this test pins that this rule alone does not do it.
    const accountDir = await freshAccountDir();
    await mkdir(join(accountDir, 'bouncer'), { recursive: true });
    const noBouncerSegmentTarget = await mkdtemp(join(tmpdir(), 'shared-dotfiles-mount-'));
    cleanupDirs.push(noBouncerSegmentTarget);
    await writeFile(join(noBouncerSegmentTarget, '10-shared.toml'), '# shared\n', 'utf8');
    await symlink(noBouncerSegmentTarget, join(accountDir, 'bouncer', 'policy.d'));

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: join(accountDir, 'bouncer', 'policy.d', '10-shared.toml') },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();
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

  test('closed loop: once the disarming [[override]] is on disk (i.e. already approved by a human), the guard steps aside — Read passes AND rules list shows the override', async () => {
    // This test picks up AFTER the approval this file's own "Write ... asks"
    // case above proves: writing the override is intercepted; a human who
    // approves it anyway ends up with exactly the on-disk state this test
    // starts from (plain fs write, no run() involved — simulating the
    // human-approved write actually landing). This test deliberately
    // FLIPS the day a stronger "sealed rules" notion ships (see the
    // bouncer-policy comment in policy/secret.toml, point (b), and the
    // cascade idea in .scratch/backlog.md): today, an ordinary
    // override-able rule that neutralizes itself is expected behavior,
    // not a bug — this is the regression seam that will need a conscious
    // update, not a silent break, when sealed rules arrive.
    const accountDir = await freshAccountDir();
    const policyDFile = join(accountDir, 'bouncer', 'policy.d', '99-disarm.toml');
    await mkdir(dirname(policyDFile), { recursive: true });
    await writeFile(
      policyDFile,
      '[[override]]\nrule = "bouncer-policy"\naction = "disable"\nreason = "test: human-approved disarm already on disk"\n',
      'utf8',
    );
    // Sanity: the file is really there, not an artifact of a stale mock.
    expect(await readFile(policyDFile, 'utf8')).toContain('bouncer-policy');

    const envelope = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: policyDFile },
    });
    const { stdout } = await run(envelope);
    expect(stdout).toBeNull();

    const { text } = await runRulesList();
    expect(text).toContain('override disable bouncer-policy');
  });
});
