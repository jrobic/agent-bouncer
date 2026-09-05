import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BASELINE } from '../src/policy/baseline.ts';
import { createProtectedWriteChecker } from '../src/protected-write-rules.ts';

const cleanupDirs: string[] = [];
const checker = createProtectedWriteChecker(BASELINE.rules.protected_write);

afterEach(async () => {
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('protected-write rules: baseline rows', () => {
  test('ruleId harness-settings: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.claude/settings.json')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'harness-settings' });
  });

  test('ruleId harness-hooks: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.claude/hooks/hook.sh')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'harness-hooks' });
  });

  test('ruleId harness-plugins: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.claude/plugins/plugin/entry.ts')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'harness-plugins',
    });
  });

  test('ruleId harness-instructions: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.claude/CLAUDE.md')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'harness-instructions' });
  });

  test('ruleId harness-global-config: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.claude-work.json')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'harness-global-config' });
  });

  test('ruleId project-mcp-config: protected paths confirm on write', async () => {
    await expect(checker.checkPath('/repo/.mcp.json')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'project-mcp-config' });
  });

  test('ruleId launch-agents: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/Library/LaunchAgents/com.example.agent.plist')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'launch-agents',
    });
  });

  test('ruleId user-systemd-units: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.config/systemd/user/example.service')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'user-systemd-units',
    });
  });

  test('ruleId shell-rc: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.config/fish/config.fish')).resolves.toMatchObject({ verdict: 'confirm', ruleId: 'shell-rc' });
  });

  test('ruleId bouncer-policy: protected paths confirm on write', async () => {
    await expect(checker.checkPath('~/.agents/bouncer/policy.d/100-personal.toml')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'bouncer-policy',
    });
  });
});

test('bouncer-policy keeps exact policy boundaries after its family migration', async () => {
  await expect(checker.checkPath('/custom/config/bouncer/policy.toml')).resolves.toMatchObject({
    verdict: 'confirm',
    ruleId: 'bouncer-policy',
  });
  await expect(checker.checkPath('/custom/config/bouncer/policy.d/10-personal.toml')).resolves.toMatchObject({
    verdict: 'confirm',
    ruleId: 'bouncer-policy',
  });
  await expect(checker.checkPath('/custom/config/bouncer/policy.toml.bak')).resolves.toBeNull();
  await expect(checker.checkPath('/custom/config/bouncer/policy.d.pre-mount.bak/10-personal.toml')).resolves.toBeNull();
});

describe('protected-write rules: Bash mechanisms', () => {
  test('structural write targets confirm while cp source operands remain reads', async () => {
    await expect(checker.checkBashWrites('cp source ~/.claude/settings.json')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-harness-settings',
    });
    await expect(checker.checkBashWrites('cp ~/.claude/settings.json /tmp/settings.json')).resolves.toBeNull();
    await expect(checker.checkBashWrites('echo x >> ~/.zshrc')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-shell-rc',
    });
    await expect(checker.checkBashWrites('tee /tmp/out < ~/.zshrc')).resolves.toBeNull();
  });

  test('fallback confirms unknown writers but permits known readers', async () => {
    await expect(checker.checkBashWrites('yq -i \'.theme = "dark"\' ~/.claude/settings.json')).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-harness-settings',
    });
    await expect(checker.checkBashWrites('git diff ~/.zshrc')).resolves.toBeNull();
  });

  test('fallback reasons name the unrecognized command head', async () => {
    const probes = [
      ['yq', 'yq -i \'.x = "y"\' ~/.zshrc'],
      ['code', 'code ~/.zshrc'],
      ['vim', 'vim ~/.zshrc'],
      ['./script.sh', './script.sh ~/.zshrc'],
    ] as const;
    const reasons = await Promise.all(probes.map(async ([head, command]) => ({
      head,
      reason: (await checker.checkBashWrites(command))?.reason,
    })));
    for (const { head, reason } of reasons) {
      expect(reason).toContain(`unrecognized write form (${head})`);
    }
  });
});

describe('protected-write rules: redirection-aware operands', () => {
  test('last-operand writers retain protected destinations before output redirects', async () => {
    const commands = [
      'cp /tmp/x ~/.zshrc 2>/dev/null',
      'cp /tmp/x ~/.zshrc > /dev/null',
      'install -m 755 /tmp/x ~/.claude/hooks/h.sh 2>/dev/null',
      'ln -sf /tmp/evil ~/.zshrc >/dev/null',
      'rsync -a /tmp/x ~/.zshrc > log.txt',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
  });

  test('quoted targets attached to an output operator are structural targets', async () => {
    const commands = [
      'echo x >"/Users/u/.zshrc"',
      'echo x >\'/Users/u/.zshrc\'',
      'echo x >>"/Users/u/.claude/settings.json"',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await expect(checker.checkBashWrites('echo "a>"|cat')).resolves.toBeNull();
  });

  test('short writer options consume attached target and output arguments', async () => {
    const commands = [
      'cp -t~/.claude/hooks evil',
      'install -t~/Library/LaunchAgents x.plist',
      'install -Dt~/Library/LaunchAgents x.plist',
      'ln -t~/.claude/hooks evil.sh',
      'mv -t~/.claude/hooks evil.sh',
      'cp -vt~/.claude/hooks evil',
      'patch -o~/.zshrc d.diff',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await expect(checker.checkBashWrites('cp -tv ~/.claude/hooks x')).resolves.toBeNull();
  });

  test('writer options do not become destination operands', async () => {
    const commands = [
      'cp /tmp/evil ~/.zshrc -S .bak',
      'install /tmp/evil ~/.claude/hooks/h.sh -m 755',
      'ln -s /tmp/evil ~/.zshrc -S .bak',
      'cp /tmp/evil ~/.zshrc -Z ctx',
      'cp /tmp/x ~/.zshrc -v',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await expect(checker.checkBashWrites('cp ~/.claude/settings.json /tmp/')).resolves.toBeNull();
  });

  test('positional directory destinations include each source basename without a slash heuristic', async () => {
    const commands = [
      'cp evil.plist ~/Library/LaunchAgents/',
      'install -m 644 evil.plist ~/Library/LaunchAgents/',
      'rsync evil.plist ~/Library/LaunchAgents/',
      'cp settings.json ~/.claude/',
      'mv CLAUDE.md ~/.claude/',
      'cp evil.plist ~/Library/LaunchAgents',
      'cp ~/.zshrc /tmp/',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await Promise.all([
      expect(checker.checkBashWrites('cp ~/.claude/settings.json /tmp/')).resolves.toBeNull(),
      expect(checker.checkBashWrites('cp a b /tmp/')).resolves.toBeNull(),
    ]);
  });

  test('quoted operands attached to output redirects remain writer operands', async () => {
    const commands = [
      'rm "~/.claude/settings.json">/tmp/x',
      'rm \'~/.claude/settings.json\'>/tmp/x',
      'cp evil "~/.zshrc">/tmp/x',
      'echo x>/Users/u/".zshrc"',
      'echo x>~/".zshrc"',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await Promise.all([
      expect(checker.checkBashWrites('echo "a>"|cat')).resolves.toBeNull(),
      expect(checker.checkBashWrites('echo \'a\'>/tmp/x')).resolves.toBeNull(),
    ]);
  });

  test('sed and dd retain protected operands before attached output redirects', async () => {
    const commands = [
      'sed -i /Users/u/.zshrc>/tmp/x',
      'sed -i "/Users/u/.zshrc">/tmp/x',
      'dd if=x of=/Users/u/.zshrc>/tmp/y',
      'dd if=x of="/Users/u/.zshrc">/tmp/y',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
  });

  test('output operators attached to a preceding word remain structural targets', async () => {
    const commands = [
      'echo x>/Users/u/.zshrc',
      'echo x>>/Users/u/.claude/settings.json',
      'cat a>/Users/u/.zshrc',
      'echo x>"/Users/u/.zshrc"',
      'echo x 2>| ~/.zshrc',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await Promise.all([
      expect(checker.checkBashWrites('echo "a>"|cat')).resolves.toBeNull(),
      expect(checker.checkBashWrites('cmd 2>&1 | tee /tmp/log')).resolves.toBeNull(),
      expect(checker.checkBashWrites('echo x >&2')).resolves.toBeNull(),
    ]);
  });

  test('quoted words before output operators keep their protected targets', async () => {
    const commands = [
      'echo "export PATH=/x">>/Users/u/.zshrc',
      'echo "hi">/Users/u/.claude/settings.json',
      'printf "%s" "x">>/Users/u/.zshrc',
      'cat "in.txt">/Users/u/.zshrc',
    ];
    await Promise.all(commands.map((command) => expect(checker.checkBashWrites(command)).resolves.toMatchObject({ verdict: 'confirm' })));
    await Promise.all([
      expect(checker.checkBashWrites('echo \'a\'>/tmp/x')).resolves.toBeNull(),
      expect(checker.checkBashWrites('echo \'a>b\' /tmp/x')).resolves.toBeNull(),
    ]);
  });
});

describe('protected-write rules: two path readings', () => {
  test('the raw symlink path wins when its resolved target is unprotected', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-protected-write-test-'));
    cleanupDirs.push(dir);
    const targetDir = join(dir, 'ordinary');
    const targetFile = join(targetDir, 'settings.json');
    const visibleDir = join(dir, '.claude');
    await mkdir(targetDir);
    await writeFile(targetFile, '{}', 'utf8');
    await symlink(targetDir, visibleDir);

    await expect(checker.checkPath(join(visibleDir, 'settings.json'))).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'harness-settings',
    });
  });

  test('the canonical path wins when an innocent symlink targets protected settings', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'bouncer-protected-write-test-'));
    cleanupDirs.push(dir);
    const protectedDir = join(dir, '.claude');
    const protectedFile = join(protectedDir, 'settings.json');
    const innocentFile = join(dir, 'innocent.json');
    await mkdir(protectedDir);
    await writeFile(protectedFile, '{}', 'utf8');
    await symlink(protectedFile, innocentFile);

    await expect(checker.checkPath(innocentFile)).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'harness-settings',
    });
    await expect(checker.checkBashWrites(`echo x > ${innocentFile}`)).resolves.toMatchObject({
      verdict: 'confirm',
      ruleId: 'bash-harness-settings',
    });
  });
});
