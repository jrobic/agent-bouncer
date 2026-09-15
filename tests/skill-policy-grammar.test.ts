import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SKILL_PATH = new URL('../skills/bouncer-policy/SKILL.md', import.meta.url);

// Keep this table aligned with docs/reference/cli.md. The forms below cover
// only commands the policy skill is allowed to cite; placeholders are wildcards.
const CLI_GRAMMAR: readonly RegExp[] = [
  /^--version(?: --json)?$/,
  /^skill <id>(?: > <path>)?$/,
  /^check(?: --harness <id>)? "<command>"$/,
  /^run --harness <id> < envelope\.json$/,
  /^rules (?:lint|list)$/,
  /^audit(?: --days <n>)?(?: --sessions-only)?(?: --suggest)?(?: --harness <id>)?$/,
  /^doctor --harness <id>$/,
];

function inlineCommands(source: string): readonly string[] {
  return [...source.matchAll(/`[^`\n]*\b(bouncer [^`\n]+)`/g)].map((match) => match[1]!);
}

function fencedCommands(source: string): readonly string[] {
  const blocks: string[] = [];
  let activeBlock: string[] | undefined;

  for (const line of source.split('\n')) {
    if (activeBlock !== undefined && /^\s*```\s*$/.test(line)) {
      blocks.push(activeBlock.join('\n'));
      activeBlock = undefined;
    } else if (activeBlock === undefined && /^\s*```(?:sh|text)?\s*$/.test(line)) {
      activeBlock = [];
    } else {
      activeBlock?.push(line);
    }
  }

  return blocks.flatMap((block) => {
    const commands: string[] = [];
    let commandParts: string[] | undefined;

    for (const rawLine of block.split('\n')) {
      const line = rawLine.trimStart().replace(/^\$\s?/, '');
      if (commandParts === undefined && !line.startsWith('bouncer ')) continue;

      const continues = line.trimEnd().endsWith('\\');
      const part = continues ? line.trimEnd().slice(0, -1).trimEnd() : line.trim();
      commandParts ??= [];
      commandParts.push(part);

      if (!continues) {
        commands.push(commandParts.join(' '));
        commandParts = undefined;
      }
    }

    return commands;
  });
}

function citedCommands(source: string): readonly string[] {
  return [...new Set([...inlineCommands(source), ...fencedCommands(source)])];
}

function grammarForm(command: string): string {
  return command
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/^bouncer /, '')
    .replace(/\s>\s[^ ]+$/, ' > <path>')
    .replace(/^skill \S+/, 'skill <id>')
    .replace(/--harness \S+/, '--harness <id>')
    .replace(/--days \d+/, '--days <n>')
    .replace(/"[^"]*"/, '"<command>"')
    .replace(/< [^ ]+$/, '< envelope.json');
}

function invalidCommands(source: string): readonly string[] {
  return citedCommands(source).filter((command) => !CLI_GRAMMAR.some((pattern) => pattern.test(grammarForm(command))));
}

test('every inline or shell-fenced bouncer command in the policy skill matches the documented CLI grammar', async () => {
  expect(invalidCommands(await readFile(SKILL_PATH, 'utf8'))).toEqual([]);
});

test.each([
  ['prompted shell command', 'sh', '$ bouncer audit --sugest', 'bouncer audit --sugest'],
  ['indented text command', 'text', '  bouncer audit --sugest', 'bouncer audit --sugest'],
  [
    'continued command',
    '',
    'bouncer audit \\\n  --sessions-only \\\n  --sugest',
    'bouncer audit --sessions-only --sugest',
  ],
  ['unknown flag after wildcard', 'sh', 'bouncer audit --harness x --sugest', 'bouncer audit --harness x --sugest'],
])('detects a %s in a disposable skill copy', async (_caseName, language, command, expected) => {
  const directory = await mkdtemp(join(tmpdir(), 'bouncer-policy-'));
  const copiedSkill = join(directory, 'SKILL.md');
  const source = await readFile(SKILL_PATH, 'utf8');
  const fence = language === '' ? '```' : `\`\`\`${language}`;

  await writeFile(copiedSkill, `${source}\n${fence}\n${command}\n\`\`\`\n`);
  try {
    expect(invalidCommands(await readFile(copiedSkill, 'utf8'))).toEqual([expected]);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});
