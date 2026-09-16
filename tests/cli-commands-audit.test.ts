// `bouncer audit` / `audit --suggest` at the command-function level (same
// discipline as tests/cli-commands.test.ts for check/rules): reads a
// synthetic JSONL log and the account's policy overlay off a tmp
// CLAUDE_CONFIG_DIR, no subprocess spawned.

import { afterEach, describe, expect, test } from 'bun:test';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseAuditArgs, runAudit, runRulesLint } from '../src/cli-commands.ts';
import { loadPolicyFromOverlayText } from '../src/policy/load.ts';
import { tmpDir } from './tmp.ts';

const ORIGINAL_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;

afterEach(() => {
  if (ORIGINAL_CONFIG_DIR === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CONFIG_DIR;
});

function freshAccountDir(): string {
  const dir = tmpDir('bouncer-audit-cli-test-');
  process.env.CLAUDE_CONFIG_DIR = dir;
  return dir;
}

async function writeOverlay(accountDir: string, text: string): Promise<void> {
  await mkdir(join(accountDir, 'bouncer'), { recursive: true });
  await writeFile(join(accountDir, 'bouncer', 'policy.toml'), text, 'utf8');
}

async function writeLog(accountDir: string, lines: readonly Record<string, unknown>[]): Promise<void> {
  await mkdir(join(accountDir, 'logs', 'hooks'), { recursive: true });
  const text = `${lines.map((l) => JSON.stringify(l)).join('\n')}\n`;
  await writeFile(join(accountDir, 'logs', 'hooks', 'bouncer.log'), text, 'utf8');
}

function verdictLine(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    timestamp: new Date().toISOString(),
    session_id: 'sess-1',
    tool_name: 'Bash',
    family: 'command',
    verdict: 'confirm',
    rule_id: 'git-protected',
    target: 'git push origin main',
    ...overrides,
  };
}

// Extracts one `## <heading>`-delimited section's own body — a whole-report
// `.not.toContain(id)` passes wrongly when the id sits on the report's
// LAST line (no trailing "\n" left to match against a `"- id\n"` pattern),
// and says nothing about WHICH section the id is (correctly) absent from.
function sectionOf(report: string, heading: string): string {
  const lines = report.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`## ${heading}`));
  if (start === -1) return '';
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('## '));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

describe('parseAuditArgs', () => {
  test('defaults to a 30-day window and no --suggest', () => {
    expect(parseAuditArgs([])).toEqual({ options: { days: 30, suggest: false, diff: false, harness: 'claude-code' } });
  });

  test('--suggest sets the suggest flag', () => {
    expect(parseAuditArgs(['--suggest'])).toEqual({ options: { days: 30, suggest: true, diff: false, harness: 'claude-code' } });
  });

  test('--sessions-only enables the session-entry filter', () => {
    expect(parseAuditArgs(['--sessions-only'])).toEqual({
      options: { days: 30, suggest: false, diff: false, sessionsOnly: true, harness: 'claude-code' },
    });
  });

  test('--days N overrides the window', () => {
    expect(parseAuditArgs(['--days', '7'])).toEqual({ options: { days: 7, suggest: false, diff: false, harness: 'claude-code' } });
  });

  test('both flags combine regardless of order', () => {
    expect(parseAuditArgs(['--suggest', '--days', '14'])).toEqual({
      options: { days: 14, suggest: true, diff: false, harness: 'claude-code' },
    });
    expect(parseAuditArgs(['--days', '14', '--suggest'])).toEqual({
      options: { days: 14, suggest: true, diff: false, harness: 'claude-code' },
    });
  });

  test('a non-numeric --days value returns an error, never throws', () => {
    const result = parseAuditArgs(['--days', 'soon']);
    expect(result.options).toBeUndefined();
    expect(result.error).toContain('--days');
  });

  test('a missing --days value returns an error, never throws', () => {
    const result = parseAuditArgs(['--days']);
    expect(result.options).toBeUndefined();
    expect(result.error).toBeDefined();
  });

  test('an unrecognized flag is an explicit error, never a silently-ignored no-op (round-3 review item 3)', () => {
    for (const bad of [['--sugest'], ['--dayz'], ['positional-garbage']]) {
      const result = parseAuditArgs(bad);
      expect(result.options).toBeUndefined();
      expect(result.error).toContain(bad[0]);
    }
  });

  test('an unrecognized flag alongside otherwise-valid ones is still rejected, not partially applied', () => {
    const result = parseAuditArgs(['--days', '7', '--sugest']);
    expect(result.options).toBeUndefined();
    expect(result.error).toBeDefined();
  });
});

describe('runAudit: report mode', () => {
  test('no log file at all: every conditional rule is reported dead, no friction', async () => {
    freshAccountDir();
    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(ok).toBe(true);
    expect(text).toContain('no deny/ask entries');
    expect(text).toContain('git-conditional-branch');
  });

  test('a frequent block/confirm cluster is surfaced as friction', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ target: 'git push origin main' }),
      verdictLine({ target: 'git push origin feature-x' }),
    ]);
    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(text).toContain('git-protected');
    expect(text).toContain('2x');
  });

  test('pin (review round on ticket 08): a MIXED shadow+enforce log still clusters as one continuous history', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ target: 'git push origin main', mode: 'shadow' }),
      verdictLine({ target: 'git push origin feature-x' }), // enforced, no mode field
    ]);
    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(text).toContain('git-protected');
    expect(text).toContain('2x'); // both count toward the SAME cluster, mode or not
  });

  test('a mixed legacy and provenance log preserves report and suggestion output', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ target: 'git push origin main' }),
      verdictLine({ target: 'git push origin feature-x', build: '56b1e5a', policy: '0123456789ab' }),
    ]);

    const report = await runAudit({ days: 30, suggest: false, diff: false });
    expect(report.text).toContain('git-protected');
    expect(report.text).toContain('2x');

    const suggestion = await runAudit({ days: 30, suggest: true, diff: false, sessionsOnly: true });
    expect(suggestion.text).toContain('# [[relax]]');
  });

  test('an observe entry marks its conditional rule as fired (its own section), not dead', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ verdict: 'observe', rule_id: 'git-conditional-apply', target: 'git apply --check p.diff' }),
    ]);
    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(sectionOf(text, 'Dead conditional rules')).not.toContain('git-conditional-apply');
    expect(sectionOf(text, 'Conditional rules that fired')).toContain('git-conditional-apply');
    expect(text).toContain('git-conditional-branch'); // still dead, never fired
  });

  test('--days excludes entries outside the window', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ timestamp: '2020-01-01T00:00:00.000Z', target: 'git push origin main' }),
    ]);
    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(text).toContain('no deny/ask entries');
  });

  test('audit-header and policy-warning lines in the log do not break parsing', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      { timestamp: new Date().toISOString(), kind: 'audit-header', overrides: [], relaxations: [] },
      verdictLine({ target: 'git push origin main' }),
    ]);
    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(ok).toBe(true);
    expect(text).toContain('git-protected');
  });

  test('a missing log file (ENOENT) is treated as empty, no warning line (round-3 review item 6)', async () => {
    freshAccountDir();
    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(text).not.toContain('warning:');
  });

  test('an EXISTING but unreadable log file surfaces an honest warning, not silent emptiness '
    + '(round-3 review item 6: ENOENT ≠ EACCES/EISDIR)', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [verdictLine({ target: 'git push origin main' })]);
    const logFile = join(dir, 'logs', 'hooks', 'bouncer.log');
    await chmod(logFile, 0o000); // unreadable by anyone but root
    try {
      const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false });
      expect(ok).toBe(true); // advisory, not a hard failure
      expect(text).toContain('warning: audit log unreadable');
    } finally {
      await chmod(logFile, 0o600);
    }
  });

  test('a directory at the log path (EISDIR) surfaces the same honest warning', async () => {
    const dir = freshAccountDir();
    await mkdir(join(dir, 'logs', 'hooks', 'bouncer.log'), { recursive: true }); // a DIR, not a file
    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(ok).toBe(true);
    expect(text).toContain('warning: audit log unreadable');
  });
});

describe('runAudit: current-policy replay', () => {
  test('removes a relaxed historical git confirmation from friction and suggestions, then records it as resolved', async () => {
    const dir = freshAccountDir();
    await writeOverlay(dir, [
      '[[relax]]',
      'list = "command.git.safe_subcommands"',
      'value = "push"',
      'reason = "test replay relaxation"',
      '',
    ].join('\n'));
    await writeLog(dir, [verdictLine()]);

    const report = await runAudit({ days: 30, suggest: false, diff: false });
    expect(report.ok).toBe(true);
    expect(report.text).toContain('Replayed 1 of 1 entries against the current policy');
    expect(sectionOf(report.text, 'Frequent friction').toLowerCase()).toContain('none');
    expect(sectionOf(report.text, 'Policy delta (replayed against the current policy)')).toContain(
      '- [git-protected] 1x on shape "git push <arg> <arg>"',
    );
    expect(sectionOf(report.text, 'Policy delta (replayed against the current policy)')).toContain('→ now allow');

    const suggestion = await runAudit({ days: 30, suggest: true, diff: false });
    expect(suggestion.text).toContain('# 1 hit(s) resolved by the current policy — not suggested');
    expect(suggestion.text).not.toContain('[[relax]]');
    expect(loadPolicyFromOverlayText(suggestion.text).warnings).toEqual([]);
  });

  test('retains a legacy-truncated entry as logged and counts it separately from replay', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [verdictLine({ target: `${'x'.repeat(197)}...` })]);

    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(ok).toBe(true);
    expect(text).toContain('Replayed 0 of 1 entries against the current policy');
    expect(text).toContain('Not replayable: 1 truncated.');
    expect(sectionOf(text, 'Frequent friction')).toContain('(as logged)');
  });

  test('reports hardened and drifted command verdicts from the current dispatcher', async () => {
    const dir = freshAccountDir();
    await writeOverlay(dir, [
      '[[relax]]',
      'list = "command.git.safe_subcommands"',
      'value = "apply"',
      'reason = "test replay drift"',
      '',
    ].join('\n'));
    await writeLog(dir, [
      verdictLine({ rule_id: 'historical-confirm', target: 'rm -rf /' }),
      verdictLine({ verdict: 'observe', rule_id: 'git-conditional-apply', target: 'git apply --check patch.diff' }),
    ]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    const delta = sectionOf(text, 'Policy delta (replayed against the current policy)');
    expect(delta).toContain('### hardened');
    expect(delta).toContain('→ now block [rm-rf-dangerous]');
    expect(delta).toContain('### drift');
    expect(delta).toContain('→ now allow');
    expect(sectionOf(text, 'Frequent friction')).toContain('rm-rf-dangerous');
    expect(sectionOf(text, 'Conditional rules that fired')).not.toContain('git-conditional-apply');
  });

  test('keeps a secret-family block after relaxing the command-family match', async () => {
    const dir = freshAccountDir();
    await writeOverlay(dir, [
      '[[relax]]',
      'list = "command.git.safe_subcommands"',
      'value = "config"',
      'reason = "test replay strictest reduction"',
      '',
    ].join('\n'));
    await writeLog(dir, [
      verdictLine({ target: 'git config credential.helper store' }),
    ]);

    const { text } = await runAudit({ days: 30, suggest: false, diff: false });
    expect(sectionOf(text, 'Frequent friction')).toContain('bash-git-leak-credential');
    expect(sectionOf(text, 'Policy delta (replayed against the current policy)')).toContain(
      '→ now block [bash-git-leak-credential]',
    );
  });

  test('falls back to the historical report when the selected harness declares no protocol', async () => {
    const { text, ok } = await runAudit({ days: 30, suggest: false, diff: false, harness: 'opencode' });
    expect(ok).toBe(true);
    expect(text).toContain('Replay unavailable: harness opencode declares no protocol');
    expect(text).not.toContain('Policy delta (replayed against the current policy)');
  });

  test('omits the resolved-hit count when the selected harness has no protocol', async () => {
    const { text, ok } = await runAudit({ days: 30, suggest: true, diff: false, harness: 'opencode' });

    expect(ok).toBe(true);
    expect(text).toContain('# Replay unavailable: harness opencode declares no protocol');
    expect(text).not.toContain('hit(s) resolved by the current policy');
  });
});

describe('runAudit: --sessions-only across modes', () => {
  test('filters a mixed log and labels the active filter in every mode', async () => {
    const dir = freshAccountDir();
    const timestamp = new Date().toISOString();
    await writeLog(dir, [
      verdictLine({ timestamp, session_id: null, rule_id: 'rm-rf-dangerous', target: 'rm -rf /', mode: 'shadow' }),
      verdictLine({ timestamp, session_id: 'session-1', rule_id: 'git-protected', target: 'git push origin main', mode: 'shadow' }),
    ]);

    const modes = [
      { options: { days: 1, suggest: false, diff: false, sessionsOnly: true }, header: '1 entries, 1 CLI entries excluded' },
      { options: { days: 1, suggest: true, diff: false, sessionsOnly: true }, header: '1 entries, 1 CLI entries excluded' },
      {
        options: { days: 1, suggest: false, diff: true, sessionsOnly: true },
        header: 'bouncer shadow: 1 entries, 1 CLI entries excluded · TS: 0 entries, 0 CLI entries excluded',
      },
    ];

    const filteredResults = await Promise.all(
      modes.map(async ({ options, header }) => ({ options, header, result: await runAudit(options) })),
    );
    for (const { options, header, result: { text, ok } } of filteredResults) {
      expect(ok).toBe(true);
      expect(text).toContain('git-protected');
      expect(text).not.toContain('rm-rf-dangerous');
      expect(text).toStartWith(options.suggest ? `# ${header}` : header);
      if (options.suggest) expect(loadPolicyFromOverlayText(text).warnings).toEqual([]);
    }

    const unfilteredResults = await Promise.all(
      modes.map(async ({ options }) => runAudit({ days: options.days, suggest: options.suggest, diff: options.diff })),
    );
    for (const { text } of unfilteredResults) {
      expect(text).toContain('rm-rf-dangerous');
      expect(text.split('\n').slice(0, 3).join('\n')).not.toMatch(/exclud/i);
    }
  });
});

describe('runAudit: --suggest mode', () => {
  test('produces TOML that `rules lint` accepts as-is (AC3)', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ target: 'git push origin main' }),
      verdictLine({ target: 'git push origin feature-x' }),
    ]);
    const { text: suggestText, ok: suggestOk } = await runAudit({ days: 30, suggest: true, diff: false, sessionsOnly: true });
    expect(suggestOk).toBe(true);
    // git-protected friction ships commented out (round-3 review item 2) —
    // the literal substring still appears (inside the comment), the active
    // block does not.
    expect(suggestText).toContain('# [[relax]]');

    // Feed the suggestion straight into the account's overlay and re-lint —
    // this is the "generate then lint" proof the ticket asks for.
    await writeOverlay(dir, suggestText);
    const { text: lintText, ok: lintOk } = await runRulesLint();
    expect(lintOk).toBe(true);
    expect(lintText).toContain('OK');
  });

  test('an unreadable log in --suggest mode gets a `#`-commented warning (stays valid TOML)', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [verdictLine({ target: 'git push origin main' })]);
    const logFile = join(dir, 'logs', 'hooks', 'bouncer.log');
    await chmod(logFile, 0o000);
    try {
      const { text } = await runAudit({ days: 30, suggest: true, diff: false });
      expect(text).toContain('# warning: audit log unreadable');
      const result = loadPolicyFromOverlayText(text);
      expect(result.warnings).toEqual([]);
    } finally {
      await chmod(logFile, 0o600);
    }
  });

  test('an empty window produces a lint-safe "nothing to suggest" comment', async () => {
    const dir = freshAccountDir();
    const { text } = await runAudit({ days: 30, suggest: true, diff: false });
    await writeOverlay(dir, text);
    const { ok } = await runRulesLint();
    expect(ok).toBe(true);
  });

  test('never writes to the account overlay file itself (no auto-apply, AC4)', async () => {
    const dir = freshAccountDir();
    await writeLog(dir, [
      verdictLine({ target: 'git push origin main' }),
      verdictLine({ target: 'git push origin feature-x' }),
    ]);
    await runAudit({ days: 30, suggest: true, diff: false });
    const overlay = await Bun.file(join(dir, 'bouncer', 'policy.toml')).exists();
    expect(overlay).toBe(false);
  });
});
