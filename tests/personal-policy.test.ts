// Ticket 13 (baseline universality triage) moved three rules OUT of the
// embedded baseline — `hook-log` (secret.path) and `pull`/`merge`
// `--ff-only` (command.git.safe_grammar) — into
// examples/personal-overlay.toml, a TRACKED, zero-secrets example (never
// installed automatically — see that file's own header). This file
// proves the move is BEHAVIOR-PRESERVING under the overlay: every case
// that used to live in tests/secret-rules.test.ts and
// tests/command-rules.test.ts against BASELINE directly now lives here,
// against the MERGED (baseline + personal overlay) policy — same
// commands, same expected outcomes. (`transcript-backup` moved back to
// the baseline itself, verdict "confirm" — see tests/secret-rules.test.ts
// — after review round 2's arbitration; it is no longer part of this
// overlay.)
//
// Loads the real file off disk (not a copy pasted into this test) so a
// future edit to the example overlay is exercised by the same suite that
// documents why it exists.

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCommandChecker } from '../src/command-rules.ts';
import { loadPolicyFromOverlayText } from '../src/policy/load.ts';
import { createSecretChecker } from '../src/secret-rules.ts';

const PERSONAL_OVERLAY_PATH = join(import.meta.dirname, '..', 'examples', 'personal-overlay.toml');
const personalOverlayText = readFileSync(PERSONAL_OVERLAY_PATH, 'utf8');
const loaded = loadPolicyFromOverlayText(personalOverlayText);

// Loading itself must succeed cleanly — a syntax error or lint failure in
// the personal overlay would silently fall back to baseline-only (the
// documented fail-closed contract), which would make every test below
// pass for the WRONG reason (baseline rejection, not overlay behavior).
describe('the personal overlay loads cleanly', () => {
  test('no warnings, overlay applied', () => {
    expect(loaded.warnings).toEqual([]);
    expect(loaded.overlayApplied).toBe(true);
  });

  test('all three moved rules are present with their expected provenance', () => {
    const hookLog = loaded.effectiveRules.find((r) => r.rule.id === 'hook-log');
    expect(hookLog?.provenance).toBe('overlay');
    expect(loaded.policy.command.git.safe_grammar.map((r) => r.sub)).toEqual(
      expect.arrayContaining(['pull', 'merge']),
    );
  });
});

const secretChecker = createSecretChecker(loaded.policy.secret, loaded.policy.command.git.config_read_modes);
const { checkPath } = secretChecker;

describe('secret.path: hook-log is restored under the personal overlay', () => {
  test('ruleId hook-log: guard-command.log is blocked', () => {
    expect(checkPath('/proj/hooks/guard-command.log')?.ruleId).toBe('hook-log');
  });

  test('ruleId hook-log: guard-mcp-write.log is blocked (fifth guard\'s log)', () => {
    expect(checkPath('/proj/hooks/guard-mcp-write.log')?.ruleId).toBe('hook-log');
  });

  test('documented gap: rotated guard-mcp-write.log.1 is not blocked', () => {
    // Rotation is not covered because hook-log ends at `.log$`. Locked as a
    // visible gap so a future extension must update this assertion
    // consciously — unchanged by the ticket 13 move.
    expect(checkPath('/proj/hooks/guard-mcp-write.log.1')).toBeNull();
  });

  test('ruleId hook-log: guard-secret.log is blocked, as a guard', () => {
    expect(checkPath('/proj/hooks/guard-secret.log')?.ruleId).toBe('hook-log');
  });

  test.each([
    'guard-write-secret',
    'transcript-backup',
  ])('ruleId hook-log: %s.log is blocked', (stem) => {
    expect(checkPath(`/proj/hooks/${stem}.log`)?.ruleId).toBe('hook-log');
  });

  // Negative discriminator: the workstation's naming scheme. The workstation
  // writes command-guard.log and secret-guard.log — no engine guard writes
  // either — plus transcript-backup.log, which coincides with a branch name
  // and so is not a discriminator. Without both tests below, nothing stops
  // someone widening the alternation to either workstation name on its own.
  test('benign: secret-guard.log (workstation naming scheme) is not blocked', () => {
    expect(checkPath('/proj/hooks/secret-guard.log')).toBeNull();
  });

  test('benign: command-guard.log (workstation naming scheme) is not blocked', () => {
    expect(checkPath('/proj/hooks/command-guard.log')).toBeNull();
  });
});

const { checkGit } = createCommandChecker(loaded.policy.command);

describe('command.git.safe_grammar: pull/merge --ff-only is restored under the personal overlay', () => {
  test('git pull --ff-only stays silent', () => {
    expect(checkGit('git pull --ff-only')).toBeNull();
  });

  test('git merge --ff-only feat stays silent', () => {
    expect(checkGit('git merge --ff-only feat')).toBeNull();
  });

  test('git pull (no --ff-only) still asks', () => {
    expect(checkGit('git pull')?.ruleId).toBe('git-protected');
  });

  test('git merge feat (no --ff-only) still asks', () => {
    expect(checkGit('git merge feat')?.ruleId).toBe('git-protected');
  });

  // The overlay's sequence match is EXACT (table-length equality, see
  // gitSubcommandNeedsConfirm) — the ratified form is narrow, not "any
  // command containing --ff-only". Locked here per review round 2 (the
  // narrowness was only noted in prose for ticket 08 before this).
  test('git pull --ff-only origin main still asks (extra positionals break the exact sequence match)', () => {
    expect(checkGit('git pull --ff-only origin main')?.ruleId).toBe('git-protected');
  });

  test('git merge --ff-only alone still asks (missing the required branch positional)', () => {
    expect(checkGit('git merge --ff-only')?.ruleId).toBe('git-protected');
  });

  test.each([
    'git pull # --ff-only',
    'git merge feat # --ff-only',
  ])('%s still asks because the shell executes only the part before #', (cmd) => {
    expect(checkGit(cmd)?.ruleId).toBe('git-protected');
  });

  test('git merge -m --ff-only feat asks because -m consumes the marker as its message', () => {
    expect(checkGit('git merge -m --ff-only feat')?.ruleId).toBe('git-protected');
  });

  test('git pull -m --ff-only asks because -m consumes the marker as its message', () => {
    expect(checkGit('git pull -m --ff-only')?.ruleId).toBe('git-protected');
  });

  test.each([
    'git pull origin -- --ff-only',
    'git merge feat -- --ff-only',
  ])('%s asks when the marker is a positional after --', (cmd) => {
    expect(checkGit(cmd)?.ruleId).toBe('git-protected');
  });
});
