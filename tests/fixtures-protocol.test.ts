// The conformance proof ADR-0006 § 10 asks for: each fixtures/protocol/
// <harness>.json file is captured by scripts/capture-protocol.ts BEFORE
// (claude-code, ticket 15a) or WITH (codex, ticket 15b) that harness's
// own adapter code — this file replays every one of those cases through
// the declaration-driven `run()` and asserts its stdout and exit code
// match, byte for byte, EXCEPT `permissionDecisionReason`, compared only
// on its `<ruleId>:` prefix (the rule id is an overlay-facing contract;
// the prose after the colon is not, and gets reworded — main's own
// mcp-write rewording is why this exists). If this file is green, the
// pipeline changed nothing observable for either harness's user.
//
// Ticket 15b generalized this from a single hardcoded claude-code.json
// read to iterating every file under fixtures/protocol/ — the "only
// acceptable modification" the 15b brief names for this test, since it
// already iterated nothing before (one fixed path). Each case gets its
// own throwaway HOME/<harness's own config-dir env var> (baseline only,
// no profile overlay) — same isolation discipline as the capture
// script itself. The SessionStart cases need a real settings/hooks file
// on disk; its SHAPE (not its exact binary path — see below) is what the
// capture script wrote, reconstructed here from the same
// tests/doctor-fixtures.ts helpers the rest of the doctor test suite
// uses. The binary path itself never appears in any captured case's
// stdout (checked once, by hand, against each recorded fixture) — only
// event names and check ids do — so a fake path here reproduces the same
// bytes a real installed/source path produced.

import { describe, expect, test } from 'bun:test';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { run } from '../src/adapter/run.ts';
import { renderShim } from '../src/adapter/shim.ts';
import type { BuildInfo } from '../src/build-info.ts';
import { CODEX_HEALTHY_HOOKS, codexTrustToml, HEALTHY_HOOKS } from './doctor-fixtures.ts';
import { tmpDir } from './tmp.ts';

interface RecordedCase {
  readonly id: string;
  readonly argv: readonly string[];
  readonly stdin: string;
  readonly expected: { readonly stdout: string | null; readonly exit: number; };
}

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'protocol');
const FIXTURE_FILES = readdirSync(FIXTURE_DIR).filter((f) => f.endsWith('.json'));
const FIXTURE_BUILD: BuildInfo = { sha: 'fixture', dirty: false, date: '2026-01-01T00:00Z' };

// Mirrors scripts/capture-protocol.ts's own settings fixtures exactly —
// see that script's `settings` field on each `sessionstart-*` case.
const MISSING_HOOK_HOOKS = (() => {
  const { UserPromptSubmit: _omit, ...rest } = HEALTHY_HOOKS;
  return rest;
})();
const CODEX_MISSING_HOOK_HOOKS = (() => {
  const { UserPromptSubmit: _omit, ...rest } = CODEX_HEALTHY_HOOKS;
  return rest;
})();

interface HarnessReplayConfig {
  readonly envVarName: string;
  readonly configSubdir: string;
  readonly settingsFileName: string;
  readonly runHarness?: string; // undefined selects run()'s own default (claude-code)
  readonly settingsFor: (caseId: string) => unknown | undefined;
  // codex-hooks' own trust ledger needs the FILE's real path, known only
  // once the scratch config dir exists — undefined for a harness with no
  // such concept (claude-code's hook-file wiring).
  readonly trustTomlFor?: (caseId: string, hooksJsonPath: string) => string | undefined;
  // ADR-0006 § 6/7, ticket 15c: `shim-file` wiring (pi-agent) installs a
  // raw shim SOURCE FILE (`extensions/bouncer.ts`), never a `{hooks:
  // ...}` JSON wrapper — when set, this REPLACES settingsFor/
  // trustTomlFor's write entirely for this harness, since neither
  // concept (a hooks table, a trust ledger) applies to it.
  readonly installArtifact?: (caseId: string, configDir: string) => void;
  // Review round 1 S-6/P-6: the exact case ids this fixture file MUST
  // keep — a dropped case fails the meta-check by NAME, not by falling
  // under a length threshold a different added-and-dropped case could
  // silently keep satisfying. claude-code: all 24 cases 15a recorded.
  // codex: every case ticket 15b's acceptance box asks for, plus L-1's
  // hooks.json-delete case — deliberately the full captured set (a
  // strict superset of "the twelve the ticket lists"), not a hand-picked
  // 12, so the shared-protocol cases (malformed/shadow/posttooluse) this
  // harness also exercises are guarded too. See the 15b report for the
  // id-by-id mapping to the ticket's acceptance bullets.
  readonly requiredCaseIds: readonly string[];
}

const HARNESS_REPLAY_CONFIG: Readonly<Record<string, HarnessReplayConfig>> = {
  'claude-code': {
    envVarName: 'CLAUDE_CONFIG_DIR',
    configSubdir: '.claude',
    settingsFileName: 'settings.json',
    settingsFor: (caseId) => {
      if (caseId === 'sessionstart-healthy-silent') return HEALTHY_HOOKS;
      if (caseId === 'sessionstart-missing-hook-scream') return MISSING_HOOK_HOOKS;
      return undefined;
    },
    requiredCaseIds: [
      'rm-rf-root-deny',
      'git-push-force-ask',
      'git-reflog-show-silent',
      'read-ssh-key-deny',
      'write-claude-settings-ask',
      'multiedit-aws-key-deny',
      'notebookedit-protected-ask',
      'grep-ssh-dir',
      'glob-ssh-dir',
      'ctx-execute-deny',
      'ctx-batch-execute-mixed-entries',
      'ctx-fetch-and-index-requests',
      'ctx-index-read',
      'generic-mcp-write-ask',
      'git-config-credential-helper-strictest',
      'userpromptsubmit-injection-flag',
      'sessionstart-healthy-silent',
      'sessionstart-missing-hook-scream',
      'empty-stdin-silent',
      'invalid-json-silent',
      'posttooluse-event-silent',
      'missing-hook-event-name-silent',
      'shadow-deny-silent',
      'shadow-typo-normal-enforce',
      'read-colon-selector-ask',
      'grep-semicolon-list-deny',
    ],
  },
  codex: {
    envVarName: 'CODEX_HOME',
    configSubdir: '.codex',
    settingsFileName: 'hooks.json',
    runHarness: 'codex',
    settingsFor: (caseId) => {
      if (caseId === 'sessionstart-healthy-silent') return CODEX_HEALTHY_HOOKS;
      if (caseId === 'sessionstart-missing-hook-scream') return CODEX_MISSING_HOOK_HOOKS;
      return undefined;
    },
    trustTomlFor: (caseId, hooksJsonPath) => {
      if (caseId === 'sessionstart-healthy-silent' || caseId === 'sessionstart-missing-hook-scream') {
        return codexTrustToml(hooksJsonPath);
      }
      return undefined;
    },
    requiredCaseIds: [
      'rm-rf-root-deny',
      'git-branch-delete-confirm-degraded-to-deny',
      'git-reflog-show-observe-silent',
      'bash-quoted-multiline-silent',
      'apply-patch-add-write-secret-deny',
      'apply-patch-update-relative-cwd-protected-deny',
      'apply-patch-move-into-protected-deny',
      'apply-patch-delete-protected-deny',
      'apply-patch-delete-hooks-json-protected-deny',
      'apply-patch-unparseable-not-judged-silent',
      'apply-patch-partial-parse-then-fail-still-denies',
      'mcp-playwright-navigate-generic-confirm-degraded-to-deny',
      'userpromptsubmit-injection-flag',
      'sessionstart-healthy-silent',
      'sessionstart-missing-hook-scream',
      'empty-stdin-malformed',
      'invalid-json-malformed',
      'posttooluse-event-silent',
      'missing-hook-event-name-silent',
      'shadow-deny-silent',
      'shadow-typo-normal-enforce',
    ],
  },
  'pi-agent': {
    envVarName: 'PI_CODING_AGENT_DIR',
    configSubdir: '.pi-agent-home',
    settingsFileName: 'extensions/bouncer.ts',
    runHarness: 'pi-agent',
    // shim-file wiring has no `{hooks: ...}` shape at all — `installArtifact`
    // below fully replaces this pair for pi-agent.
    settingsFor: () => undefined,
    // `wiring:binary` validates an actual executable, never a hook-file
    // string. A fake installed path would make the healthy case fail a
    // check unrelated to SessionStart rendering, so `process.execPath`
    // provides the real executable path. The healthy stdout is `null`
    // regardless of which executable path was baked into the shim; that
    // path is therefore outside the fixture byte contract.
    // Keep this executable-path rationale synchronized with
    // scripts/capture-protocol.ts's matching shim capture branch.
    installArtifact: (caseId, configDir) => {
      if (caseId !== 'sessionstart-healthy-silent') return;
      mkdirSync(join(configDir, 'extensions'), { recursive: true });
      writeFileSync(join(configDir, 'extensions', 'bouncer.ts'), renderShim('pi-agent', process.execPath)!, 'utf8');
    },
    requiredCaseIds: [
      'rm-rf-root-deny',
      'git-branch-delete-ask',
      'git-reflog-show-observe-silent',
      'read-ssh-key-deny',
      'write-pi-agent-config-ask',
      'hashline-edit-multi-section-write-secret-deny',
      'hashline-edit-unparseable-not-judged-silent',
      'pi-edit-shape-write-secret-deny',
      'grep-ssh-dir',
      'glob-ssh-dir',
      'find-ssh-dir',
      'ls-ssh-dir',
      'read-zsh-history-colon-selector-ask',
      'grep-path-list-semicolon-deny',
      'sessionstart-healthy-silent',
      'sessionstart-broken-shim-scream',
      'empty-stdin-malformed',
      'invalid-json-malformed',
      'unknown-event-silent',
      'missing-event-name-silent',
      'shadow-deny-silent',
      'shadow-typo-normal-enforce',
    ],
  },
};

// Mirrors cli.ts's own `run` argv handling exactly: only the LITERAL
// string "--shadow" ever sets shadow mode; every other token is passed
// through as an unrecognized-argument warning, never silently dropped.
function parseRunArgv(argv: readonly string[]): { shadow: boolean; unrecognizedTokens: readonly string[]; } {
  return { shadow: argv.includes('--shadow'), unrecognizedTokens: argv.filter((t) => t !== '--shadow') };
}

// Byte for byte, except `permissionDecisionReason`: reduced to its
// `<ruleId>:` prefix on BOTH sides before comparing (see the header
// comment above) — the rule id is an overlay-facing contract, the prose
// after it is not and gets reworded (main's own mcp-write change is why
// this exists).
function normalizeReasonPrefix(stdout: string | null): string | null {
  if (stdout === null) return null;
  // Review round 2 C-3: a future harness's template may legally render
  // plain text, not JSON (15a's lint proves shape, never a fixed
  // output format) — a parse failure here must fall through to the
  // byte comparison unchanged, not crash the replay with a JSON error
  // instead of a diff.
  let payload: { hookSpecificOutput?: { permissionDecisionReason?: unknown; }; };
  try {
    payload = JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecisionReason?: unknown; }; };
  } catch {
    return stdout;
  }
  const reason = payload.hookSpecificOutput?.permissionDecisionReason;
  if (typeof reason !== 'string') return stdout;
  const colonIndex = reason.indexOf(':');
  const prefix = colonIndex === -1 ? reason : reason.slice(0, colonIndex + 1);
  return stdout.replace(JSON.stringify(reason), JSON.stringify(prefix));
}

describe('normalizeReasonPrefix: non-JSON stdout falls through unchanged (review round 2 C-3)', () => {
  test('a plain-text template (legal per 15a lint) does not crash the parse — returns stdout as-is', () => {
    expect(normalizeReasonPrefix('not json at all')).toBe('not json at all');
  });

  test('null stays null', () => {
    expect(normalizeReasonPrefix(null)).toBeNull();
  });

  test('a real deny envelope still reduces its reason to the ruleId prefix', () => {
    const stdout = JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: 'rm-rf-dangerous: some prose',
      },
    });
    const normalized = normalizeReasonPrefix(stdout);
    expect(normalized).not.toBeNull();
    expect(JSON.parse(normalized!).hookSpecificOutput.permissionDecisionReason).toBe('rm-rf-dangerous:');
  });
});

for (const file of FIXTURE_FILES) {
  const harnessId = file.replace(/\.json$/, '');
  const config = HARNESS_REPLAY_CONFIG[harnessId];
  if (config === undefined) {
    throw new Error(
      `tests/fixtures-protocol.test.ts: no replay config for harness ${JSON.stringify(harnessId)} (fixtures/protocol/${file})`,
    );
  }
  const { cases } = JSON.parse(readFileSync(join(FIXTURE_DIR, file), 'utf8')) as { cases: readonly RecordedCase[]; };

  describe(`fixtures/protocol/${file}: byte-for-byte replay against run() (permissionDecisionReason on its ruleId prefix)`, () => {
    for (const recorded of cases) {
      test(recorded.id, async () => {
        const accountDir = tmpDir('bouncer-protocol-replay-');
        const configDir = join(accountDir, config.configSubdir);
        mkdirSync(configDir, { recursive: true });
        if (config.installArtifact !== undefined) {
          config.installArtifact(recorded.id, configDir);
        } else {
          const settings = config.settingsFor(recorded.id);
          if (settings !== undefined) {
            const settingsPath = join(configDir, config.settingsFileName);
            writeFileSync(settingsPath, JSON.stringify({ hooks: settings }), 'utf8');
            const trustToml = config.trustTomlFor?.(recorded.id, settingsPath);
            if (trustToml !== undefined) writeFileSync(join(configDir, 'config.toml'), trustToml, 'utf8');
          }
        }

        const originalHome = process.env.HOME;
        const originalEnvValue = process.env[config.envVarName];
        process.env.HOME = accountDir;
        process.env[config.envVarName] = configDir;
        try {
          const { shadow, unrecognizedTokens } = parseRunArgv(recorded.argv);
          const result = await run(recorded.stdin, {
            shadow,
            unrecognizedTokens,
            build: FIXTURE_BUILD,
            ...(config.runHarness !== undefined ? { harness: config.runHarness } : {}),
          });
          expect(normalizeReasonPrefix(result.stdout)).toBe(normalizeReasonPrefix(recorded.expected.stdout));
          expect(result.exit ?? 0).toBe(recorded.expected.exit);
        } finally {
          if (originalHome === undefined) delete process.env.HOME;
          else process.env.HOME = originalHome;
          if (originalEnvValue === undefined) delete process.env[config.envVarName];
          else process.env[config.envVarName] = originalEnvValue;
        }
      });
    }
  });

  // A meta-check on each fixture set itself (review round 1 S-6/P-6):
  // every REQUIRED case id (named per harness in HARNESS_REPLAY_CONFIG,
  // not just a length threshold) must be present — dropping a specific
  // case then fails by NAME, not by a count a different dropped-and-added
  // case could silently keep satisfying.
  test(`${file}: the fixture set has every required case id, not an accidentally-empty or drifted file`, () => {
    const ids = new Set(cases.map((c) => c.id));
    expect(ids.size).toBe(cases.length);
    const missing = config.requiredCaseIds.filter((id) => !ids.has(id));
    expect(missing).toEqual([]);
  });

  test(`${file}: fixture stdout excludes runtime provenance`, () => {
    for (const recorded of cases) {
      if (recorded.expected.stdout === null) continue;
      expect(recorded.expected.stdout).not.toContain('effective policy');
      expect(recorded.expected.stdout).not.toMatch(/[0-9a-f]{12}/);
    }
  });
}
