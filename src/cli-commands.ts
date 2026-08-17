// The non-`run` CLI subcommands: `check`, `rules lint`, `rules list`,
// `doctor`, `audit`. Each returns the text to print plus whether it counts
// as a success (for the exit code) — kept separate from process.exit/
// console.log so these are unit-testable without spawning a subprocess.

import { readFile } from 'node:fs/promises';
import {
  clusterEntries,
  findDeadConditionalRules,
  parseLogEntries,
  renderReport,
  renderSuggestions,
  withinWindow,
} from './adapter/audit.ts';
import { HOOK_NAME } from './adapter/constants.ts';
import { createDispatcher } from './adapter/dispatch.ts';
import { defaultSettingsPath, formatDoctorChecklist, runDoctorChecks } from './adapter/doctor.ts';
import { hookLogPath } from './adapter/log-path.ts';
import { loadCurrentPolicy, overlayDirPath, overlayPath } from './adapter/policy.ts';
import { resolvableRuleIds } from './policy/lint.ts';
import type { EffectiveRule, LoadResult } from './policy/load.ts';

export interface CommandResult {
  readonly text: string;
  readonly ok: boolean;
}

/**
 * `bouncer check "<command>"` — dry-runs a Bash command against the
 * effective (baseline + account overlay) policy and prints the verdict it
 * would produce, without a live session. Reproduces the PreToolUse
 * dispatch exactly (so a command that also trips the secret family, say,
 * is reported faithfully) rather than command-family-only.
 */
export async function runCheck(command: string): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  const dispatcher = createDispatcher(loaded.policy);
  const hit = await dispatcher.inspectPreToolUse({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  });

  const warningLines = loaded.warnings.map((w) => `warning: ${w}`);
  if (!hit) {
    return { text: [...warningLines, 'allow'].join('\n'), ok: true };
  }
  const line = `${hit.verdict.verdict} [${hit.verdict.ruleId}] ${hit.verdict.reason}`;
  return { text: [...warningLines, line].join('\n'), ok: true };
}

/**
 * `bouncer rules lint` — validates the account's current overlay set
 * (`policy.toml` plus every `policy.d/*.toml` file, if any) against the
 * RE2-like dialect and the [[override]]/[[relax]] resolution/reason/
 * cross-file-conflict rules. Non-zero exit on failure (unlike `run`, which
 * must always exit 0 for the hook protocol) — this is a validation command
 * meant to be scripted against. On success, names every file that was
 * actually merged in (ticket 12's "reports per file"); on failure, the
 * warning lines already name the specific offending file.
 */
export async function runRulesLint(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  if (loaded.warnings.length === 0) {
    const suffix = loaded.overlayApplied
      ? `overlay: ${loaded.overlayFiles.join(', ')}`
      : 'no overlay present — baseline only';
    return { text: `lint: OK (${suffix})`, ok: true };
  }
  return {
    text: [`lint: FAILED (${overlayPath()}, ${overlayDirPath()})`, ...loaded.warnings.map((w) => `  - ${w}`)].join('\n'),
    ok: false,
  };
}

function ruleLine(entry: EffectiveRule): string {
  const suffix = entry.provenance === 'override'
    ? `override(${entry.overrideAction}) — ${entry.overrideReason}`
    : entry.provenance;
  // The source file only exists for overlay/override provenance — a
  // baseline rule has no file on disk to name, so `sourceFile` stays
  // absent and this suffix stays empty, leaving baseline lines unchanged.
  const fileSuffix = entry.sourceFile !== undefined ? ` [${entry.sourceFile}]` : '';
  return `rule ${entry.family} ${entry.rule.id} ${suffix}${fileSuffix}`;
}

function overrideLine(loaded: LoadResult): string[] {
  return loaded.activeOverrides.map((o) => `override ${o.action} ${o.rule} — ${o.reason} [${o.sourceFile}]`);
}

// `[[relax]]` entries and a governed-sub git-conditional substitution both
// only ever widen the effective policy — surfaced with their own
// `overlay-relax` provenance (distinct from `override`, which can also
// disable/replace/relax an EXISTING rule) so a relaxed allowlist is exactly
// as impossible to overlook as an active override.
function relaxationLine(loaded: LoadResult): string[] {
  return loaded.activeRelaxations.map((r) => `overlay-relax ${r.list} ${r.value} — ${r.reason} [${r.sourceFile}]`);
}

/**
 * `bouncer rules list` — one line per effective rule (family, id,
 * provenance), active overrides and relaxations listed first and counted
 * together in a summary line so a relaxed policy is impossible to overlook.
 * Stable, greppable output: `^summary`, `^override`, `^overlay-relax`,
 * `^rule` prefixes.
 */
export async function runRulesList(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  const overridesActive = loaded.activeOverrides.length + loaded.activeRelaxations.length;
  const lines = [
    `summary: ${loaded.effectiveRules.length} rules, ${overridesActive} overrides active`
      + (loaded.warnings.length > 0 ? `, ${loaded.warnings.length} warnings` : ''),
    ...loaded.warnings.map((w) => `warning: ${w}`),
    ...overrideLine(loaded),
    ...relaxationLine(loaded),
    ...loaded.effectiveRules.map(ruleLine),
  ];
  return { text: lines.join('\n'), ok: true };
}

export interface ParsedDoctorArgs {
  readonly settingsPath?: string;
  readonly error?: string;
}

/**
 * Pure parsing for `bouncer doctor [--settings <path>]`'s argv tail — kept
 * out of cli.ts (the I/O layer) so the one rule that actually needs a test,
 * "what counts as a missing value", is unit-testable without spawning a
 * subprocess. `--settings` as the LAST token, or immediately followed by
 * another flag (`--settings --other-flag`), is a missing-argument error —
 * the next flag must never be silently swallowed as if it were the path.
 */
export function parseDoctorArgs(rest: readonly string[]): ParsedDoctorArgs {
  const flagIndex = rest.indexOf('--settings');
  if (flagIndex === -1) return {};
  const value = rest[flagIndex + 1];
  if (value === undefined || value.startsWith('--')) {
    return { error: '--settings requires a path argument' };
  }
  return { settingsPath: value };
}

/**
 * `bouncer doctor [--settings <path>]` — the manual, always-verbose form
 * of the wiring/policy/log/override checklist (ticket 07). `--settings`
 * defaults to `<configDir>/settings.json` (the account's own settings
 * file, same root as the policy overlay and the audit log) but accepts an
 * override so a scratch settings.json can be checked without touching a
 * live config — the same override this ticket's demo and ACs exercise.
 * Non-zero exit on any failing check (unlike `run`, which must always
 * exit 0 for the hook protocol) — `ok` is exactly what cli.ts maps to
 * `process.exit(ok ? 0 : 1)`.
 */
export async function runDoctor(settingsPath?: string): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  const report = await runDoctorChecks(settingsPath ?? defaultSettingsPath(), loaded);
  return { text: formatDoctorChecklist(report), ok: report.ok };
}

export interface AuditOptions {
  readonly days: number;
  readonly suggest: boolean;
}

// Same error-protocol shape as ParsedDoctorArgs (return, never throw, so
// cli.ts never needs a try/catch around parsing): a discriminated union
// rather than two independent optionals, because `options` genuinely IS
// required whenever there is no `error` (unlike ParsedDoctorArgs's
// settingsPath, which is legitimately optional even on success) — this
// lets `parsed.options` narrow to defined after the `error` check with no
// non-null assertion needed.
export type ParsedAuditArgs =
  | { readonly options: AuditOptions; readonly error?: undefined }
  | { readonly options?: undefined; readonly error: string };

const DEFAULT_AUDIT_DAYS = 30;
const KNOWN_AUDIT_FLAGS: ReadonlySet<string> = new Set(['--suggest', '--days']);

/**
 * Parses `audit`'s own flags (`--days N`, `--suggest`) — deliberately tiny
 * (two flags, no ordering requirement) rather than pulling in a general
 * arg-parsing dependency for one subcommand. An unrecognized token
 * (`--sugest`, `--dayz`, a stray positional, ...) is an explicit error, not
 * silently ignored — a typo'd flag must not fall through to "30-day report,
 * exit 0" as if nothing had been asked for.
 */
export function parseAuditArgs(rest: readonly string[]): ParsedAuditArgs {
  let days = DEFAULT_AUDIT_DAYS;
  let suggest = false;
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg === '--suggest') {
      suggest = true;
      continue;
    }
    if (arg === '--days') {
      const value = rest[i + 1];
      const parsed = value !== undefined ? Number(value) : Number.NaN;
      if (!Number.isFinite(parsed) || parsed <= 0) {
        return { error: `audit: --days requires a positive number, got ${JSON.stringify(value)}` };
      }
      days = parsed;
      i++;
      continue;
    }
    if (!KNOWN_AUDIT_FLAGS.has(arg)) {
      return { error: `audit: unrecognized argument ${JSON.stringify(arg)} (expected: --days <n> | --suggest)` };
    }
  }
  return { options: { days, suggest } };
}

/**
 * `bouncer audit` / `bouncer audit --suggest` — the proactive tuning loop
 * (ticket 10): clusters this account's deny/ask and conditional-allow log
 * entries over the last `--days` days and either prints the human report
 * (frequent friction + dead conditional rules) or, with `--suggest`,
 * candidate `[[relax]]`/`[[override]]` TOML snippets. Reads the log file
 * and the current policy off disk — the clustering/rendering itself is
 * pure (src/adapter/audit.ts). A missing log file (ENOENT) is treated
 * exactly like an empty one (a fresh account has audited nothing yet, not
 * a failure); any OTHER read error (permissions, the path being a
 * directory, ...) is NOT swallowed the same way — the header this function
 * promises ("missing = empty") would otherwise silently lie for an
 * existing-but-unreadable log, so that case surfaces a `warning:` line
 * atop the report instead.
 */
export async function runAudit(options: AuditOptions): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();

  let logText = '';
  let logWarning: string | null = null;
  try {
    logText = await readFile(hookLogPath(HOOK_NAME), 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code !== 'ENOENT') {
      const message = err instanceof Error ? err.message : String(err);
      logWarning = `audit log unreadable: ${message}`;
    }
  }
  const entries = withinWindow(parseLogEntries(logText), options.days);
  const clusters = clusterEntries(entries);

  if (options.suggest) {
    const resolvable = resolvableRuleIds(loaded.policy);
    const text = renderSuggestions(clusters, resolvable, { days: options.days });
    // `#`-commented: renderSuggestions's output is TOML meant to be pasted
    // straight into an overlay (AC3) — a bare `warning: ...` line ahead of
    // it would not parse as TOML and would corrupt that contract.
    const warningLines = logWarning !== null ? [`# warning: ${logWarning}`] : [];
    return { text: [...warningLines, text].join('\n'), ok: true };
  }

  const firedObserveRuleIds = new Set(
    clusters.filter((c) => c.verdict === 'observe').map((c) => c.ruleId),
  );
  const deadRuleIds = findDeadConditionalRules(loaded.policy, firedObserveRuleIds);
  const text = renderReport(clusters, deadRuleIds, { days: options.days });
  const warningLines = logWarning !== null ? [`warning: ${logWarning}`] : [];
  return { text: [...warningLines, text].join('\n'), ok: true };
}
