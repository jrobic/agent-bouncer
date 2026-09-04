// The non-`run` CLI subcommands: `check`, `rules lint`, `rules list`,
// `doctor`, `audit`. Each returns the text to print plus whether it counts
// as a success (for the exit code) — kept separate from process.exit/
// console.log so these are unit-testable without spawning a subprocess.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { clusterDivergences, diffLogs, parseTsLogEntries, renderDiffReport, TS_GUARD_LOG_FILES } from './adapter/audit-diff.ts';
import type { TsLogEntry } from './adapter/audit-diff.ts';
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
import { defaultSettingsPath, formatCanonicalCanaryEntry, formatDoctorChecklist, runDoctorChecks } from './adapter/doctor.ts';
import { configDir, hookLogPath } from './adapter/log-path.ts';
import { loadCurrentPolicy } from './adapter/policy.ts';
import { withDispatcherLikeRun } from './adapter/run.ts';
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
 * `bouncer ping` — verifies that this process can read its account root and
 * build a dispatcher through the same baseline-retry path `run` uses.
 */
export async function runPing(): Promise<CommandResult> {
  try {
    await readdir(configDir());
  } catch (err) {
    // The ticket wants an unreadable config dir to surface here; run would
    // silently enforce the baseline.
    if ((err as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT') return { text: '', ok: false };
  }
  try {
    const loaded = await loadCurrentPolicy();
    await withDispatcherLikeRun(loaded, () => undefined);
    return { text: '', ok: true };
  } catch {
    return { text: '', ok: false };
  }
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
// ADR-0001 § Provenance: "lint: OK (overlay: common/policy.d/100-x.toml,
// profile/policy.toml)" — reads straight off LoadResult.layers, no
// `startsWith`/`replace` string surgery on `overlayFiles` (that would be
// re-deriving layer membership from a string this module didn't build).
// `<layer>: absent` when the root doesn't exist at all; `<layer>: 0
// files` when it exists but is empty — see LayerInfo's own comment for
// why those must stay two distinct states.
function overlayFileList(loaded: LoadResult): string {
  return loaded.layers
    .map((layer) => {
      if (layer.root === undefined) return `${layer.name}: absent`;
      if (layer.files.length === 0) return `${layer.name}: 0 files`;
      return layer.files.map((f) => `${layer.name}/${f}`).join(', ');
    })
    .join(', ');
}

export async function runRulesLint(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy();
  if (loaded.warnings.length === 0) {
    const suffix = loaded.overlayApplied ? `overlay: ${overlayFileList(loaded)}` : 'no overlay present — baseline only';
    return { text: `lint: OK (${suffix})`, ok: true };
  }
  // Names EVERY layer's root (not just the profile's) — a broken common-
  // layer file used to point the user at the profile paths only.
  const roots = loaded.layers.map((l) => `${l.name}: ${l.root ?? 'absent'}`).join(', ');
  // ADR-0001 § Rejection, per layer: which layer(s) actually survive the
  // load, not just which file(s) broke — a rejected profile next to a
  // healthy common still has common's rules and relaxations effective,
  // and this line is where that becomes visible without re-deriving it
  // from `warnings`' free text. `absent` mirrors the `roots` line above
  // (LayerInfo.root undefined, never merely zero files).
  const layerStates = loaded.layers
    .map((l) => {
      if (l.rejected !== undefined) return `${l.name}: rejected (${l.rejected.file})`;
      if (l.root === undefined) return `${l.name}: absent`;
      return `${l.name}: active (${l.files.length} files)`;
    })
    .join(', ');
  return {
    text: [`lint: FAILED (${roots})`, ...loaded.warnings.map((w) => `  - ${w}`), `  layers: ${layerStates}`].join('\n'),
    ok: false,
  };
}

// ADR-0001 § Provenance: an entry that won cross-layer precedence over an
// earlier layer's carries `shadows <earlier-layer-file>` — absent (and
// this suffix empty) for every other line, including every line loaded
// through loadPolicyFromOverlayFiles's one-layer case (nothing to shadow
// with only one layer in play).
function shadowsSuffix(shadows: string | undefined): string {
  return shadows !== undefined ? ` shadows ${shadows}` : '';
}

function ruleLine(entry: EffectiveRule): string {
  const suffix = entry.provenance === 'override'
    ? `override(${entry.overrideAction}) — ${entry.overrideReason}`
    : entry.provenance;
  // The source file only exists for overlay/override provenance — a
  // baseline rule has no file on disk to name, so `sourceFile` stays
  // absent and this suffix stays empty, leaving baseline lines unchanged.
  const fileSuffix = entry.sourceFile !== undefined ? ` [${entry.sourceFile}]` : '';
  return `rule ${entry.family} ${entry.rule.id} ${suffix}${fileSuffix}${shadowsSuffix(entry.shadows)}`;
}

function overrideLine(loaded: LoadResult): string[] {
  return loaded.activeOverrides.map(
    (o) => `override ${o.action} ${o.rule} — ${o.reason} [${o.sourceFile}]${shadowsSuffix(o.shadows)}`,
  );
}

// `[[relax]]` entries and a governed-sub git-conditional substitution both
// only ever widen the effective policy — surfaced with their own
// `overlay-relax` provenance (distinct from `override`, which can also
// disable/replace/relax an EXISTING rule) so a relaxed allowlist is exactly
// as impossible to overlook as an active override.
function relaxationLine(loaded: LoadResult): string[] {
  return loaded.activeRelaxations.map(
    (r) => `overlay-relax ${r.list} ${r.value} — ${r.reason} [${r.sourceFile}]${shadowsSuffix(r.shadows)}`,
  );
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
  readonly printCanary?: true;
  readonly error?: string;
}

/**
 * Pure parsing for `bouncer doctor [--settings <path>] [--print-canary]`'s
 * argv tail. `--settings` as the LAST token, or immediately followed by
 * another flag (`--settings --other-flag`), is a missing-argument error.
 */
export function parseDoctorArgs(rest: readonly string[]): ParsedDoctorArgs {
  const printCanary = rest.includes('--print-canary');
  const flagIndex = rest.indexOf('--settings');
  if (flagIndex === -1) return printCanary ? { printCanary: true } : {};
  const value = rest[flagIndex + 1];
  if (value === undefined || value.startsWith('--')) {
    return { error: '--settings requires a path argument' };
  }
  return { settingsPath: value, ...(printCanary ? { printCanary: true } : {}) };
}

/**
 * `bouncer doctor [--settings <path>]` — the manual, always-verbose
 * wiring/policy/log/override checklist.
 */
export async function runDoctor(settingsPath?: string): Promise<CommandResult> {
  const resolvedSettingsPath = settingsPath ?? defaultSettingsPath();
  const loaded = await loadCurrentPolicy();
  const report = await runDoctorChecks(resolvedSettingsPath, loaded);
  return { text: formatDoctorChecklist(report), ok: report.ok };
}

export type PrintCanaryResult =
  | { readonly text: string; readonly ok: true; readonly error?: undefined; }
  | { readonly text?: undefined; readonly ok: false; readonly error: string; };

/** `bouncer doctor --print-canary` — the printable canonical canary entry. */
export async function runPrintCanary(settingsPath?: string): Promise<PrintCanaryResult> {
  const result = await formatCanonicalCanaryEntry(settingsPath ?? defaultSettingsPath());
  return result.error === undefined
    ? { text: result.entry, ok: true }
    : { error: result.error, ok: false };
}

export interface AuditOptions {
  readonly days: number;
  readonly suggest: boolean;
  // Ticket 08: `bouncer audit --diff [--ts-logs <dir>]`. `diff` and
  // `suggest` are mutually exclusive modes (parseAuditArgs rejects
  // combining them) — a report comparing against the TS generation and a
  // policy-relaxation suggestion loop answer different questions and have
  // nothing to compose into.
  readonly diff: boolean;
  // Overrides the TS generation's config dir (default: the SAME config
  // dir bouncer itself uses). This is a CONFIG dir, not the logs/hooks
  // directory directly —
  // runAuditDiff appends logs/hooks/<guard>.log itself, same layout
  // src/adapter/log-path.ts's hookLogPath uses for bouncer's own log.
  readonly tsLogsDir?: string;
}

// Same error-protocol shape as ParsedDoctorArgs (return, never throw, so
// cli.ts never needs a try/catch around parsing): a discriminated union
// rather than two independent optionals, because `options` genuinely IS
// required whenever there is no `error` (unlike ParsedDoctorArgs's
// settingsPath, which is legitimately optional even on success) — this
// lets `parsed.options` narrow to defined after the `error` check with no
// non-null assertion needed.
export type ParsedAuditArgs =
  | { readonly options: AuditOptions; readonly error?: undefined; }
  | { readonly options?: undefined; readonly error: string; };

const DEFAULT_AUDIT_DAYS = 30;
const KNOWN_AUDIT_FLAGS: ReadonlySet<string> = new Set(['--suggest', '--days', '--diff', '--ts-logs']);

/**
 * Parses `audit`'s own flags (`--days N`, `--suggest`, `--diff`,
 * `--ts-logs <dir>`) — deliberately tiny rather than pulling in a general
 * arg-parsing dependency for one subcommand. An unrecognized token
 * (`--sugest`, `--dayz`, a stray positional, ...) is an explicit error, not
 * silently ignored — a typo'd flag must not fall through to "30-day report,
 * exit 0" as if nothing had been asked for. `--diff`/`--suggest` are
 * mutually exclusive, and `--ts-logs` only makes sense alongside `--diff`.
 */
export function parseAuditArgs(rest: readonly string[]): ParsedAuditArgs {
  let days = DEFAULT_AUDIT_DAYS;
  let suggest = false;
  let diff = false;
  let tsLogsDir: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (arg === '--suggest') {
      suggest = true;
      continue;
    }
    if (arg === '--diff') {
      diff = true;
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
    if (arg === '--ts-logs') {
      const value = rest[i + 1];
      if (value === undefined || value.startsWith('--')) {
        return { error: 'audit: --ts-logs requires a directory argument' };
      }
      tsLogsDir = value;
      i++;
      continue;
    }
    if (!KNOWN_AUDIT_FLAGS.has(arg)) {
      return {
        error: `audit: unrecognized argument ${JSON.stringify(arg)} `
          + `(expected: --days <n> | --suggest | --diff [--ts-logs <dir>])`,
      };
    }
  }
  if (diff && suggest) {
    return { error: 'audit: --diff and --suggest are mutually exclusive' };
  }
  if (tsLogsDir !== undefined && !diff) {
    return { error: 'audit: --ts-logs requires --diff' };
  }
  return { options: { days, suggest, diff, ...(tsLogsDir !== undefined ? { tsLogsDir } : {}) } };
}

/**
 * `bouncer audit --diff [--ts-logs <dir>]` (ticket 08, code-only scope):
 * compares bouncer's shadow-mode log entries against the TS generation's
 * four independent guard logs over the last `--days` days, reporting the
 * three divergence kinds src/adapter/audit-diff.ts classifies. Read-only —
 * this writes nothing anywhere, on either side. A missing TS log file
 * (ENOENT — a guard that has never fired, or hasn't been wired at all) is
 * "no entries from that file", not a failure; an existing-but-unreadable
 * one surfaces its own `warning:` line, same discipline runAudit's own
 * bouncer-log read already uses.
 */
async function runAuditDiff(options: AuditOptions): Promise<CommandResult> {
  let bouncerLogText = '';
  let bouncerLogWarning: string | null = null;
  try {
    bouncerLogText = await readFile(hookLogPath(HOOK_NAME), 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code !== 'ENOENT') {
      const message = err instanceof Error ? err.message : String(err);
      bouncerLogWarning = `bouncer audit log unreadable: ${message}`;
    }
  }
  const bouncerEntries = parseLogEntries(bouncerLogText);

  const tsLogsDir = options.tsLogsDir ?? configDir();
  const tsWarnings: string[] = [];
  const tsEntries: TsLogEntry[] = [];
  let tsIgnoredLineCount = 0;
  for (const filename of TS_GUARD_LOG_FILES) {
    const filePath = join(tsLogsDir, 'logs', 'hooks', filename);
    try {
      // oxlint-disable-next-line no-await-in-loop
      const text = await readFile(filePath, 'utf8');
      const parsed = parseTsLogEntries(text);
      tsEntries.push(...parsed.entries);
      tsIgnoredLineCount += parsed.ignoredLineCount;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code !== 'ENOENT') {
        const message = err instanceof Error ? err.message : String(err);
        tsWarnings.push(`${filePath} unreadable: ${message}`);
      }
    }
  }

  const diffResult = diffLogs(tsEntries, bouncerEntries, options.days);
  const clusters = clusterDivergences(diffResult.divergences);
  const text = renderDiffReport(clusters, {
    days: options.days,
    tsEventCount: diffResult.tsEventCount,
    shadowEntryCount: diffResult.shadowEntryCount,
    matchedCount: diffResult.matchedCount,
    tsIgnoredLineCount,
  });

  const warningLines = [
    ...(bouncerLogWarning !== null ? [`warning: ${bouncerLogWarning}`] : []),
    ...tsWarnings.map((w) => `warning: ${w}`),
  ];
  return { text: [...warningLines, text].join('\n'), ok: true };
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
  if (options.diff) return runAuditDiff(options);

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
