// The non-`run` CLI subcommands: `check`, `rules lint`, `rules list`,
// `doctor`, `audit`, `harness list`. Each returns the text to print plus
// whether it counts as a success (for the exit code) — kept separate from
// process.exit/console.log so these are unit-testable without spawning a
// subprocess. `--harness <id>` (default `claude-code`) is threaded through
// `check`/`doctor`/`audit`, exactly as `run` (ADR-0006 § 9).

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { clusterDivergences, diffWindowedLogs, parseTsLogEntries, renderDiffReport, TS_GUARD_LOG_FILES } from './adapter/audit-diff.ts';
import type { TsLogEntry } from './adapter/audit-diff.ts';
import {
  clusterEntries,
  filterSessionEntries,
  findDeadConditionalRules,
  parseLogEntries,
  renderReport,
  renderSuggestions,
  withinWindow,
} from './adapter/audit.ts';
import { wiringCodecFor } from './adapter/codecs/wiring/registry.ts';
import { DEFAULT_HARNESS_ID, HOOK_NAME } from './adapter/constants.ts';
import { degradePreToolUseVerdict } from './adapter/degrade.ts';
import { createDispatcher } from './adapter/dispatch.ts';
import { formatDoctorChecklist, harnessAnnouncementLine, runDoctorChecks } from './adapter/doctor.ts';
import { configDirFor, hookLogPathFor } from './adapter/log-path.ts';
import { buildCommandInputBag, buildNeutralCall } from './adapter/neutral-call.ts';
import { loadCurrentPolicy } from './adapter/policy.ts';
import { withDispatcherLikeRun } from './adapter/run.ts';
import { BASELINE } from './policy/baseline.ts';
import { resolvableRuleIds } from './policy/lint.ts';
import type { EffectiveRule, LoadResult } from './policy/load.ts';
import type { HarnessDeclaration, HarnessProtocol } from './policy/schema.ts';

export interface CommandResult {
  readonly text: string;
  readonly ok: boolean;
}

// The claude-code baseline declaration is always embedded (no I/O) —
// `ping` never takes `--harness`, so it always routes through this one.
const CLAUDE_CODE_BASELINE_HARNESS: HarnessDeclaration = BASELINE.rules.harness.find((h) => h.id === DEFAULT_HARNESS_ID)!;

function unknownHarnessResult(harnessId: string): CommandResult {
  return { text: `bouncer: harness ${JSON.stringify(harnessId)} is not declared`, ok: false };
}

function noProtocolResult(harnessId: string): CommandResult {
  return { text: `bouncer: harness ${JSON.stringify(harnessId)} has no usable protocol declaration`, ok: false };
}

export interface ParsedHarnessFlag {
  readonly harness?: string;
  readonly rest: readonly string[];
  readonly error?: string;
}

// Review round 1 S-5: `--harness <id>` was parsed three times (cli.ts's
// `run`/`check`, and inline in parseDoctorArgs/parseAuditArgs below) —
// one extraction, one error message. Same missing-argument protocol
// `--settings`/`--days`/every other valued flag in this codebase uses:
// absent value, or a following flag, is an explicit error, never a
// silent "value is the next flag's name". Returns `rest` with both the
// flag and its value spliced out, so the caller's own remaining-argument
// handling (the shadow/unrecognized-token scan for `run`, the joined
// command string for `check`, the rest of `parseDoctorArgs`/
// `parseAuditArgs`'s own flags) never sees them. The error message
// itself carries NO subcommand prefix — `parseDoctorArgs` uses it as-is
// (matching `--settings`'s own unprefixed error there); `parseAuditArgs`
// prepends its own `audit: ` (matching every other error in that
// function).
export function extractHarnessFlag(argv: readonly string[]): ParsedHarnessFlag {
  const index = argv.indexOf('--harness');
  if (index === -1) return { rest: argv };
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    return { rest: argv, error: '--harness requires a value argument' };
  }
  return { harness: value, rest: argv.filter((_, i) => i !== index && i !== index + 1) };
}

// Review round 3 R3-2: `check` used to look up a tool row literally named
// `"Bash"` — worked for claude-code (and codex, by coincidence, once
// 15b lands it), but breaks for any harness whose command tool has a
// different name (pi-agent's `bash`, 15c). `check` has no ONE call to
// dry-run against; it needs A representative command-shaped row, so it
// takes the harness's own FIRST one, in declaration order — the same
// "first row wins" convention `[harness.protocol.tools]` documents for
// exact-vs-glob matching, applied here to picking among exact rows. A
// row with no `command` selector at all (legal — lint never requires
// one, ADR-0006 § 3 leaves every selector optional per row) has nowhere
// to place a dry-run string, so it is skipped in favor of the next
// `role = "command"` row that DOES declare one; a harness with none
// usable is the same "no row to check against" error as no row at all.
function firstCommandTool(protocol: HarnessProtocol): { readonly name: string; readonly selector: string; } | undefined {
  for (const [name, row] of Object.entries(protocol.tools)) {
    if (row.role === 'command' && row.command !== undefined) return { name, selector: row.command };
  }
  return undefined;
}

/**
 * `bouncer check "<command>" [--harness <id>]` — dry-runs a Bash-shaped
 * command against the effective (baseline + account overlay) policy and
 * prints the verdict it would produce, without a live session. Reproduces
 * the PreToolUse dispatch exactly (so a command that also trips the
 * secret family, say, is reported faithfully) rather than command-family-
 * only. `check` appends ` → <action> (<id>)` when the degraded action's
 * name differs from the abstract verdict's (ADR-0006 § 9). Dispatched
 * through the harness's OWN first `role = "command"` tool row (review
 * round 3 R3-2), with the command string placed at THAT row's own
 * `command` selector (review round 4 R4-1 — a hardcoded `{ command }`
 * input bag only worked for a row whose selector happened to be named
 * `command`; any other selector name silently dry-ran against an empty
 * call and reported `allow` for everything, the worst possible answer).
 */
export async function runCheck(command: string, harnessId: string = DEFAULT_HARNESS_ID): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy(harnessId);
  if (loaded.harness === undefined) return unknownHarnessResult(harnessId);
  const protocol = loaded.harness.protocol;
  if (protocol === undefined) return noProtocolResult(harnessId);

  const warningLines = loaded.warnings.map((w) => `warning: ${w}`);
  const tool = firstCommandTool(protocol);
  if (tool === undefined) {
    return {
      text: [...warningLines, `bouncer: harness ${JSON.stringify(harnessId)} declares no "role = \\"command\\"" tool row to check against`]
        .join('\n'),
      ok: false,
    };
  }

  const dispatcher = createDispatcher(loaded.policy);
  const call = buildNeutralCall(protocol, tool.name, buildCommandInputBag(tool.selector, command), null, HOOK_NAME);
  if (call === null) {
    // Unreachable by construction: tool.name was just read off an existing
    // protocol.tools row, so findToolRow (an exact match) always finds it.
    return {
      text: [
        ...warningLines,
        `bouncer: harness ${JSON.stringify(harnessId)} declares no ${JSON.stringify(tool.name)} tool row to check against`,
      ]
        .join('\n'),
      ok: false,
    };
  }

  const hit = await dispatcher.inspectPreToolUse(call);
  if (!hit) {
    return { text: [...warningLines, 'allow'].join('\n'), ok: true };
  }
  // block/confirm and deny/ask are disjoint vocabularies (ADR-0006 §4's
  // lint proves block only ever maps to "deny", confirm only to "deny" or
  // "ask") — the action name never equals the verdict name, so the
  // degraded action always earns the suffix.
  const action = degradePreToolUseVerdict(hit.verdict.verdict, protocol.output);
  const line = `${hit.verdict.verdict} [${hit.verdict.ruleId}] ${hit.verdict.reason} → ${action} (${harnessId})`;
  return { text: [...warningLines, line].join('\n'), ok: true };
}

/**
 * `bouncer ping` — verifies that this process can read its account root and
 * build a dispatcher through the same baseline-retry path `run` uses.
 * Always claude-code (`--harness` is not part of `ping`'s surface).
 */
export async function runPing(): Promise<CommandResult> {
  try {
    await readdir(configDirFor(CLAUDE_CODE_BASELINE_HARNESS));
  } catch (err) {
    // The ticket wants an unreadable config dir to surface here; run would
    // silently enforce the baseline.
    if ((err as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT') return { text: '', ok: false };
  }
  try {
    const loaded = await loadCurrentPolicy(DEFAULT_HARNESS_ID);
    await withDispatcherLikeRun(loaded, () => undefined);
    return { text: '', ok: true };
  } catch {
    return { text: '', ok: false };
  }
}

/**
 * `bouncer rules lint` — validates the account's current overlay set
 * (`policy.toml` plus every `policy.d/*.toml`/`harness.d/*.toml` file, if
 * any) against the RE2-like dialect and the
 * [[override]]/[[relax]]/`[harness.protocol]` resolution/reason/cross-
 * file-conflict rules. Non-zero exit on failure (unlike `run`, which must
 * always exit 0 for the hook protocol) — this is a validation command
 * meant to be scripted against. On success, names every file that was
 * actually merged in; on failure, the warning lines already name the
 * specific offending file. Scoped to claude-code's own profile, same as
 * before this ticket — `--harness` is not part of `rules lint`'s surface.
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
  const loaded = await loadCurrentPolicy(DEFAULT_HARNESS_ID);
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
  // A coalesced baseline harness row names every contributing overlay file;
  // a normal overlay/override still has exactly one sourceFile.
  const files = entry.sourceFiles ?? (entry.sourceFile === undefined ? [] : [entry.sourceFile]);
  const fileSuffix = files.map((file) => ` [${file}]`).join('');
  const harnessSuffix = entry.harnessId !== undefined ? ` [harness:${entry.harnessId}]` : '';
  return `rule ${entry.family} ${entry.rule.id} ${suffix}${fileSuffix}${harnessSuffix}${shadowsSuffix(entry.shadows)}`;
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
 * together in a summary line so a relaxed policy is impossible to overlook,
 * followed by one `harness` line per baseline or overlay-declared harness
 * (ADR-0006 § 5). Stable, greppable output: `^summary`, `^override`,
 * `^overlay-relax`, `^harness`, `^rule` prefixes.
 */
export async function runRulesList(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy(DEFAULT_HARNESS_ID);
  const overridesActive = loaded.activeOverrides.length + loaded.activeRelaxations.length;
  const lines = [
    `summary: ${loaded.effectiveRules.length} rules, ${overridesActive} overrides active`
    + (loaded.warnings.length > 0 ? `, ${loaded.warnings.length} warnings` : ''),
    ...loaded.warnings.map((w) => `warning: ${w}`),
    ...overrideLine(loaded),
    ...relaxationLine(loaded),
    ...overlayHarnessListLines(loaded),
    ...loaded.effectiveRules.map(ruleLine),
  ];
  return { text: lines.join('\n'), ok: true };
}

export interface ParsedDoctorArgs {
  readonly settingsPath?: string;
  readonly printCanary?: true;
  readonly harness?: string;
  readonly error?: string;
}

/**
 * Pure parsing for `bouncer doctor [--settings <path>] [--print-canary]
 * [--harness <id>]`'s argv tail. `--settings`/`--harness` as the LAST
 * token, or immediately followed by another flag, is a missing-argument
 * error — same protocol as `--settings` always used.
 */
export function parseDoctorArgs(rest: readonly string[]): ParsedDoctorArgs {
  const printCanary = rest.includes('--print-canary');
  const settingsIndex = rest.indexOf('--settings');
  const settingsValue = settingsIndex === -1 ? undefined : rest[settingsIndex + 1];
  if (settingsIndex !== -1 && (settingsValue === undefined || settingsValue.startsWith('--'))) {
    return { error: '--settings requires a path argument' };
  }
  const harnessFlag = extractHarnessFlag(rest);
  if (harnessFlag.error !== undefined) return { error: harnessFlag.error };
  return {
    ...(settingsValue !== undefined ? { settingsPath: settingsValue } : {}),
    ...(printCanary ? { printCanary: true } : {}),
    ...(harnessFlag.harness !== undefined ? { harness: harnessFlag.harness } : {}),
  };
}

/**
 * `bouncer doctor [--settings <path>] [--harness <id>]` — the manual,
 * always-verbose wiring/policy/log/override checklist for the target
 * harness (default `claude-code`).
 */
export async function runDoctor(settingsPath?: string, harnessId: string = DEFAULT_HARNESS_ID): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy(harnessId);
  if (loaded.harness === undefined) return unknownHarnessResult(harnessId);
  const report = await runDoctorChecks(settingsPath, loaded, loaded.harness);
  return { text: formatDoctorChecklist(report), ok: report.ok };
}

export type PrintCanaryResult =
  | { readonly text: string; readonly ok: true; readonly error?: undefined; }
  | { readonly text?: undefined; readonly ok: false; readonly error: string; };

/** `bouncer doctor --print-canary [--harness <id>]` — the printable canonical canary entry, via this harness's own wiring codec. */
export async function runPrintCanary(settingsPath?: string, harnessId: string = DEFAULT_HARNESS_ID): Promise<PrintCanaryResult> {
  const loaded = await loadCurrentPolicy(harnessId);
  if (loaded.harness === undefined) return { error: `harness ${JSON.stringify(harnessId)} is not declared`, ok: false };
  const protocol = loaded.harness.protocol;
  if (protocol === undefined) return { error: `harness ${JSON.stringify(harnessId)} has no usable protocol declaration`, ok: false };
  if (protocol.wiring === undefined) {
    return { error: `harness ${JSON.stringify(harnessId)} declares no wiring codec to print a canary entry for`, ok: false };
  }
  const codec = wiringCodecFor(protocol.wiring);
  if (codec === undefined) {
    return { error: `wiring codec ${JSON.stringify(protocol.wiring)} has no runtime implementation`, ok: false };
  }
  const result = await codec.formatCanonicalCanaryEntry(settingsPath, loaded.harness, protocol);
  return result.error === undefined
    ? { text: result.entry, ok: true }
    : { error: result.error, ok: false };
}

export interface AuditOptions {
  readonly days: number;
  // Omitting the flag preserves the complete audit, including direct CLI probes.
  readonly sessionsOnly?: boolean;
  readonly suggest: boolean;
  // Ticket 08: `bouncer audit --diff [--ts-logs <dir>]`. `diff` and
  // `suggest` are mutually exclusive modes (parseAuditArgs rejects
  // combining them) — a report comparing against the TS generation and a
  // policy-relaxation suggestion loop answer different questions and have
  // nothing to compose into.
  readonly diff: boolean;
  // Overrides the TS generation's config dir (default: the SAME config
  // dir bouncer itself uses). This is a CONFIG dir, not the logs/hooks
  // directory directly — runAuditDiff appends logs/hooks/<guard>.log
  // itself, same layout src/adapter/log-path.ts's hookLogPathFor uses for
  // bouncer's own log.
  readonly tsLogsDir?: string;
  // ADR-0006 § 9: `audit --harness <id>` resolves that harness's own log.
  readonly harness?: string;
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

function sessionFilterHeader(entryCount: number, excludedCliEntryCount: number, label?: string): string {
  const prefix = label === undefined ? '' : `${label}: `;
  return `${prefix}${entryCount} entries, ${excludedCliEntryCount} CLI entries excluded`;
}
const KNOWN_AUDIT_FLAGS: ReadonlySet<string> = new Set([
  '--suggest',
  '--days',
  '--diff',
  '--ts-logs',
  '--sessions-only',
]);

/**
 * Parses `audit`'s own flags (`--days N`, `--suggest`, `--diff`,
 * `--ts-logs <dir>`, `--sessions-only`, `--harness <id>`) — deliberately
 * tiny rather than pulling in a general arg-parsing dependency for one
 * subcommand. An unrecognized token (`--sugest`, `--dayz`, a stray
 * positional, ...) is an explicit error, not silently ignored — a typo'd
 * flag must not fall through to "30-day report, exit 0" as if nothing had
 * been asked for. `--diff`/`--suggest` are mutually exclusive, and
 * `--ts-logs` only makes sense alongside `--diff`. `--harness` is
 * extracted first, via the shared `extractHarnessFlag` (review round 1
 * S-5) — its own error carries no prefix, so it is added here to match
 * every other error this function returns.
 */
export function parseAuditArgs(rest: readonly string[]): ParsedAuditArgs {
  const harnessFlag = extractHarnessFlag(rest);
  if (harnessFlag.error !== undefined) return { error: `audit: ${harnessFlag.error}` };
  const harness = harnessFlag.harness ?? DEFAULT_HARNESS_ID;

  let days = DEFAULT_AUDIT_DAYS;
  let suggest = false;
  let diff = false;
  let tsLogsDir: string | undefined;
  let sessionsOnly = false;
  for (let i = 0; i < harnessFlag.rest.length; i++) {
    const arg = harnessFlag.rest[i]!;
    if (arg === '--suggest') {
      suggest = true;
      continue;
    }
    if (arg === '--diff') {
      diff = true;
      continue;
    }
    if (arg === '--sessions-only') {
      sessionsOnly = true;
      continue;
    }
    if (arg === '--days') {
      const value = harnessFlag.rest[i + 1];
      const parsed = value !== undefined ? Number(value) : Number.NaN;
      if (!Number.isFinite(parsed) || parsed <= 0) {
        return { error: `audit: --days requires a positive number, got ${JSON.stringify(value)}` };
      }
      days = parsed;
      i++;
      continue;
    }
    if (arg === '--ts-logs') {
      const value = harnessFlag.rest[i + 1];
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
          + `(expected: --days <n> | --sessions-only | --suggest | --diff [--ts-logs <dir>] | --harness <id>)`,
      };
    }
  }
  if (diff && suggest) {
    return { error: 'audit: --diff and --suggest are mutually exclusive' };
  }
  if (tsLogsDir !== undefined && !diff) {
    return { error: 'audit: --ts-logs requires --diff' };
  }
  return {
    options: {
      days,
      suggest,
      diff,
      harness,
      ...(tsLogsDir !== undefined ? { tsLogsDir } : {}),
      ...(sessionsOnly ? { sessionsOnly } : {}),
    },
  };
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
async function runAuditDiff(options: AuditOptions, harness: HarnessDeclaration): Promise<CommandResult> {
  let bouncerLogText = '';
  let bouncerLogWarning: string | null = null;
  try {
    bouncerLogText = await readFile(hookLogPathFor(harness, HOOK_NAME), 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code !== 'ENOENT') {
      const message = err instanceof Error ? err.message : String(err);
      bouncerLogWarning = `bouncer audit log unreadable: ${message}`;
    }
  }
  const bouncerEntries = parseLogEntries(bouncerLogText);

  const tsLogsDir = options.tsLogsDir ?? configDirFor(harness);
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

  const now = new Date();
  const bouncerShadowEntries = withinWindow(
    bouncerEntries.filter((entry) => entry.mode === 'shadow'),
    options.days,
    now,
  );
  const tsWindowEntries = withinWindow(tsEntries, options.days, now);
  const sessionFilteredBouncerEntries = options.sessionsOnly
    ? filterSessionEntries(bouncerShadowEntries)
    : null;
  const sessionFilteredTsEntries = options.sessionsOnly
    ? filterSessionEntries(tsWindowEntries)
    : null;
  const diffBouncerEntries = sessionFilteredBouncerEntries?.entries ?? bouncerShadowEntries;
  const diffTsEntries = sessionFilteredTsEntries?.entries ?? tsWindowEntries;
  const diffResult = diffWindowedLogs(diffTsEntries, diffBouncerEntries);
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
  const filterHeader = sessionFilteredBouncerEntries === null || sessionFilteredTsEntries === null
    ? []
    : [
      `${
        sessionFilterHeader(
          diffBouncerEntries.length,
          sessionFilteredBouncerEntries.excludedCliEntryCount,
          'bouncer shadow',
        )
      } · ${
        sessionFilterHeader(
          diffTsEntries.length,
          sessionFilteredTsEntries.excludedCliEntryCount,
          'TS',
        )
      }`,
    ];
  return { text: [...warningLines, ...filterHeader, text].join('\n'), ok: true };
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
  const harnessId = options.harness ?? DEFAULT_HARNESS_ID;
  const loaded = await loadCurrentPolicy(harnessId);
  if (loaded.harness === undefined) return unknownHarnessResult(harnessId);
  const harness = loaded.harness;

  if (options.diff) return runAuditDiff(options, harness);

  let logText = '';
  let logWarning: string | null = null;
  try {
    logText = await readFile(hookLogPathFor(harness, HOOK_NAME), 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code !== 'ENOENT') {
      const message = err instanceof Error ? err.message : String(err);
      logWarning = `audit log unreadable: ${message}`;
    }
  }
  const windowEntries = withinWindow(parseLogEntries(logText), options.days);
  const sessionFilteredEntries = options.sessionsOnly ? filterSessionEntries(windowEntries) : null;
  const entries = sessionFilteredEntries?.entries ?? windowEntries;
  const clusters = clusterEntries(entries);
  const filterHeader = sessionFilteredEntries === null
    ? []
    : [sessionFilterHeader(sessionFilteredEntries.entries.length, sessionFilteredEntries.excludedCliEntryCount)];

  if (options.suggest) {
    const resolvable = resolvableRuleIds(loaded.policy);
    const text = renderSuggestions(clusters, resolvable, { days: options.days });
    // `#`-commented: renderSuggestions's output is TOML meant to be pasted
    // straight into an overlay (AC3) — a bare `warning: ...` line ahead of
    // it would not parse as TOML and would corrupt that contract.
    const warningLines = logWarning !== null ? [`# warning: ${logWarning}`] : [];
    return { text: [...warningLines, ...filterHeader.map((header) => `# ${header}`), text].join('\n'), ok: true };
  }

  const firedObserveRuleIds = new Set(
    clusters.filter((c) => c.verdict === 'observe').map((c) => c.ruleId),
  );
  const deadRuleIds = findDeadConditionalRules(loaded.policy, firedObserveRuleIds);
  const text = renderReport(clusters, deadRuleIds, { days: options.days });
  const warningLines = logWarning !== null ? [`warning: ${logWarning}`] : [];
  return { text: [...warningLines, ...filterHeader, text].join('\n'), ok: true };
}

// ADR-0006 § 5/9: one greppable line per harness — src/adapter/doctor.ts's
// harnessAnnouncementLine (the same format `doctor`'s own checklist
// uses) is the one source. Two call sites, two different scopes:
// `harness list` (below) wants the FULL inventory, `rules list` wants
// only the harnesses an overlay actually declared or extended (ADR-0006
// § 5: "a harness declared or extended by an overlay is listed by `rules
// list`" — the plain six-baseline case lists none, same filter as
// `doctor`'s own checklist, review round 1 P-1).
function harnessListLines(loaded: LoadResult): string[] {
  return loaded.policy.harness.map((h) => harnessAnnouncementLine(h, loaded.effectiveRules));
}

function overlayHarnessListLines(loaded: LoadResult): string[] {
  return loaded.policy.harness
    .filter((h) => loaded.overlayHarnessIds.includes(h.id))
    .map((h) => harnessAnnouncementLine(h, loaded.effectiveRules));
}

/**
 * `bouncer harness list` — one greppable line per harness this account
 * knows about (ADR-0006 § 9): every baseline harness plus every id its
 * common layer declares or extends. Always the DEFAULT (claude-code)
 * account's own view — `harness list` itself takes no `--harness` (it
 * enumerates every harness, not one).
 */
export async function runHarnessList(): Promise<CommandResult> {
  const loaded = await loadCurrentPolicy(DEFAULT_HARNESS_ID);
  return { text: harnessListLines(loaded).join('\n'), ok: true };
}
