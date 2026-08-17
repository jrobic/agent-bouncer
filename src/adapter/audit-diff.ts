// Ticket 08 (shadow mode, code-only scope): `bouncer audit --diff`'s pure
// core — parses the TS generation's own JSONL log lines, correlates them
// against bouncer's shadow-mode entries (src/adapter/audit.ts's
// AuditEntry, filtered to `mode: "shadow"`), and classifies divergences
// into the three kinds decision 4 defines. No filesystem (src/cli-commands.ts's
// runAudit reads the log files and calls into this module); this module
// only ever sees strings and already-parsed entries, same discipline as
// audit.ts itself.
//
// TS log entry shape — read from
// ~/dotfiles/claude/hooks/_shared/lib.ts's logDeny (READ-ONLY
// reference, never modified): `{timestamp, session_id, tool_name,
// decision: "deny"|"ask", rule_id, target}`. No `family` field (each of
// the four guard files IS its own family), no `mode` field (the TS
// generation has no shadow concept), no `kind`-discriminated header/
// warning lines (logDeny is the only writer over there) — simpler than
// bouncer's own log by construction.
//
// Correlation is a HEURISTIC, not an exact match — there is no id shared
// between the two systems. It keys on (target, tool, timestamp within
// ±2s), stated explicitly in the rendered report so a reader never
// mistakes a heuristic pairing for a guaranteed one.
//
// KNOWN BLIND SPOT (measured, ticket 05's live demo, 2026-08-16): a tool
// call denied by settings.json's OWN `permissions` layer short-circuits
// BEFORE either guard chain's PreToolUse hooks ever run — neither bouncer
// NOR the TS generation ever sees it, on either side. A "0 divergence"
// report only covers traffic that REACHES the hooks; it says nothing
// about calls the permissions layer already stopped. Stated in the
// rendered report itself (renderDiffReport), not just here.

import { normalizeTarget, withinWindow } from './audit.ts';
import type { AuditEntry } from './audit.ts';
import type { VerdictKind } from '../types.ts';

// ─── TS log parsing ────────────────────────────────────────────────────

export interface TsLogEntry {
  readonly timestamp: string;
  readonly sessionId: string | null;
  readonly toolName: string | null;
  readonly decision: 'deny' | 'ask';
  readonly ruleId: string;
  readonly target: string;
}

export interface ParsedTsLog {
  readonly entries: readonly TsLogEntry[];
  // A line that is blank is not counted (nothing was ever there to parse)
  // — this counts only lines that FAILED to parse as JSON, or parsed but
  // don't carry the {rule_id, timestamp, decision: deny|ask} shape
  // isTsVerdictLine checks. Reported in the diff header (item 3, review
  // round on ticket 08) so a reader can tell "12 events, 0 ignored" apart
  // from "12 events, 400 ignored" — the second is a schema drift worth
  // investigating, not a healthy quiet log.
  readonly ignoredLineCount: number;
}

function isTsVerdictLine(raw: Record<string, unknown>): boolean {
  return typeof raw.rule_id === 'string'
    && typeof raw.timestamp === 'string'
    && (raw.decision === 'deny' || raw.decision === 'ask');
}

/**
 * Parses one TS guard log file's raw JSONL text. A corrupted or
 * unrecognized line is skipped rather than failing the whole parse — same
 * discipline as audit.ts's parseLogEntries, for the same reason (a log
 * spans months; one bad line must not blind the tool to every other one)
 * — but unlike parseLogEntries, the skip is COUNTED (`ignoredLineCount`),
 * since a diff that silently drops lines could quietly under-report the
 * TS side's own volume.
 */
export function parseTsLogEntries(text: string): ParsedTsLog {
  const entries: TsLogEntry[] = [];
  let ignoredLineCount = 0;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      ignoredLineCount += 1;
      continue;
    }
    if (!isTsVerdictLine(raw)) {
      ignoredLineCount += 1;
      continue;
    }
    entries.push({
      timestamp: raw.timestamp as string,
      sessionId: typeof raw.session_id === 'string' ? raw.session_id : null,
      toolName: typeof raw.tool_name === 'string' ? raw.tool_name : null,
      decision: raw.decision as 'deny' | 'ask',
      ruleId: raw.rule_id as string,
      target: typeof raw.target === 'string' ? raw.target : '',
    });
  }
  return { entries, ignoredLineCount };
}

// The four predecessor guard log filenames, each written by its own
// independently-registered TS hook. `write-secret` and `mcp-write` match
// bouncer's own family naming (ticket 06 ported these ids); the files
// themselves live at `<dir>/logs/hooks/<name>.log`, same layout as
// bouncer's own hookLogPath.
export const TS_GUARD_LOG_FILES: readonly string[] = [
  'guard-command.log',
  'guard-secret.log',
  'guard-write-secret.log',
  'guard-mcp-write.log',
];

// Two DISTINCT constants, deliberately not one reused for both jobs
// (review round on ticket 08: a single constant serving both the TS-side
// grouping gap AND the TS↔bouncer correlation window was flagged as
// double-duty, easy to accidentally tune one and silently affect the
// other). Both happen to be 2000ms today — that is a coincidence of the
// chosen default, not a reason to merge them back into one name.

// How close two TS log lines (same tool, same exact target) must be in
// time to count as the SAME real event (see groupIntoTsEvents below).
const TS_EVENT_GAP_MS = 2000;

// How close a TS event and a bouncer shadow entry must be in time to
// count as the SAME real event, once already matched on (tool, target)
// (see diffLogs below).
const CORRELATION_WINDOW_MS = 2000;

function withinTsWindow(entries: readonly TsLogEntry[], days: number, now: Date): TsLogEntry[] {
  const cutoff = now.getTime() - days * 24 * 60 * 60 * 1000;
  return entries.filter((e) => {
    const t = Date.parse(e.timestamp);
    return !Number.isNaN(t) && t >= cutoff;
  });
}

// ─── TS event grouping — severity-max across the 4 independent hooks ───

interface TsEvent {
  readonly toolName: string | null;
  readonly target: string;
  readonly timestamp: string;
  readonly decision: 'deny' | 'ask';
  readonly ruleIds: readonly string[];
}

function buildTsEvent(entries: readonly TsLogEntry[]): TsEvent {
  const first = entries[0]!;
  const decision: 'deny' | 'ask' = entries.some((e) => e.decision === 'deny') ? 'deny' : 'ask';
  return {
    toolName: first.toolName,
    target: first.target,
    timestamp: first.timestamp,
    decision,
    ruleIds: [...new Set(entries.map((e) => e.ruleId))],
  };
}

// Claude Code runs all three (soon: four, per-family) independently-
// registered TS hooks against the SAME real tool call — a single real
// event can produce SEVERAL TS log lines, one per file, each with its own
// decision. Grouping by (tool, exact target) THEN by time-PROXIMITY
// (gap-based: sorted, a new event starts whenever the gap since the
// previous entry in the same group exceeds TS_EVENT_GAP_MS) before
// correlating collapses them back into the ONE combined event severity-max
// dispatch (ticket 05) is meant to match — the strictest decision (deny >
// ask) among the group, every contributing rule id kept.
//
// Gap-based, NOT a fixed time bucket (`Math.floor(t / window)`): a fixed
// bucket silently SPLITS two lines that are genuinely close together but
// happen to straddle a bucket boundary (1999ms and 2001ms round-trip to
// DIFFERENT buckets despite being 2ms apart) — a phantom divergence the
// report's own "±2s" promise would then be lying about. Gap-based judges
// actual proximity, never boundary position.
//
// Exact target match, not audit.ts's normalizeTarget: a diff is hunting
// real divergences, so it wants the SHARPER match — normalizeTarget's
// looser folding is for friction clustering, a different job, used only
// for grouping already-classified divergences into report rows below.
// An entry with an unparseable timestamp is always its own isolated
// singleton event — proximity to neighbors cannot be judged without one
// (in practice this never fires: withinTsWindow, always run first, has
// already dropped every unparseable-timestamp entry — kept here as a
// defensive fallback for any future caller that skips that step).
function groupIntoTsEvents(entries: readonly TsLogEntry[]): TsEvent[] {
  const byTarget = new Map<string, TsLogEntry[]>();
  for (const e of entries) {
    // JSON-encoded, not space-joined: `target` is an arbitrary shell
    // command or path and can itself contain spaces — a plain join risks
    // exactly the lossy-key collision ticket 12's review caught in
    // src/policy/load.ts's crossFileConflicts (`${list} ${value}`).
    const key = JSON.stringify([e.toolName, e.target]);
    const group = byTarget.get(key) ?? [];
    group.push(e);
    byTarget.set(key, group);
  }

  const events: TsEvent[] = [];
  for (const group of byTarget.values()) {
    const sorted = [...group].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    let current: TsLogEntry[] = [];
    let lastValidTime: number | null = null;
    for (const e of sorted) {
      const t = Date.parse(e.timestamp);
      if (Number.isNaN(t)) {
        if (current.length > 0) events.push(buildTsEvent(current));
        events.push(buildTsEvent([e]));
        current = [];
        lastValidTime = null;
        continue;
      }
      const startsNewEvent = current.length > 0 && lastValidTime !== null && t - lastValidTime > TS_EVENT_GAP_MS;
      if (startsNewEvent) {
        events.push(buildTsEvent(current));
        current = [];
      }
      current.push(e);
      lastValidTime = t;
    }
    if (current.length > 0) events.push(buildTsEvent(current));
  }
  return events;
}

// ─── correlation & divergence classification ──────────────────────────

export type DiffDivergenceKind = 'bouncer-would-allow' | 'ts-allowed' | 'verdict-divergence';

export interface DiffDivergence {
  readonly kind: DiffDivergenceKind;
  readonly tsRuleIds: readonly string[];
  readonly bouncerRuleId: string | null;
  readonly tsDecision: 'deny' | 'ask' | null;
  readonly bouncerVerdict: VerdictKind | null;
  readonly toolName: string | null;
  readonly target: string;
  readonly timestamp: string;
}

// TS "deny"/"ask" is the only vocabulary the predecessor generation has —
// deny maps to bouncer's "block", ask to "confirm". Any OTHER bouncer
// verdict (observe, flag) can never be the "same bucket" as a TS deny/ask
// by construction: TS has no "silent but logged" concept, so a MATCHED
// bouncer "observe" against a TS deny/ask is always a real verdict
// divergence, never quietly treated as agreement.
function sameSemanticVerdict(tsDecision: 'deny' | 'ask', bouncerVerdict: VerdictKind): boolean {
  return (tsDecision === 'deny' && bouncerVerdict === 'block')
    || (tsDecision === 'ask' && bouncerVerdict === 'confirm');
}

const NON_SILENT_BOUNCER_VERDICTS: ReadonlySet<VerdictKind> = new Set(['block', 'confirm']);

// The volumes a cutover decision needs (the criterion is ≥500 GUARDED
// calls, ≥7 days, zero untriaged divergence — see the ticket) plus the
// matched count that makes "how much of this traffic actually correlated"
// legible at a glance. Reported in the diff header (renderDiffReport), not
// buried in a count the reader has to derive by re-adding cluster counts.
export interface DiffResult {
  readonly divergences: readonly DiffDivergence[];
  readonly tsEventCount: number;
  readonly shadowEntryCount: number;
  readonly matchedCount: number;
}

/**
 * The diff itself: TS-side entries (already read from all four guard
 * files, unlabeled by file — rule ids alone identify what fired) against
 * bouncer's own log entries (only ones with `mode: "shadow"` are
 * considered — a non-shadow entry was never meant to be compared against
 * a parallel TS run at all). Each bouncer shadow entry matches AT MOST one
 * TS event and vice versa (greedy, nearest-in-time-first), so nothing is
 * double-counted across both leftover passes.
 */
export function diffLogs(
  tsEntries: readonly TsLogEntry[],
  bouncerEntries: readonly AuditEntry[],
  days: number,
  now: Date = new Date(),
): DiffResult {
  const tsEvents = groupIntoTsEvents(withinTsWindow(tsEntries, days, now));
  const shadowEntries = withinWindow(bouncerEntries.filter((e) => e.mode === 'shadow'), days, now);

  const usedBouncer = new Set<number>();
  const divergences: DiffDivergence[] = [];

  for (const tsEvent of tsEvents) {
    const tsTime = Date.parse(tsEvent.timestamp);
    let matchIndex = -1;
    let matchDelta = Infinity;
    shadowEntries.forEach((be, i) => {
      if (usedBouncer.has(i)) return;
      if (be.toolName !== tsEvent.toolName) return;
      if (be.target !== tsEvent.target) return;
      const beTime = Date.parse(be.timestamp);
      const delta = Math.abs(beTime - tsTime);
      if (delta <= CORRELATION_WINDOW_MS && delta < matchDelta) {
        matchIndex = i;
        matchDelta = delta;
      }
    });

    if (matchIndex === -1) {
      divergences.push({
        kind: 'bouncer-would-allow',
        tsRuleIds: tsEvent.ruleIds,
        bouncerRuleId: null,
        tsDecision: tsEvent.decision,
        bouncerVerdict: null,
        toolName: tsEvent.toolName,
        target: tsEvent.target,
        timestamp: tsEvent.timestamp,
      });
      continue;
    }

    usedBouncer.add(matchIndex);
    const be = shadowEntries[matchIndex]!;
    if (!sameSemanticVerdict(tsEvent.decision, be.verdict)) {
      divergences.push({
        kind: 'verdict-divergence',
        tsRuleIds: tsEvent.ruleIds,
        bouncerRuleId: be.ruleId,
        tsDecision: tsEvent.decision,
        bouncerVerdict: be.verdict,
        toolName: tsEvent.toolName,
        target: tsEvent.target,
        timestamp: tsEvent.timestamp,
      });
    }
  }

  shadowEntries.forEach((be, i) => {
    if (usedBouncer.has(i)) return;
    // "observe"/"flag" are bouncer's OWN silent-allow verdicts — an
    // unmatched one agrees with a TS side that also allowed silently
    // (nothing logged there either), not a divergence to report.
    if (!NON_SILENT_BOUNCER_VERDICTS.has(be.verdict)) return;
    divergences.push({
      kind: 'ts-allowed',
      tsRuleIds: [],
      bouncerRuleId: be.ruleId,
      tsDecision: null,
      bouncerVerdict: be.verdict,
      toolName: be.toolName,
      target: be.target,
      timestamp: be.timestamp,
    });
  });

  return {
    divergences,
    tsEventCount: tsEvents.length,
    shadowEntryCount: shadowEntries.length,
    matchedCount: usedBouncer.size,
  };
}

// ─── pre-triaged "expected" families (ticket 08 § "Divergences attendues") ───

export interface ExpectedDivergenceFamily {
  readonly id: string;
  readonly ticketRef: string;
  readonly description: string;
  readonly matches: (d: DiffDivergence) => boolean;
}

// Three families, not four: severity-max combined dispatch (ticket 05) is
// explicitly a parity CLAIM TO MEASURE, not a known divergence — nothing
// to tag [expected], only a test proving no divergence occurs (see
// "severity-max parity" in tests/adapter-audit-diff.test.ts).

// Read-shaped tools only — a Bash-invoked DELETE of a guard-*.log file
// (e.g. `rm guard-command.log`) is a materially different, more severe
// action the guard-log-reads family was never about; see that family's
// own comment below.
const READ_SHAPED_TOOLS: ReadonlySet<string> = new Set(['Read', 'Grep', 'Glob']);

export const EXPECTED_DIVERGENCES: readonly ExpectedDivergenceFamily[] = [
  {
    id: 'pull-merge-ff-only-ask',
    ticketRef: 'ticket 13 (baseline universality triage)',
    description: 'git pull/merge --ff-only now ask unconditionally in the trunk (ff-only safety moved to the '
      + 'personal overlay) — the TS generation allowed this specific form silently. A BARE pull/merge (no '
      + '--ff-only at all) is a DIFFERENT, untagged divergence — ticket 13 hardened that too, but it deserves '
      + 'its own explicit triage, not a loose match riding in on this family\'s name.',
    matches: (d) => d.kind === 'ts-allowed'
      && d.bouncerRuleId === 'git-protected'
      && /^git\s+(pull|merge)\b/.test(d.target)
      && /--ff-only\b/.test(d.target),
  },
  {
    id: 'guard-log-reads',
    ticketRef: 'ticket 13 (baseline universality triage)',
    description: 'READS of the predecessor TS guards\' own log files (hook-log) via a read-shaped tool — expected '
      + 'specifically when the personal overlay is not installed for this diff run; install '
      + 'examples/personal-overlay.toml to close it. A bouncer rule firing on a NON-read access to the same '
      + 'path (a delete, a write) is a real, untagged divergence — hook-log covering more than reads was never '
      + 'the claim.',
    matches: (d) => d.kind === 'ts-allowed'
      && d.bouncerRuleId === null
      && d.toolName !== null
      && READ_SHAPED_TOOLS.has(d.toolName)
      && /guard-(command|secret|write-secret|mcp-write)\.log$/.test(d.target),
  },
  {
    id: 'transcripts-deny-to-confirm',
    ticketRef: 'ticket 13 (baseline universality triage, review round 2 arbitration)',
    description: 'transcript-backup softened from block to confirm, EXACTLY that direction — a legitimate direct '
      + 'read is asked about, not stopped outright. The reverse (bouncer weaker than confirm, or TS at "ask" '
      + 'instead of "deny") is never this family — a real divergence a loose match would otherwise hide.',
    matches: (d) => d.kind === 'verdict-divergence'
      && d.bouncerRuleId === 'transcript-backup'
      && d.tsDecision === 'deny'
      && d.bouncerVerdict === 'confirm',
  },
];

/** The first pre-triaged family a divergence matches, if any — a divergence
 * matching none of them is genuinely new and needs human triage. */
export function expectedFamilyOf(d: DiffDivergence): ExpectedDivergenceFamily | null {
  return EXPECTED_DIVERGENCES.find((f) => f.matches(d)) ?? null;
}

// ─── clustering & rendering ─────────────────────────────────────────────

export interface DiffCluster {
  readonly kind: DiffDivergenceKind;
  readonly tsRuleIds: readonly string[];
  readonly bouncerRuleId: string | null;
  readonly shape: string;
  readonly count: number;
  readonly lastSeen: string;
  readonly exampleTargets: readonly string[];
  readonly expected: ExpectedDivergenceFamily | null;
}

const MAX_DIFF_EXAMPLES = 3;

function byFrequencyThenRecency(a: DiffCluster, b: DiffCluster): number {
  if (b.count !== a.count) return b.count - a.count;
  return Date.parse(b.lastSeen) - Date.parse(a.lastSeen);
}

/** Groups divergences by (kind, TS rule ids, bouncer rule id, normalized
 * target shape) — audit.ts's own normalizeTarget, appropriate HERE (unlike
 * inside diffLogs) because this is purely a report-grouping concern, sorted
 * by frequency then recency, same discipline as audit.ts's clusterEntries. */
export function clusterDivergences(divergences: readonly DiffDivergence[]): DiffCluster[] {
  interface Building {
    kind: DiffDivergenceKind;
    tsRuleIds: string[];
    bouncerRuleId: string | null;
    shape: string;
    count: number;
    lastSeen: string;
    exampleTargets: string[];
    expected: ExpectedDivergenceFamily | null;
  }
  const byKey = new Map<string, Building>();
  for (const d of divergences) {
    const shape = normalizeTarget(d.target);
    const key = `${d.kind} ${d.tsRuleIds.join(',')} ${d.bouncerRuleId ?? ''} ${shape}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += 1;
      if (Date.parse(d.timestamp) > Date.parse(existing.lastSeen)) existing.lastSeen = d.timestamp;
      if (existing.exampleTargets.length < MAX_DIFF_EXAMPLES && !existing.exampleTargets.includes(d.target)) {
        existing.exampleTargets.push(d.target);
      }
    } else {
      byKey.set(key, {
        kind: d.kind,
        tsRuleIds: [...d.tsRuleIds],
        bouncerRuleId: d.bouncerRuleId,
        shape,
        count: 1,
        lastSeen: d.timestamp,
        exampleTargets: [d.target],
        expected: expectedFamilyOf(d),
      });
    }
  }
  return [...byKey.values()].sort(byFrequencyThenRecency);
}

export interface DiffReportOptions {
  readonly days: number;
  readonly tsEventCount: number;
  readonly shadowEntryCount: number;
  readonly matchedCount: number;
  readonly tsIgnoredLineCount: number;
}

function tsRuleIdsLabel(ids: readonly string[]): string {
  return ids.length > 0 ? ids.join('+') : '(none)';
}

const SECTIONS: readonly [DiffDivergenceKind, string][] = [
  ['bouncer-would-allow', 'TS denied/asked, bouncer would allow'],
  ['ts-allowed', 'bouncer would deny/ask, TS allowed'],
  ['verdict-divergence', 'matched, but verdicts differ'],
];

/**
 * Human report — free-form prose, rendered the same way as `audit`'s own
 * renderReport (audit.ts): three sections, one per divergence kind, each
 * cluster naming rule ids from BOTH sides, a count, and — when the shape
 * matches a pre-triaged family — an `[expected: ...]` tag citing the
 * ticket. The tag is informational, never a filter: every divergence still
 * appears, tagged or not, so the human triage step this exists to support
 * always sees the full picture.
 */
export function renderDiffReport(clusters: readonly DiffCluster[], options: DiffReportOptions): string {
  const lines: string[] = [];
  lines.push(`bouncer audit --diff — last ${options.days} day(s)`);
  lines.push(
    `TS: ${options.tsEventCount} event(s) (${options.tsIgnoredLineCount} line(s) ignored) `
      + `— bouncer shadow: ${options.shadowEntryCount} entries — matched: ${options.matchedCount}`,
  );
  lines.push('');
  lines.push(
    'Correlation is heuristic: (target, tool, timestamp within ±2s) — there is no shared id between bouncer '
      + 'and the TS generation, so this is best-effort pairing, not a guarantee.',
  );
  lines.push(
    'Known blind spot (measured, ticket 05\'s live demo): a call denied by settings.json\'s own `permissions` '
      + 'layer never reaches either guard chain\'s hooks — invisible to BOTH sides. "0 divergence" only covers '
      + 'traffic that REACHES the hooks, not traffic permissions already stopped.',
  );

  for (const [kind, heading] of SECTIONS) {
    lines.push('');
    lines.push(`## ${heading}`);
    const inSection = clusters.filter((c) => c.kind === kind);
    if (inSection.length === 0) {
      lines.push('(none)');
      continue;
    }
    for (const c of inSection) {
      const expectedTag = c.expected !== null ? ` [expected: ${c.expected.id} — ${c.expected.ticketRef}]` : '';
      lines.push(
        `- ts=${tsRuleIdsLabel(c.tsRuleIds)} bouncer=${c.bouncerRuleId ?? '(none)'} `
          + `fired ${c.count}x on shape "${c.shape}" (last: ${c.lastSeen})${expectedTag}`,
      );
      for (const example of c.exampleTargets) lines.push(`    e.g. ${example}`);
    }
  }
  return lines.join('\n');
}
