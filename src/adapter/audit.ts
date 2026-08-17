// Audit: the proactive rule-tuning loop (ticket 10, spec User Stories 9-11).
// Parses already-read JSONL log TEXT (see src/adapter/log.ts for the entry
// shape this reads back) and an already-loaded RulesPolicy's git-conditional
// tables, and produces:
//   - clustering of deny/ask (block/confirm) AND conditional-allow (observe)
//     entries by rule id x normalized target shape, over a time window
//   - a report: frequent-friction candidates + dead conditional rules (a
//     declarative git-conditional table entry that never produced an
//     observe verdict in the window)
//   - `--suggest`: candidate `[[relax]]`/`[[override]]` TOML snippets — text
//     only, never applied (Out of Scope: "Auto-application of `audit
//     --suggest` output — human gate, always")
//
// Pure — no filesystem, no Bun/Node I/O. The CLI command
// (src/cli-commands.ts's runAudit) reads the log file and the current
// policy off disk and calls into this module; this module only ever sees
// strings and already-loaded data structures.

import { extractGitSubcommand } from '../command-rules.ts';
import type { RelaxableList, RulesPolicy } from '../policy/schema.ts';
import type { VerdictKind } from '../types.ts';

// ─── parsing ───────────────────────────────────────────────────────────

export interface AuditEntry {
  readonly timestamp: string;
  readonly sessionId: string | null;
  readonly toolName: string | null;
  readonly family: string;
  readonly verdict: VerdictKind;
  readonly ruleId: string;
  readonly target: string;
  // Ticket 08: present (always "shadow") only on an entry `run --shadow`
  // produced — src/adapter/log.ts's LogMode. Absent on every entry logged
  // outside a shadow invocation; audit-diff.ts filters on this to compare
  // ONLY shadow-window entries against the TS generation's logs.
  readonly mode?: 'shadow';
}

// The sole discriminator between a verdict line and the other two shapes
// src/adapter/log.ts writes to the same file (`kind: "audit-header"` /
// `kind: "policy-warning"`, neither of which carries rule_id/verdict/
// family) — matches logVerdict's appendLogEntry call exactly.
function isVerdictLine(raw: Record<string, unknown>): boolean {
  return typeof raw.rule_id === 'string' && typeof raw.verdict === 'string' && typeof raw.family === 'string';
}

/**
 * Parses raw JSONL log text into verdict entries only — audit-header and
 * policy-warning lines are silently skipped (they carry no rule_id/target
 * to cluster on), and a corrupted line is skipped rather than failing the
 * whole audit (an audit log spans months; one truncated line from a crash
 * mid-write must not blind the tool to every other line).
 */
export function parseLogEntries(text: string): AuditEntry[] {
  const entries: AuditEntry[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!isVerdictLine(raw)) continue;
    entries.push({
      timestamp: typeof raw.timestamp === 'string' ? raw.timestamp : '',
      sessionId: typeof raw.session_id === 'string' ? raw.session_id : null,
      toolName: typeof raw.tool_name === 'string' ? raw.tool_name : null,
      family: raw.family as string,
      verdict: raw.verdict as VerdictKind,
      ruleId: raw.rule_id as string,
      target: typeof raw.target === 'string' ? raw.target : '',
      ...(raw.mode === 'shadow' ? { mode: 'shadow' as const } : {}),
    });
  }
  return entries;
}

/** Keeps only entries whose timestamp falls within the last `days` days of
 * `now` (defaults to the real current time). An unparseable timestamp is
 * dropped, not kept — a corrupt date must not silently count as "recent". */
export function withinWindow(entries: readonly AuditEntry[], days: number, now: Date = new Date()): AuditEntry[] {
  const cutoff = now.getTime() - days * 24 * 60 * 60 * 1000;
  return entries.filter((e) => {
    const t = Date.parse(e.timestamp);
    return !Number.isNaN(t) && t >= cutoff;
  });
}

// ─── target normalization ─────────────────────────────────────────────
//
// A heuristic, not a parser: shape-match individual tokens, plus one
// position-based rule for multi-word (command-shaped) targets. Good enough
// to group friction ("git push origin main" / "git push origin feature-x"
// are the same shape); not meant to be exact. Known limits, deliberately
// not chased further (mirrors command-rules.ts's own "known limits"
// discipline):
//   - a wrapped command (`rtk git push origin main`, `env X=Y git push
//     origin main`) shifts the subcommand out of position 1, so its
//     trailing positionals collapse one token later than a bare `git push`
//     — under-normalizes rather than over-normalizes, so at worst two
//     really-identical shapes stay in separate clusters.
//   - a path's basename is only collapsed when the WHOLE target is exactly
//     `name.ext` (no `/`); `~/project-a/.env` and `~/project-b/.env` stay
//     distinct clusters after the home-prefix collapse.

const HOME_PREFIX = /^(\/Users\/[^/]+|\/home\/[^/]+)(\/|$)/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_HASH = /^[0-9a-f]{7,40}$/i;
const NUMBER = /^\d+$/;
const FILENAME_WITH_EXT = /^[\w-]+\.[A-Za-z0-9]{1,8}$/;

function shapeOfToken(token: string): string {
  const home = token.match(HOME_PREFIX);
  if (home) return `~${token.slice(home[1]!.length)}`;
  if (UUID.test(token)) return '<uuid>';
  if (HEX_HASH.test(token)) return '<hash>';
  if (NUMBER.test(token)) return '<n>';
  if (FILENAME_WITH_EXT.test(token)) return '<file>';
  return token;
}

/**
 * Normalizes a Verdict target into a coarse "shape" for clustering. Per
 * token: collapse a home-directory prefix, a hash/UUID/number, or a bare
 * `name.ext` file to a placeholder. For a multi-word (command-shaped)
 * target, ALSO collapse every remaining positional (non-flag) token from
 * index 2 onward to `<arg>` — beyond "command subcommand", the rest of a
 * command line is almost always the variable part (a branch, a remote, a
 * ref), which is what lets `git push origin main` and `git push origin
 * feature-x` cluster under one shape.
 */
export function normalizeTarget(target: string): string {
  const tokens = target.split(/\s+/).filter((t) => t !== '');
  if (tokens.length === 0) return target;
  const multiToken = tokens.length > 1;
  const shaped = tokens.map((token, i) => {
    const s = shapeOfToken(token);
    if (s !== token) return s;
    if (multiToken && i >= 2 && !token.startsWith('-')) return '<arg>';
    return token;
  });
  return shaped.join(' ');
}

// ─── clustering ────────────────────────────────────────────────────────

/**
 * `verdict` and `family` are FIRST-SEEN, not latest-seen: clusterEntries
 * sets them from the first log entry it encounters for a given rule id x
 * shape key and never updates them again as more entries join the same
 * cluster (only `count`/`lastSeen`/`exampleTargets` accumulate). A rule
 * whose verdict changed mid-window (an override applied partway through,
 * flipping block -> confirm for the same shape) is reported under its
 * FIRST verdict for the whole window — stale by construction, not a bug to
 * fix quietly. Accurate reporting of a mid-window verdict change would need
 * per-entry verdict tracking this module does not do.
 */
export interface Cluster {
  readonly ruleId: string;
  readonly family: string;
  readonly verdict: VerdictKind;
  readonly shape: string;
  readonly count: number;
  readonly lastSeen: string;
  readonly exampleTargets: readonly string[];
}

const MAX_EXAMPLE_TARGETS = 3;

function byFrequencyThenRecency(a: Cluster, b: Cluster): number {
  if (b.count !== a.count) return b.count - a.count;
  return Date.parse(b.lastSeen) - Date.parse(a.lastSeen);
}

/** Groups entries by rule id x normalized target shape, sorted by
 * frequency (desc) then recency (desc) — the report's own sort order, so
 * every caller sees the same ranking. */
export function clusterEntries(entries: readonly AuditEntry[]): Cluster[] {
  interface Building {
    ruleId: string;
    family: string;
    verdict: VerdictKind;
    shape: string;
    count: number;
    lastSeen: string;
    exampleTargets: string[];
  }
  const byKey = new Map<string, Building>();
  for (const e of entries) {
    const shape = normalizeTarget(e.target);
    const key = `${e.ruleId} ${shape}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += 1;
      if (Date.parse(e.timestamp) > Date.parse(existing.lastSeen)) existing.lastSeen = e.timestamp;
      if (existing.exampleTargets.length < MAX_EXAMPLE_TARGETS && !existing.exampleTargets.includes(e.target)) {
        existing.exampleTargets.push(e.target);
      }
    } else {
      byKey.set(key, {
        ruleId: e.ruleId,
        family: e.family,
        verdict: e.verdict,
        shape,
        count: 1,
        lastSeen: e.timestamp,
        exampleTargets: [e.target],
      });
    }
  }
  return [...byKey.values()].sort(byFrequencyThenRecency);
}

// ─── dead conditional rules ────────────────────────────────────────────

/** Every `git-conditional-<sub>` id the given git policy can EVER produce —
 * the three declarative tables (each entry can fire an observe verdict for
 * its `sub`) plus the two engine-escape names (checkout/restore, which
 * classifyGitAllowWith in src/command-rules.ts treats identically to a
 * table-driven conditional). Unconditionally-safe subcommands
 * (safe_subcommands) never produce an observe verdict at all — allowed
 * silently, nothing to log or audit — so they are deliberately absent
 * here. */
export function conditionalRuleIdsOf(git: RulesPolicy['command']['git']): string[] {
  const subs = new Set<string>([
    ...git.ask_flags.map((r) => r.sub),
    ...git.safe_first_arg.map((r) => r.sub),
    ...git.safe_grammar.map((r) => r.sub),
    'checkout',
    'restore',
  ]);
  return [...subs].map((sub) => `git-conditional-${sub}`);
}

/** Every conditional rule id of `policy` that is NOT in `firedRuleIds` — a
 * declarative (or engine-escape) git conditional that never produced an
 * observe verdict in the audited window. */
export function findDeadConditionalRules(
  policy: RulesPolicy,
  firedRuleIds: ReadonlySet<string>,
): string[] {
  return conditionalRuleIdsOf(policy.command.git).filter((id) => !firedRuleIds.has(id));
}

// ─── report rendering ──────────────────────────────────────────────────

export interface AuditReportOptions {
  readonly days: number;
}

const FRICTION_VERDICTS: ReadonlySet<VerdictKind> = new Set(['block', 'confirm']);

// clusterEntries already returns its result sorted by frequency (desc) then
// recency (desc) — a plain .filter() preserves that relative order (filter
// never reorders), so re-sorting the filtered subset here would be sorting
// an already-sorted list. No .sort() call needed or present.
function frictionClustersOf(clusters: readonly Cluster[]): Cluster[] {
  return clusters.filter((c) => FRICTION_VERDICTS.has(c.verdict));
}

function firedConditionalClustersOf(clusters: readonly Cluster[]): Cluster[] {
  return clusters.filter((c) => c.verdict === 'observe');
}

/**
 * Human report — free-form prose meant to be READ, not grepped. Contrast
 * `rules list` (src/cli-commands.ts): that output is a stable, documented,
 * greppable contract (`^summary`, `^rule`, ... prefixes another tool can
 * script against); this one is not, and its wording may change between
 * versions without that counting as a breaking change.
 *
 * Three sections, in order: frequent friction (deny/ask clusters — allow-
 * list candidates), conditional rules that fired (an observe-verdict
 * cluster — a declarative git-conditional table entry earning its keep,
 * Story 10), and dead conditional rules (declared but never fired in the
 * window — an allow rule with nothing to allow).
 */
export function renderReport(
  clusters: readonly Cluster[],
  deadRuleIds: readonly string[],
  options: AuditReportOptions,
): string {
  const friction = frictionClustersOf(clusters);
  const fired = firedConditionalClustersOf(clusters);
  const lines: string[] = [];
  lines.push(`bouncer audit — last ${options.days} day(s)`);
  lines.push('');
  lines.push('## Frequent friction (deny/ask — allowlist candidates?)');
  if (friction.length === 0) {
    lines.push('(none — no deny/ask entries in this window)');
  } else {
    for (const c of friction) {
      lines.push(`- [${c.ruleId}] fired ${c.count}x on shape "${c.shape}" (last: ${c.lastSeen}) — allowlist candidate?`);
      for (const example of c.exampleTargets) lines.push(`    e.g. ${example}`);
    }
  }
  lines.push('');
  lines.push('## Conditional rules that fired (earning their keep)');
  if (fired.length === 0) {
    lines.push('(none — no conditional-allow entries in this window)');
  } else {
    for (const c of fired) {
      lines.push(`- ${c.ruleId} fired ${c.count}x (last: ${c.lastSeen})`);
    }
  }
  lines.push('');
  lines.push('## Dead conditional rules (never fired in this window)');
  if (deadRuleIds.length === 0) {
    lines.push('(none — every conditional rule fired at least once)');
  } else {
    for (const id of deadRuleIds) lines.push(`- ${id}`);
  }
  return lines.join('\n');
}

// ─── --suggest: candidate TOML snippets ───────────────────────────────
//
// Every suggestion carries an auto-filled `reason` citing the audit
// evidence (count, shape, window) so the OUTPUT ITSELF is valid TOML that
// `rules lint` accepts as-is (AC3) — "fill in a reason" is the human's
// review step, not a requirement for the snippet to parse. A rule id with
// no policy lever (rm-rf-dangerous, sudo, mcp-write's own target string
// beyond its prefix, and any `git-conditional-*` id — none of these are
// resolvable via [[override]], and only three lists accept [[relax]], see
// policy/schema.ts's RelaxableList) gets a plain `#` comment instead of a
// fabricated, lint-rejected snippet.

type SuggestionAction =
  | { readonly kind: 'relax'; readonly list: RelaxableList; readonly value: string }
  | { readonly kind: 'override'; readonly rule: string; readonly verdict: VerdictKind }
  | { readonly kind: 'none' };

// Mirrors mcp-write-rules.ts's MCP_TOOL_NAME split (non-greedy up to the
// SECOND `__`) — duplicated here deliberately: this is a suggestion-text
// helper, not a security decision, and importing the security module's
// private regex would couple a display concern to an enforcement one.
// tests/adapter-audit.test.ts carries a drift test comparing this against
// the real module's behavior on representative tool names.
export const MCP_TOOL_NAME = /^mcp__.+?__(.+)$/;

// The two rule ids `--suggest` knows a [[relax]] lever for, and where that
// lever's `value` comes from — extracted to a constant (rather than two
// inline `if (cluster.ruleId === '...')` branches) so the mapping is one
// place to read, and its `list` field is typed RelaxableList so a rename
// in policy/schema.ts's own union is a compile error here, not a silent
// drift; tests/adapter-audit.test.ts additionally asserts every `list`
// here is a member of the runtime RELAXABLE_LISTS companion (schema.ts can
// grow a new list without this table's typing alone catching a stale
// three-way split).
export interface RelaxLever {
  readonly ruleId: string;
  readonly list: RelaxableList;
  readonly extractValue: (exampleTarget: string) => string | undefined;
}

export const RELAX_LEVERS: readonly RelaxLever[] = [
  {
    ruleId: 'git-protected',
    list: 'command.git.safe_subcommands',
    extractValue: (raw) => extractGitSubcommand(raw)?.sub,
  },
  {
    ruleId: 'mcp-write',
    list: 'mcp_write.read_prefixes',
    extractValue: (raw) => MCP_TOOL_NAME.exec(raw)?.[1],
  },
];

function suggestionFor(cluster: Cluster, resolvableIds: ReadonlySet<string>): SuggestionAction {
  const lever = RELAX_LEVERS.find((l) => l.ruleId === cluster.ruleId);
  if (lever) {
    const raw = cluster.exampleTargets[0] ?? '';
    const value = lever.extractValue(raw);
    if (value) return { kind: 'relax', list: lever.list, value };
    return { kind: 'none' };
  }
  if (resolvableIds.has(cluster.ruleId)) {
    const nextVerdict: VerdictKind | null = cluster.verdict === 'block'
      ? 'confirm'
      : cluster.verdict === 'confirm'
      ? 'observe'
      : null;
    if (nextVerdict) return { kind: 'override', rule: cluster.ruleId, verdict: nextVerdict };
  }
  return { kind: 'none' };
}

function tomlString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function reasonFor(cluster: Cluster, days: number): string {
  return `audit: rule "${cluster.ruleId}" fired ${cluster.count}x on shape ${cluster.shape} `
    + `in the last ${days}d — review before keeping`;
}

// A [[relax]] on command.git.safe_subcommands has a MUCH wider blast radius
// than the audited shape suggests: it disables the git-conditional
// dispatch for the ENTIRE subcommand, not just the branch/remote pattern
// that happened to trip the audit window — `push` covers every form,
// `--force` included, not only the plain `git push origin <branch>` shape
// that generated the friction. Auto-emitting that as a live, copy-pasteable
// block would let a human relax far more than they meant to by reviewing
// only the reason text. Every OTHER lever (mcp read_prefixes, an
// [[override]] on a regex rule) narrows exactly what was audited, so only
// this one list ships commented out.
function isGitSafeSubcommandLever(list: RelaxableList): boolean {
  return list === 'command.git.safe_subcommands';
}

function gitSafeSubcommandReason(cluster: Cluster, value: string, days: number): string {
  return `UNCOMMENT ONLY AFTER REVIEWING: allows EVERY git ${value} form without confirmation, `
    + `including --force — not just the audited shape. ${reasonFor(cluster, days)}`;
}

/**
 * `--suggest`: renders candidate `[[relax]]`/`[[override]]` TOML snippets
 * for every frequent-friction cluster with a known policy lever, deduped
 * so two shapes suggesting the same relaxation only emit it once. Text
 * only — never written to any overlay file by this module or its callers
 * (AC4: no code path applies a suggestion automatically).
 */
export function renderSuggestions(
  clusters: readonly Cluster[],
  resolvableIds: ReadonlySet<string>,
  options: AuditReportOptions,
): string {
  const lines: string[] = [
    `# bouncer audit --suggest — candidate policy overlay snippets, last ${options.days} day(s)`,
    '# Generated, never applied automatically — review each reason, then copy what you',
    '# want into your policy.toml overlay and re-run `bouncer rules lint`.',
    '',
  ];

  const friction = frictionClustersOf(clusters);
  if (friction.length === 0) {
    lines.push('# (no deny/ask friction in this window — nothing to suggest)');
    return `${lines.join('\n').trimEnd()}\n`;
  }

  const relaxSeen = new Set<string>();
  const overrideSeen = new Set<string>();

  for (const cluster of friction) {
    const action = suggestionFor(cluster, resolvableIds);

    if (action.kind === 'none') {
      lines.push(
        `# ${cluster.ruleId}: no policy lever available for automatic relaxation `
          + `(fired ${cluster.count}x, last ${cluster.lastSeen}) — review manually`,
      );
      lines.push('');
      continue;
    }

    if (action.kind === 'relax') {
      const dedupeKey = `${action.list} ${action.value}`;
      if (relaxSeen.has(dedupeKey)) continue;
      relaxSeen.add(dedupeKey);

      if (isGitSafeSubcommandLever(action.list)) {
        const block = [
          '[[relax]]',
          `list = ${tomlString(action.list)}`,
          `value = ${tomlString(action.value)}`,
          `reason = ${tomlString(gitSafeSubcommandReason(cluster, action.value, options.days))}`,
        ];
        lines.push(
          `# The block below is commented out: relaxing "${action.list}" for "${action.value}" `
            + `disables ALL grammar checks for that subcommand, not only the audited shape.`,
        );
        lines.push(...block.map((l) => `# ${l}`));
        lines.push('');
        continue;
      }

      lines.push('[[relax]]');
      lines.push(`list = ${tomlString(action.list)}`);
      lines.push(`value = ${tomlString(action.value)}`);
      lines.push(`reason = ${tomlString(reasonFor(cluster, options.days))}`);
      lines.push('');
      continue;
    }

    // action.kind === 'override'
    if (overrideSeen.has(action.rule)) continue;
    overrideSeen.add(action.rule);
    lines.push('[[override]]');
    lines.push(`rule = ${tomlString(action.rule)}`);
    lines.push('action = "relax"');
    lines.push(`verdict = ${tomlString(action.verdict)}`);
    lines.push(`reason = ${tomlString(reasonFor(cluster, options.days))}`);
    lines.push('');
  }

  return `${lines.join('\n').trimEnd()}\n`;
}
