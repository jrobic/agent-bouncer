// Harness declarations are policy data shared by the embedded baseline and
// overlays. This module owns their leaf shape, dialect, witness, and local
// uniqueness validation so neither source can drift — including, since
// ADR-0006, the optional `[harness.protocol]` table: the
// transport/input-map/tools-map/output-table/templates a generic adapter
// pipeline (src/adapter/run.ts) reads instead of hardcoding Claude Code.

import { lintRegexSource } from './lint.ts';
import { compileRules } from './match.ts';
import type {
  DerivedHarnessRule,
  HarnessAction,
  HarnessDeclaration,
  HarnessOutputTable,
  HarnessOverlay,
  HarnessPersistent,
  HarnessProtocol,
  HarnessProtocolEvents,
  HarnessProtocolInput,
  HarnessRole,
  HarnessTemplate,
  HarnessTemplateKey,
  HarnessToolRow,
  RegexRule,
} from './schema.ts';

type HarnessFields = Readonly<{
  id: string;
  dir?: readonly string[];
  parents?: readonly string[];
  env?: readonly string[];
  witness?: string;
  reason?: string;
  persistent?: readonly HarnessPersistent[];
  protocol?: HarnessProtocol;
}>;

type HarnessParseOptions = Readonly<{
  partial: boolean;
}>;

type HarnessParseResult<T> = Readonly<{
  value?: T;
  issues: readonly string[];
}>;

function field(object: object, name: string): unknown {
  return Reflect.get(object, name);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function stringArray(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return undefined;
  return value;
}

function duplicateValues(values: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    if (seen.has(value)) return true;
    seen.add(value);
    return false;
  });
}

// The fallback remains deliberately narrow: it supports a plain documented
// path fragment, then the validation below proves it against the regex. More
// expressive fragments must declare the concrete witness they mean.
function derivedWitness(dir: string): string {
  const path = dir.replace(/^\(\^\|\/\)/, '').replace(/\\\./g, '.');
  return path.startsWith('/') || path.startsWith('~') ? path : `~/${path}`;
}

function witnessIssue(dir: string, witness: string, label: string): string | null {
  const [directoryRule] = deriveHarnessRules([{
    id: 'witness-validation',
    dir: [dir],
    env: [],
    witness,
    reason: 'Witness validation',
    persistent: [],
  }]);
  const [compiledRule] = compileRules([directoryRule!]);
  return compiledRule!.re.test(witness)
    ? null
    : `${label}.witness must match ${label}.dir[0] — declare witness explicitly`;
}

function parsePersistent(value: unknown, label: string): HarnessParseResult<readonly HarnessPersistent[]> {
  if (!Array.isArray(value)) return { issues: [`${label}.persistent must be an array`] };

  const persistent: HarnessPersistent[] = [];
  const issues: string[] = [];
  for (const [index, raw] of value.entries()) {
    const itemLabel = `${label}.persistent[${index}]`;
    if (raw === null || typeof raw !== 'object') {
      issues.push(`${itemLabel} must contain non-empty id, path, and reason strings`);
      continue;
    }
    const id = field(raw, 'id');
    const path = field(raw, 'path');
    const reason = field(raw, 'reason');
    if (!nonEmptyString(id) || !nonEmptyString(path) || !nonEmptyString(reason)) {
      issues.push(`${itemLabel} must contain non-empty id, path, and reason strings`);
      continue;
    }
    persistent.push({ id, path, reason });
    for (const issue of lintRegexSource(path)) issues.push(`${itemLabel}.path: ${issue.message}`);
  }
  for (const id of duplicateValues(persistent.map((entry) => entry.id))) {
    issues.push(`${label}.persistent id ${JSON.stringify(id)} is declared more than once`);
  }
  return issues.length === 0 ? { value: persistent, issues } : { issues };
}

// ─── `[harness.protocol]` (ADR-0006 § 3/4) ────────────────────────────────

const KNOWN_TRANSPORTS: Readonly<Record<string, true>> = { 'stdin-json': true };
// Exported for the registry parity test (tests/adapter-codec-registries.test.ts):
// this lint-time registry and the runtime one src/adapter/codecs/wiring/
// registry.ts's WIRING_CODECS builds must name the same key set, or a
// declaration that lints clean could still find nothing to dispatch to
// at doctor/run time — checked by a real test, not just this comment.
export const KNOWN_WIRINGS: Readonly<Record<string, true>> = { 'hook-file': true, 'codex-hooks': true, 'shim-file': true };
// ADR-0006 § 6: an input codec on a tool row — named code that parses the
// raw input bag itself instead of a field-map selector, for a shape a
// selector cannot express (Codex's `apply_patch` patch text). Mirrors
// KNOWN_WIRINGS/KNOWN_TRANSPORTS exactly: the string a declaration writes
// must resolve to a real module (src/adapter/codecs/input/), and the two
// registries — this lint-time one and the runtime one buildNeutralCall
// reads (src/adapter/neutral-call.ts) — must name the same set or a
// declaration that lints clean could still fail to dispatch at runtime.
// Exported for the registry parity test, same reason as KNOWN_WIRINGS above.
export const KNOWN_INPUT_CODECS: Readonly<Record<string, true>> = { 'apply-patch': true, 'hashline': true };
const KNOWN_ROLES: Readonly<Record<HarnessRole, true>> = { command: true, read: true, write: true, fetch: true, mcp: true };
const TOOL_ROW_SELECTOR_KEYS = ['command', 'path', 'pattern', 'text', 'url', 'urls'] as const;
const TOOL_ROW_KNOWN_KEYS: Readonly<Record<string, true>> = {
  role: true,
  command: true,
  path: true,
  pattern: true,
  text: true,
  url: true,
  urls: true,
  codec: true,
};

function requireNonEmptyString(raw: object, key: string, label: string, issues: string[]): string | undefined {
  const value = field(raw, key);
  if (!nonEmptyString(value)) {
    issues.push(`${label}.${key} must be a non-empty string`);
    return undefined;
  }
  return value;
}

// Absence is legal here (unlike requireNonEmptyString
// above) — only a PRESENT-but-invalid value is an issue. Used for the
// optional prompt, session-start, post-tool, and post-tool-failure selectors
// and events; each optional event surface is linted against its input and
// template so no half-declared path silently does nothing.
function optionalNonEmptyString(raw: object, key: string, label: string, issues: string[]): string | undefined {
  const value = field(raw, key);
  if (value === undefined) return undefined;
  if (!nonEmptyString(value)) {
    issues.push(`${label}.${key} must be a non-empty string`);
    return undefined;
  }
  return value;
}

function parseProtocolInput(raw: unknown, label: string): HarnessParseResult<HarnessProtocolInput> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.input must be a table`] };
  const issues: string[] = [];
  const event = requireNonEmptyString(raw, 'event', `${label}.input`, issues);
  const tool = requireNonEmptyString(raw, 'tool', `${label}.input`, issues);
  const input = requireNonEmptyString(raw, 'input', `${label}.input`, issues);
  const session = requireNonEmptyString(raw, 'session', `${label}.input`, issues);
  const prompt = optionalNonEmptyString(raw, 'prompt', `${label}.input`, issues);
  const cwd = requireNonEmptyString(raw, 'cwd', `${label}.input`, issues);
  const permission = optionalNonEmptyString(raw, 'permission', `${label}.input`, issues);
  const response = optionalNonEmptyString(raw, 'response', `${label}.input`, issues);
  const error = optionalNonEmptyString(raw, 'error', `${label}.input`, issues);
  if (issues.length > 0) return { issues };
  return {
    value: {
      event: event!,
      tool: tool!,
      input: input!,
      session: session!,
      ...(prompt !== undefined ? { prompt } : {}),
      cwd: cwd!,
      ...(permission !== undefined ? { permission } : {}),
      ...(response !== undefined ? { response } : {}),
      ...(error !== undefined ? { error } : {}),
    },
    issues,
  };
}

function parseProtocolEvents(raw: unknown, label: string): HarnessParseResult<HarnessProtocolEvents> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.events must be a table`] };
  const issues: string[] = [];
  const preTool = requireNonEmptyString(raw, 'pre_tool', `${label}.events`, issues);
  const prompt = optionalNonEmptyString(raw, 'prompt', `${label}.events`, issues);
  const sessionStart = optionalNonEmptyString(raw, 'session_start', `${label}.events`, issues);
  const postTool = optionalNonEmptyString(raw, 'post_tool', `${label}.events`, issues);
  const postToolFailure = optionalNonEmptyString(raw, 'post_tool_failure', `${label}.events`, issues);
  if (issues.length > 0) return { issues };
  return {
    value: {
      pre_tool: preTool!,
      ...(prompt !== undefined ? { prompt } : {}),
      ...(sessionStart !== undefined ? { session_start: sessionStart } : {}),
      ...(postTool !== undefined ? { post_tool: postTool } : {}),
      ...(postToolFailure !== undefined ? { post_tool_failure: postToolFailure } : {}),
    },
    issues,
  };
}

function parseToolRow(raw: unknown, toolName: string, label: string): HarnessParseResult<HarnessToolRow> {
  const rowLabel = `${label}.tools[${JSON.stringify(toolName)}]`;
  if (raw === null || typeof raw !== 'object') return { issues: [`${rowLabel} must be a table`] };
  const issues: string[] = [];

  for (const key of Object.keys(raw)) {
    if (!Object.hasOwn(TOOL_ROW_KNOWN_KEYS, key)) issues.push(`${rowLabel}.${key} is not a recognized field`);
  }

  const role = field(raw, 'role');
  if (!nonEmptyString(role) || !Object.hasOwn(KNOWN_ROLES, role)) {
    issues.push(`${rowLabel}.role must be one of: ${Object.keys(KNOWN_ROLES).join(', ')}`);
  }

  const selectors: Record<string, string> = {};
  for (const key of TOOL_ROW_SELECTOR_KEYS) {
    const value = field(raw, key);
    if (value === undefined) continue;
    if (!nonEmptyString(value)) {
      issues.push(`${rowLabel}.${key} must be a non-empty string`);
      continue;
    }
    selectors[key] = value;
  }

  // ADR-0006 § 6: a `codec` row parses the raw input bag
  // itself (Codex's `apply_patch` patch text, unreachable through a
  // field-map selector) — mutually exclusive with every selector key: a
  // row naming both would leave it ambiguous whether the codec or the
  // selectors own a given field, so this is a named rejection (which
  // selector key collided), never a generic "malformed row".
  const codecRaw = field(raw, 'codec');
  let codec: string | undefined;
  if (codecRaw !== undefined) {
    if (!nonEmptyString(codecRaw) || !Object.hasOwn(KNOWN_INPUT_CODECS, codecRaw)) {
      issues.push(`${rowLabel}.codec must be one of: ${Object.keys(KNOWN_INPUT_CODECS).join(', ')}`);
    } else {
      codec = codecRaw;
    }
    const collidingKeys = Object.keys(selectors);
    if (collidingKeys.length > 0) {
      issues.push(`${rowLabel}.codec cannot be combined with selector field(s): ${collidingKeys.join(', ')}`);
    }
  }

  if (issues.length > 0) return { issues };
  return { value: { role: role as HarnessRole, ...selectors, ...(codec === undefined ? {} : { codec }) }, issues };
}

function parseTools(raw: unknown, label: string): HarnessParseResult<Readonly<Record<string, HarnessToolRow>>> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.tools must be a table`] };
  const issues: string[] = [];
  const tools: Record<string, HarnessToolRow> = {};
  for (const [toolName, rowRaw] of Object.entries(raw)) {
    const parsed = parseToolRow(rowRaw, toolName, label);
    issues.push(...parsed.issues);
    if (parsed.value !== undefined) tools[toolName] = parsed.value;
  }
  if (Object.keys(tools).length === 0) issues.push(`${label}.tools must declare at least one tool row`);
  if (issues.length > 0) return { issues };
  return { value: tools, issues };
}

// Rules 1-5 of ADR-0006 § 4: every abstract verdict maps to exactly the
// actions it may legally degrade to, and "ask" carries a written,
// measured `ask_probe`. Rule 6 (an overlay relaxing an EXISTING baseline
// harness's "deny" confirm to "ask") is context that only the merge in
// src/policy/load.ts has — see lintHarnessProtocolConfirmRelaxation below.
function parseOutputTable(raw: unknown, label: string): HarnessParseResult<HarnessOutputTable> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.output must be a table`] };
  const issues: string[] = [];

  const block = field(raw, 'block');
  if (block !== 'deny') issues.push(`${label}.output.block must be "deny"`);

  const confirm = field(raw, 'confirm');
  if (confirm !== 'deny' && confirm !== 'ask') issues.push(`${label}.output.confirm must be "deny" or "ask"`);

  const observe = field(raw, 'observe');
  if (observe !== 'silent') issues.push(`${label}.output.observe must be "silent"`);

  const flag = field(raw, 'flag');
  if (flag !== 'context' && flag !== 'silent') issues.push(`${label}.output.flag must be "context" or "silent"`);

  const onMalformed = field(raw, 'on_malformed');
  if (onMalformed !== 'allow' && onMalformed !== 'deny') {
    issues.push(`${label}.output.on_malformed must be "allow" or "deny"`);
  }

  const askProbe = field(raw, 'ask_probe');
  if (confirm === 'ask' && !nonEmptyString(askProbe)) {
    issues.push(`${label}.output.ask_probe must be a non-empty string when confirm = "ask"`);
  }

  if (issues.length > 0) return { issues };
  return {
    value: {
      block: 'deny',
      confirm: confirm as 'deny' | 'ask',
      observe: 'silent',
      flag: flag as 'context' | 'silent',
      on_malformed: onMalformed as 'allow' | 'deny',
      ...(nonEmptyString(askProbe) ? { ask_probe: askProbe } : {}),
    },
    issues,
  };
}

// render.ts JSON-encodes a placeholder's VALUE
// (quotes included), so `"${reason}"` in a harness's own TOML double-
// quotes at render time — invalid JSON the harness cannot parse, and a
// silent fail-open the harness author never sees. Two independent belts,
// since a template author can defeat pattern-matching by construction but
// not an actual JSON round trip, and can defeat a JSON round trip by
// writing a non-JSON stdout shape (a future shim's own line format) that
// pattern-matching alone would not catch either:
//
// Belt 1 — a placeholder directly touching a `"` is always the mistake
// this rule exists for (the author meant it inside a JSON string and
// wrote a JSON string manually around a value that IS one already).
// Captures the placeholder's own name so the message names the ACTUAL
// mistake (this used to hardcode "${reason}" no
// matter which placeholder was actually quoted).
const QUOTED_PLACEHOLDER = /"\$\{(\w+)\}|\$\{(\w+)\}"/;

// Belt 2 — render with a worst-case probe value (a double quote, a
// backslash, a newline, and a closing brace — the four characters most
// likely to break naive string concatenation) standing in for EVERY
// placeholder, mirroring src/adapter/render.ts's own
// `JSON.stringify(value)` substitution exactly. A `stdout` that looks
// like a JSON object/array literal must still parse after that
// substitution; a template with no such shape (a future non-JSON shim
// line) is not held to this belt.
const TEMPLATE_PLACEHOLDER = /\$\{(\w+)\}/g;
const PROBE_VALUE = '"\\\n}';

// Belt 3 — src/adapter/render.ts fills EXACTLY these
// placeholder names, never more: `deny`/`ask` templates get `reason`,
// `rule` (the bare ruleId), and `verdict`; `context`, `session_start`, and
// `failure_context` get `context`; `redact` gets `response`. Belt 2 above
// proves a template's JSON SHAPE survives substitution; this map proves
// that the renderer can actually FILL each named placeholder.
const TEMPLATE_ALLOWED_PLACEHOLDERS: Readonly<Record<HarnessTemplateKey, ReadonlySet<string>>> = {
  deny: new Set(['reason', 'rule', 'verdict']),
  ask: new Set(['reason', 'rule', 'verdict']),
  context: new Set(['context']),
  session_start: new Set(['context']),
  redact: new Set(['response']),
  failure_context: new Set(['context']),
};

// ADR-0008 § 3: the post-tool answer IS the rewritten response. A `redact`
// template that does not carry `${response}` would hand the harness a
// fixed answer (an empty patch: the original output shown), and one that
// sets `exit` would answer with a process status instead of the rewrite —
// both fail open, silently, so both are rejected here rather than trusted.
function redactTemplateIssues(template: HarnessTemplate, label: string): string[] {
  const issues: string[] = [];
  if (template.stdout === undefined || !template.stdout.includes('${response}')) {
    issues.push(`${label}.output.redact.stdout must carry \${response} — the rewritten tool response is the whole answer`);
  }
  if (template.exit !== undefined) {
    issues.push(`${label}.output.redact.exit must not be set — the post-tool answer is stdout, never a process status`);
  }
  return issues;
}
function failureContextTemplateIssues(template: HarnessTemplate, label: string): string[] {
  const issues: string[] = [];
  if (template.stdout === undefined || !template.stdout.includes('${context}')) {
    issues.push(`${label}.output.failure_context.stdout must carry \${context} — the name-only alert is the whole answer`);
  }
  if (template.exit !== undefined) {
    issues.push(`${label}.output.failure_context.exit must not be set — the alert is stdout, never a process status`);
  }
  return issues;
}

function templateStdoutIssues(stdout: string, key: HarnessTemplateKey, label: string): string[] {
  const issues: string[] = [];

  const quotedMatch = stdout.match(QUOTED_PLACEHOLDER);
  if (quotedMatch) {
    const name = quotedMatch[1] ?? quotedMatch[2];
    issues.push(
      `${label}.output.${key}.stdout: placeholders are JSON-encoded; write \${${name}}, not "\${${name}}"`,
    );
  }

  const allowed = TEMPLATE_ALLOWED_PLACEHOLDERS[key];
  for (const match of stdout.matchAll(TEMPLATE_PLACEHOLDER)) {
    const name = match[1]!;
    if (!allowed.has(name)) {
      issues.push(
        `${label}.output.${key}.stdout: unknown placeholder \${${name}} — this template only fills ${[...allowed].join(', ')}`,
      );
    }
  }

  const trimmed = stdout.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const probed = stdout.replace(TEMPLATE_PLACEHOLDER, () => JSON.stringify(PROBE_VALUE));
    try {
      JSON.parse(probed);
    } catch {
      issues.push(`${label}.output.${key}.stdout does not parse as JSON once its placeholders are substituted`);
    }
  }
  return issues;
}

function parseTemplate(raw: unknown, key: HarnessTemplateKey, label: string): HarnessParseResult<HarnessTemplate> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.output.${key} must be a table`] };
  const issues: string[] = [];
  const stdout = field(raw, 'stdout');
  const exit = field(raw, 'exit');
  if (stdout !== undefined && typeof stdout !== 'string') issues.push(`${label}.output.${key}.stdout must be a string`);
  if (exit !== undefined && (typeof exit !== 'number' || !Number.isInteger(exit))) {
    issues.push(`${label}.output.${key}.exit must be an integer`);
  }
  if (stdout === undefined && exit === undefined) issues.push(`${label}.output.${key} must set stdout, exit, or both`);
  if (typeof stdout === 'string') issues.push(...templateStdoutIssues(stdout, key, label));
  if (issues.length > 0) return { issues };
  return {
    value: { ...(typeof stdout === 'string' ? { stdout } : {}), ...(typeof exit === 'number' ? { exit } : {}) },
    issues,
  };
}

// Templates live NESTED under `[harness.protocol.output.<action>]` (ADR-0006
// § 3's sample) — `outputRaw` is the SAME raw table parseOutputTable read
// its flat fields from, read a second time for its per-action subtables.
// Only the actions the output table actually maps a verdict to (minus
// "silent", which renders nothing) are required. `session_start` is
// required exactly when `events.session_start` is declared (this
// was unconditional before, forcing every harness to carry
// a SessionStart doctor announcement even one with no such surface). A
// raw table present for an action the output table does NOT route to it —
// an `ask` table when `confirm` isn't `"ask"`, a `context` table when
// `flag` isn't `"context"`, a `session_start` table with no matching
// event — is a dead template. The event-specific `redact` and
// `failure_context` templates follow the same event-to-template rule below.
const EVENT_TEMPLATE_RULES: readonly {
  event: 'session_start' | 'post_tool' | 'post_tool_failure';
  template: HarnessTemplateKey;
  validate?: (template: HarnessTemplate, label: string) => string[];
}[] = [
  { event: 'session_start', template: 'session_start' },
  { event: 'post_tool', template: 'redact', validate: redactTemplateIssues },
  { event: 'post_tool_failure', template: 'failure_context', validate: failureContextTemplateIssues },
];

function parseTemplates(
  outputRaw: object,
  output: HarnessOutputTable,
  events: HarnessProtocolEvents,
  label: string,
): HarnessParseResult<Readonly<Partial<Record<HarnessTemplateKey, HarnessTemplate>>>> {
  const issues: string[] = [];
  const templates: Partial<Record<HarnessTemplateKey, HarnessTemplate>> = {};

  const neededActions = new Set<HarnessAction>([output.block, output.confirm, output.observe, output.flag]);
  neededActions.delete('silent');
  if (events.prompt === undefined) neededActions.delete('context');
  for (const action of neededActions) {
    const parsed = parseTemplate(field(outputRaw, action), action as HarnessTemplateKey, label);
    issues.push(...parsed.issues);
    if (parsed.value !== undefined) templates[action as HarnessTemplateKey] = parsed.value;
  }
  if (!neededActions.has('ask') && field(outputRaw, 'ask') !== undefined) {
    issues.push(`${label}.output.ask is present but confirm is not "ask" — a dead template`);
  }
  if (!neededActions.has('context') && field(outputRaw, 'context') !== undefined) {
    issues.push(`${label}.output.context is present but flag is not "context" or events.prompt is not declared — a dead template`);
  }

  // The event selects its own template; `output.flag` selects only the action.
  for (const { event, template, validate } of EVENT_TEMPLATE_RULES) {
    const rawTemplate = field(outputRaw, template);
    if (events[event] === undefined) {
      if (rawTemplate !== undefined) {
        issues.push(`${label}.output.${template} is present but events.${event} is not declared — a dead template`);
      }
      continue;
    }
    const parsed = parseTemplate(rawTemplate, template, label);
    issues.push(...parsed.issues);
    if (parsed.value !== undefined) {
      if (validate !== undefined) issues.push(...validate(parsed.value, label));
      templates[template] = parsed.value;
    }
  }

  if (issues.length > 0) return { issues };
  return { value: templates, issues };
}

// Event selectors and output actions are cross-table rules, so these checks
// run from parseHarnessProtocol after all three tables have parsed.
function protocolCoherenceIssues(
  input: HarnessProtocolInput,
  events: HarnessProtocolEvents,
  output: HarnessOutputTable,
  label: string,
): string[] {
  const issues: string[] = [];
  if (events.prompt !== undefined && input.prompt === undefined) {
    issues.push(`${label}.input.prompt is required when events.prompt is declared`);
  }
  if (events.prompt === undefined && events.post_tool_failure === undefined && output.flag !== 'silent') {
    issues.push(
      `${label}.output.flag must be "silent" when neither events.prompt nor events.post_tool_failure is declared`,
    );
  }
  // ADR-0008 § 3: the response selector and post-tool event are a lockstep
  // pair; the same rule applies to the error selector and failure event
  // described in ADR-0008 § 9. Event names must be unique across all kinds.
  if (events.post_tool !== undefined && input.response === undefined) {
    issues.push(`${label}.input.response is required when events.post_tool is declared`);
  }
  if (events.post_tool === undefined && input.response !== undefined) {
    issues.push(`${label}.input.response is declared but events.post_tool is not — a dead selector`);
  }
  if (events.post_tool_failure !== undefined && input.error === undefined) {
    issues.push(`${label}.input.error is required when events.post_tool_failure is declared`);
  }
  if (events.post_tool_failure === undefined && input.error !== undefined) {
    issues.push(`${label}.input.error is declared but events.post_tool_failure is not — a dead selector`);
  }
  const declaredEvents = Object.entries(events).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string',
  );
  const eventNames = new Map<string, string>();
  for (const [kind, name] of declaredEvents) {
    const previous = eventNames.get(name);
    if (previous !== undefined) {
      issues.push(`${label}.events.${previous} and ${kind} must have different event names`);
    } else {
      eventNames.set(name, kind);
    }
  }
  return issues;
}

/**
 * Parses and fully validates a `[harness.protocol]` table — ADR-0006 § 3's
 * transport/wiring/input-map/events/tools-map, and § 4's output table plus
 * its per-action templates. Used identically for a baseline harness (must
 * always pass — parseBaselineHarness below asserts it does) and an overlay
 * declaration (a failure here rejects that overlay `[[harness]]` block as
 * a unit — src/policy/load.ts). Does NOT check ADR-0006 § 4 rule 6 (an
 * overlay relaxing an EXISTING baseline harness's "deny" confirm to "ask")
 * — that needs the baseline's own protocol in scope, which only the merge
 * in src/policy/load.ts has; see lintHarnessProtocolConfirmRelaxation.
 */
export function parseHarnessProtocol(raw: unknown, label: string): HarnessParseResult<HarnessProtocol> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.protocol must be a table`] };
  const protocolLabel = `${label}.protocol`;
  const issues: string[] = [];

  const transport = field(raw, 'transport');
  if (!nonEmptyString(transport) || !Object.hasOwn(KNOWN_TRANSPORTS, transport)) {
    issues.push(`${protocolLabel}.transport must be one of: ${Object.keys(KNOWN_TRANSPORTS).join(', ')}`);
  }

  const wiring = field(raw, 'wiring');
  if (wiring !== undefined && (!nonEmptyString(wiring) || !Object.hasOwn(KNOWN_WIRINGS, wiring))) {
    issues.push(`${protocolLabel}.wiring must be one of: ${Object.keys(KNOWN_WIRINGS).join(', ')}`);
  }

  const inputParsed = parseProtocolInput(field(raw, 'input'), protocolLabel);
  issues.push(...inputParsed.issues);
  const eventsParsed = parseProtocolEvents(field(raw, 'events'), protocolLabel);
  issues.push(...eventsParsed.issues);
  const toolsParsed = parseTools(field(raw, 'tools'), protocolLabel);
  issues.push(...toolsParsed.issues);

  const outputRaw = field(raw, 'output');
  const outputParsed = parseOutputTable(outputRaw, protocolLabel);
  issues.push(...outputParsed.issues);

  if (inputParsed.value !== undefined && eventsParsed.value !== undefined && outputParsed.value !== undefined) {
    issues.push(...protocolCoherenceIssues(inputParsed.value, eventsParsed.value, outputParsed.value, protocolLabel));
  }

  const templatesParsed = outputParsed.value === undefined || eventsParsed.value === undefined
      || outputRaw === null || typeof outputRaw !== 'object'
    ? undefined
    : parseTemplates(outputRaw, outputParsed.value, eventsParsed.value, protocolLabel);
  if (templatesParsed !== undefined) issues.push(...templatesParsed.issues);

  if (
    issues.length > 0 || inputParsed.value === undefined || eventsParsed.value === undefined
    || toolsParsed.value === undefined || outputParsed.value === undefined || templatesParsed?.value === undefined
  ) {
    return { issues };
  }

  return {
    value: {
      transport: transport as string,
      ...(nonEmptyString(wiring) ? { wiring } : {}),
      input: inputParsed.value,
      events: eventsParsed.value,
      tools: toolsParsed.value,
      output: outputParsed.value,
      templates: templatesParsed.value,
    },
    issues,
  };
}

// ADR-0006 § 4 rule 6: "an overlay moves a BASELINE harness's confirm from
// deny to ask (a baseline deny is a measured fact, fact 3 for Codex)".
// Pure and context-free by design (the caller supplies both sides) so it
// can be unit-tested directly — codex is the first baseline
// harness with a "deny" protocol.output.confirm, so this rule is now
// exercised end-to-end too (tests/policy-harness-protocol.test.ts's own
// "rule 6" describe block, against the real embedded BASELINE); src/
// policy/load.ts's mergeHarnesses is the real overlay merge's call site.
export function lintHarnessProtocolConfirmRelaxation(
  baselineConfirm: HarnessAction,
  overlayConfirm: HarnessAction,
  label: string,
): readonly string[] {
  if (baselineConfirm === 'deny' && overlayConfirm === 'ask') {
    return [
      `${label}.protocol.output.confirm cannot relax this baseline harness's "deny" to "ask" `
      + `— deny is a measured fact, not a default to loosen from an overlay`,
    ];
  }
  return [];
}

function parseHarnessFields(raw: unknown, label: string, options: HarnessParseOptions): HarnessParseResult<HarnessFields> {
  if (raw === null || typeof raw !== 'object') return { issues: [`${label}.id must be a non-empty string`] };

  const id = field(raw, 'id');
  if (!nonEmptyString(id)) return { issues: [`${label}.id must be a non-empty string`] };

  const issues: string[] = [];
  const dirInput = field(raw, 'dir');
  const parentsInput = field(raw, 'parents');
  const envInput = field(raw, 'env');
  const reasonInput = field(raw, 'reason');
  const persistentInput = field(raw, 'persistent');
  const witnessInput = field(raw, 'witness');
  const protocolInput = field(raw, 'protocol');
  const dir = dirInput === undefined ? undefined : stringArray(dirInput);
  const parents = parentsInput === undefined ? undefined : stringArray(parentsInput);
  const env = envInput === undefined ? undefined : stringArray(envInput);

  if (!options.partial && dirInput === undefined) issues.push(`${label}.dir must be a non-empty string array`);
  if (dirInput !== undefined && (dir === undefined || dir.length === 0)) issues.push(`${label}.dir must be a non-empty string array`);
  if (parentsInput !== undefined && parents === undefined) issues.push(`${label}.parents must be a string array`);
  if (!options.partial && envInput === undefined) issues.push(`${label}.env must be a string array`);
  if (envInput !== undefined && env === undefined) issues.push(`${label}.env must be a string array`);
  if (!options.partial && !nonEmptyString(reasonInput)) issues.push(`${label}.reason must be a non-empty string`);
  if (reasonInput !== undefined && !nonEmptyString(reasonInput)) issues.push(`${label}.reason must be a non-empty string`);
  if (!options.partial && persistentInput === undefined) issues.push(`${label}.persistent must be an array`);
  if (witnessInput !== undefined && !nonEmptyString(witnessInput)) issues.push(`${label}.witness must be a non-empty string`);
  if (witnessInput !== undefined && dir === undefined) issues.push(`${label}.witness requires dir`);

  if (dir !== undefined) {
    for (const fragment of [...dir, ...(parents ?? [])]) {
      for (const issue of lintRegexSource(fragment)) issues.push(`${label}.dir: ${issue.message}`);
    }
    const witness = typeof witnessInput === 'string' ? witnessInput : derivedWitness(dir[0]!);
    const issue = witnessIssue(dir[0]!, witness, label);
    if (issue !== null) issues.push(issue);
  }
  if (env !== undefined) {
    for (const name of env) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(name)) issues.push(`${label}.env ${JSON.stringify(name)} must be uppercase`);
    }
    for (const name of duplicateValues(env)) issues.push(`${label}.env ${JSON.stringify(name)} is declared more than once`);
  }

  const parsedPersistent = persistentInput === undefined ? undefined : parsePersistent(persistentInput, label);
  if (parsedPersistent !== undefined) issues.push(...parsedPersistent.issues);

  const parsedProtocol = protocolInput === undefined ? undefined : parseHarnessProtocol(protocolInput, label);
  if (parsedProtocol !== undefined) issues.push(...parsedProtocol.issues);
  if (issues.length > 0) return { issues };

  return {
    value: {
      id,
      ...(dir === undefined ? {} : { dir }),
      ...(parents === undefined ? {} : { parents }),
      ...(env === undefined ? {} : { env }),
      ...(dir === undefined ? {} : { witness: typeof witnessInput === 'string' ? witnessInput : derivedWitness(dir[0]!) }),
      ...(typeof reasonInput !== 'string' ? {} : { reason: reasonInput }),
      ...(parsedPersistent === undefined ? {} : { persistent: parsedPersistent.value! }),
      ...(parsedProtocol?.value === undefined ? {} : { protocol: parsedProtocol.value }),
    },
    issues,
  };
}

export function parseBaselineHarness(raw: unknown, label: string): HarnessParseResult<HarnessDeclaration> {
  const parsed = parseHarnessFields(raw, label, { partial: false });
  const harness = parsed.value;
  if (
    harness === undefined || harness.dir === undefined || harness.env === undefined || harness.reason === undefined
    || harness.persistent === undefined
  ) {
    return { issues: parsed.issues };
  }
  const witness = harness.witness ?? derivedWitness(harness.dir[0]!);
  return {
    value: {
      id: harness.id,
      dir: harness.dir,
      ...(harness.parents === undefined ? {} : { parents: harness.parents }),
      env: harness.env,
      witness,
      reason: harness.reason,
      persistent: harness.persistent,
      ...(harness.protocol === undefined ? {} : { protocol: harness.protocol }),
    },
    issues: parsed.issues,
  };
}

export function parseHarnessOverlay(raw: unknown, label: string): HarnessParseResult<HarnessOverlay> {
  const parsed = parseHarnessFields(raw, label, { partial: true });
  return parsed.value === undefined ? { issues: parsed.issues } : { value: parsed.value, issues: parsed.issues };
}

export function deriveHarnessRules(harnesses: readonly HarnessDeclaration[]): readonly DerivedHarnessRule[] {
  return harnesses.flatMap((harness) => {
    const configDirs = [...harness.dir, ...(harness.parents ?? [])];
    const configDir: DerivedHarnessRule = {
      id: `${harness.id}-config-dir`,
      regex: `(?:${configDirs.map((dir) => `(?:${dir})/?$`).join('|')})`,
      reason: harness.reason,
      harnessId: harness.id,
    };
    const persistent = harness.persistent.map<DerivedHarnessRule>((entry) => ({
      id: entry.id,
      regex: `(?:${harness.dir.map((dir) => `(?:${dir})/${entry.path}`).join('|')})`,
      reason: entry.reason,
      harnessId: harness.id,
    }));
    return [configDir, ...persistent];
  });
}

export function isDerivedHarnessRule(rule: RegexRule): rule is DerivedHarnessRule {
  return 'harnessId' in rule && typeof rule.harnessId === 'string';
}

export function harnessEnvWitnesses(harnesses: readonly HarnessDeclaration[]): ReadonlyMap<string, string> {
  const witnesses = new Map<string, string>();
  for (const harness of harnesses) {
    for (const env of harness.env) if (!witnesses.has(env)) witnesses.set(env, harness.witness);
  }
  return witnesses;
}
