// The fixture runner: loads a family's JSON fixture file and evaluates each
// case against an injectable engine. Pure logic, no bun:test import here —
// the *.test.ts files own the assertions, this module owns evaluation, so
// the mutation-proof test can reuse it against a deliberately broken engine
// without duplicating the dispatch logic.
//
// Fixture format (see fixtures/*.json): one JSON file per rule family, each
// holding `{ family, event, check?, cases: [...] }`. `check` names which
// engine entry point a case exercises; a case may override it (the secret
// family mixes path/command/url checks in one file). Nothing here is
// TypeScript-specific — a non-TS runner reads the same JSON and only needs
// to reimplement the small dispatch switch below against its own engine.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Deny } from '../src/types.ts';
import type { HookInput, Targets } from '../src/targets.ts';
import type { InjectionHit } from '../src/prompt-rules.ts';

// The abstract verdict vocabulary the spec assigns to the core (ticket 05).
// This ticket's engine still returns `deny`/`ask` (Deny.decision); mapping
// engine output onto this vocabulary is this runner's job (see mapDeny/
// mapHits below), not the engine's — the engine does not change here.
// `observe` is reserved for a future logged-allow case (conditional-rule
// passes with a rule id, per the spec's Logging decision) that no current
// engine function emits; it is part of the vocabulary so fixtures never
// need rewriting when that lands, but no fixture in this set uses it yet.
export type AbstractVerdict = 'block' | 'confirm' | 'flag' | 'observe';

export interface ExpectedVerdict {
  readonly verdict: AbstractVerdict;
  readonly ruleId: string;
}

export type CheckKind = 'bash' | 'secret-bash' | 'path' | 'url' | 'mcpTool' | 'text' | 'prompt';

export interface FixtureCase {
  readonly id: string;
  readonly check?: CheckKind;
  readonly toolName?: string;
  readonly command?: string;
  readonly path?: string;
  readonly url?: string;
  readonly mcpToolName?: string;
  readonly text?: string;
  readonly target?: string;
  readonly prompt?: string;
  readonly expected: readonly ExpectedVerdict[];
  readonly knownLimit?: boolean;
  readonly knownLimitReason?: string;
}

export interface FixtureFile {
  readonly family: string;
  readonly event: string;
  readonly check?: CheckKind;
  readonly cases: readonly FixtureCase[];
}

// The engine surface the runner dispatches to. Real fixtures.test.ts wires
// this to src/*.ts; fixtures-mutation.test.ts wires it to a deliberately
// broken copy to prove the fixtures are behavior-sensitive.
export interface Engine {
  readonly checkBash: (cmd: string) => Deny | null;
  readonly checkSecretBash: (cmd: string) => Deny | null;
  readonly checkPath: (path: string) => Deny | null;
  readonly checkUrl: (url: string) => Deny | null;
  readonly checkMcpWrite: (toolName: string) => Deny | null;
  readonly scanSecrets: (text: string, target: string) => Deny | null;
  readonly scanPrompt: (prompt: string) => readonly InjectionHit[];
  readonly extractTargets: (input: HookInput, hookName: string) => Targets;
  readonly isGuardedToolName: (toolName: string | undefined) => boolean;
}

const HOOK_NAME = 'fixture-runner';
const FIXTURES_DIR = join(import.meta.dir, '..', 'fixtures');

// Reads fixtures/*.json off disk rather than a hardcoded list, so a fixture
// file dropped in the directory is picked up by every consumer (both proof
// files import this) without a second place to remember to update it.
export function listFixtureFiles(): string[] {
  return readdirSync(FIXTURES_DIR)
    .filter((name) => name.endsWith('.json'))
    .sort();
}

export function loadFixtureFile(filename: string): FixtureFile {
  const path = join(FIXTURES_DIR, filename);
  const raw = readFileSync(path, 'utf8');
  return JSON.parse(raw) as FixtureFile;
}

// `decision` defaults to "deny" when omitted (see src/types.ts) — maps to
// "block"; "ask" maps to "confirm". This is the runner-side boundary the
// lead's decision names: the engine's deny/ask stays as-is, only the runner
// translates it into the abstract vocabulary the fixtures are written in.
function mapDeny(deny: Deny | null): ExpectedVerdict[] {
  if (!deny) return [];
  const verdict: AbstractVerdict = deny.decision === 'ask' ? 'confirm' : 'block';
  return [{ verdict, ruleId: deny.ruleId }];
}

// Prompt-injection hits carry no decision — the family is flag-only by
// design (see src/prompt-rules.ts's Posture note).
function mapHits(hits: readonly InjectionHit[]): ExpectedVerdict[] {
  return hits.map((hit) => ({ verdict: 'flag' as const, ruleId: hit.ruleId }));
}

// Routes a command through the same guarded-tool-name + target-extraction
// seam ticket 03 built, then the given single-command checker. Used by both
// "bash" (command family) and "secret-bash" (secret family) cases so a
// context-mode tool call is judged exactly like the Bash call it reroutes.
function evaluateCommand(
  engine: Engine,
  checker: (cmd: string) => Deny | null,
  toolName: string,
  command: string,
): ExpectedVerdict[] {
  if (!engine.isGuardedToolName(toolName)) return [];
  const input: HookInput = { tool_name: toolName, tool_input: commandToolInput(toolName, command) };
  for (const cmd of engine.extractTargets(input, HOOK_NAME).commands) {
    const hit = checker(cmd);
    if (hit) return mapDeny(hit);
  }
  return [];
}

// extractTargets reads a different tool_input field per tool: Bash carries
// `command`, the context-mode sandbox tools carry `code` (ctx_execute /
// ctx_execute_file) or a `commands` array (ctx_batch_execute). A fixture
// only ever names one command, so this builds whichever shape the given
// tool name expects — mirroring extractTargets' own switch, not
// reimplementing its logic.
function commandToolInput(toolName: string, command: string): Record<string, unknown> {
  if (toolName.endsWith('_ctx_execute') || toolName.endsWith('_ctx_execute_file')) {
    return { code: command };
  }
  if (toolName.endsWith('_ctx_batch_execute')) {
    return { commands: [{ label: 'fixture', command }] };
  }
  return { command };
}

// A path/url case may optionally route through extractTargets too (ctx_index
// / ctx_fetch_and_index parity) when `toolName` is set; otherwise the field
// is checked directly, which is the honest shape for PATH_RULES/BASH_RULES
// today — Read/Edit/Grep/Glob dispatch is adapter work (ticket 05/06), not
// part of this engine yet.
function resolveField(
  engine: Engine,
  toolName: string | undefined,
  bucket: 'paths' | 'urls',
  bareValue: string | undefined,
): string | undefined {
  if (toolName === undefined) return bareValue;
  const input: HookInput = {
    tool_name: toolName,
    tool_input: bucket === 'paths' ? { path: bareValue } : { url: bareValue },
  };
  return engine.extractTargets(input, HOOK_NAME)[bucket][0];
}

// A missing or misspelled payload key must never fall through to an empty
// string: an empty command/path/url/prompt very often evaluates to "no
// verdict", which would make a typo'd fixture pass as a false green instead
// of failing loudly. Every required field is validated here instead of
// defaulted away.
function requireString(fixtureCase: FixtureCase, field: keyof FixtureCase): string {
  const value = fixtureCase[field];
  if (typeof value !== 'string') {
    throw new Error(
      `fixture ${fixtureCase.id}: check ${JSON.stringify(fixtureCase.check)} requires a string `
        + `"${field}" field, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

export function evaluateCase(
  engine: Engine,
  file: Pick<FixtureFile, 'check'>,
  fixtureCase: FixtureCase,
): ExpectedVerdict[] {
  const check = fixtureCase.check ?? file.check;
  switch (check) {
    case 'bash':
      return evaluateCommand(
        engine,
        engine.checkBash,
        fixtureCase.toolName ?? 'Bash',
        requireString(fixtureCase, 'command'),
      );
    case 'secret-bash':
      return evaluateCommand(
        engine,
        engine.checkSecretBash,
        fixtureCase.toolName ?? 'Bash',
        requireString(fixtureCase, 'command'),
      );
    case 'path': {
      const path = resolveField(engine, fixtureCase.toolName, 'paths', requireString(fixtureCase, 'path'));
      if (path === undefined) {
        throw new Error(`fixture ${fixtureCase.id}: toolName routing produced no path to check`);
      }
      return mapDeny(engine.checkPath(path));
    }
    case 'url': {
      const url = resolveField(engine, fixtureCase.toolName, 'urls', requireString(fixtureCase, 'url'));
      if (url === undefined) {
        throw new Error(`fixture ${fixtureCase.id}: toolName routing produced no url to check`);
      }
      return mapDeny(engine.checkUrl(url));
    }
    case 'mcpTool':
      return mapDeny(engine.checkMcpWrite(requireString(fixtureCase, 'mcpToolName')));
    case 'text':
      return mapDeny(engine.scanSecrets(requireString(fixtureCase, 'text'), fixtureCase.target ?? 'target'));
    case 'prompt':
      return mapHits(engine.scanPrompt(requireString(fixtureCase, 'prompt')));
    default:
      throw new Error(`fixture ${fixtureCase.id}: unknown check kind ${JSON.stringify(check)}`);
  }
}

export function runFixtureFile(
  engine: Engine,
  file: FixtureFile,
): { readonly case: FixtureCase; readonly actual: ExpectedVerdict[]; readonly pass: boolean }[] {
  return file.cases.map((fixtureCase) => {
    const actual = evaluateCase(engine, file, fixtureCase);
    const pass = JSON.stringify(actual) === JSON.stringify(fixtureCase.expected);
    return { case: fixtureCase, actual, pass };
  });
}
