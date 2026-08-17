// The fixture runner: loads a family's JSON fixture file and evaluates each
// case against the REAL adapter dispatch (src/adapter/dispatch.ts) — not a
// mirror of it. Fixtures now carry the literal Claude Code envelope shape
// (`toolName` + `toolInput`, or `prompt` for UserPromptSubmit), the same
// bytes the compiled binary reads off stdin, so there is exactly one
// tool-name -> engine-call mapping in this codebase (dispatch.ts's), not two
// kept in sync by hand.
//
// One residual: `event` is the only discriminator this runner reads.
// PreToolUse cases carry `toolName`/`toolInput`; UserPromptSubmit cases
// carry `prompt` instead — genuinely a different envelope, not a family
// that "stays unreachable", so no `check` field survives anywhere in the
// fixture set.
//
// Nothing here is TypeScript-specific — a non-TS runner reads the same JSON
// and only needs its own dispatch.ts equivalent.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspectPreToolUse, inspectUserPromptSubmit } from '../src/adapter/dispatch.ts';
import type { HookInput } from '../src/adapter/protocol.ts';
import type { VerdictKind } from '../src/types.ts';

export interface ExpectedVerdict {
  readonly verdict: VerdictKind;
  readonly ruleId: string;
}

export interface FixtureCase {
  readonly id: string;
  readonly toolName?: string;
  readonly toolInput?: Record<string, unknown>;
  readonly prompt?: string;
  readonly expected: readonly ExpectedVerdict[];
  readonly knownLimit?: boolean;
  readonly knownLimitReason?: string;
}

export interface FixtureFile {
  readonly family: string;
  readonly event: 'PreToolUse' | 'UserPromptSubmit';
  readonly cases: readonly FixtureCase[];
}

const FIXTURES_DIR = join(import.meta.dir, '..', 'fixtures');

// Reads fixtures/*.json off disk rather than a hardcoded list, so a fixture
// file dropped in the directory is picked up by every consumer (both proof
// files import this) without a second place to remember to update it.
export function listFixtureFiles(): string[] {
  return readdirSync(FIXTURES_DIR)
    .filter((name) => name.endsWith('.json'))
    .toSorted();
}

export function loadFixtureFile(filename: string): FixtureFile {
  const path = join(FIXTURES_DIR, filename);
  const raw = readFileSync(path, 'utf8');
  return JSON.parse(raw) as FixtureFile;
}

function requireString(fixtureCase: FixtureCase, field: keyof FixtureCase): string {
  const value = fixtureCase[field];
  if (typeof value !== 'string') {
    throw new Error(
      `fixture ${fixtureCase.id}: requires a string "${field}" field, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

export async function evaluateCase(
  file: Pick<FixtureFile, 'event'>,
  fixtureCase: FixtureCase,
): Promise<ExpectedVerdict[]> {
  if (file.event === 'UserPromptSubmit') {
    const input: HookInput = {
      hook_event_name: 'UserPromptSubmit',
      prompt: requireString(fixtureCase, 'prompt'),
    };
    return inspectUserPromptSubmit(input).map((v) => ({ verdict: v.verdict, ruleId: v.ruleId }));
  }

  const input: HookInput = {
    hook_event_name: 'PreToolUse',
    tool_name: requireString(fixtureCase, 'toolName'),
    tool_input: fixtureCase.toolInput ?? {},
  };
  const hit = await inspectPreToolUse(input);
  return hit ? [{ verdict: hit.verdict.verdict, ruleId: hit.verdict.ruleId }] : [];
}
