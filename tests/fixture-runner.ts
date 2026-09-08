// The fixture runner: loads a family's JSON fixture file and evaluates each
// case against the REAL adapter dispatch (src/adapter/dispatch.ts) — not a
// mirror of it. Fixtures carry the literal Claude Code envelope shape
// (`toolName` + `toolInput`, or `prompt` for UserPromptSubmit), the same
// bytes the compiled binary reads off stdin; this runner turns that shape
// into the neutral call through the SAME claude-code declaration
// (`policy/harness/claude-code.toml`'s `[harness.protocol]`) `run()`
// itself reads — ticket 15a's whole point: one tool-name -> engine-call
// mapping, in the declaration, not two kept in sync by hand (one in code,
// one here).
//
// One residual: `event` is the only discriminator this runner reads.
// PreToolUse cases carry `toolName`/`toolInput`; UserPromptSubmit cases
// carry `prompt` instead — genuinely a different envelope, not a family
// that "stays unreachable", so no `check` field survives anywhere in the
// fixture set.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspectPreToolUse, inspectUserPromptSubmit } from '../src/adapter/dispatch.ts';
import { buildNeutralCall } from '../src/adapter/neutral-call.ts';
import { BASELINE } from '../src/policy/baseline.ts';
import type { VerdictKind } from '../src/types.ts';

const CLAUDE_CODE_PROTOCOL = BASELINE.rules.harness.find((h) => h.id === 'claude-code')!.protocol!;

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
    const prompt = requireString(fixtureCase, 'prompt');
    return inspectUserPromptSubmit(prompt).map((v) => ({ verdict: v.verdict, ruleId: v.ruleId }));
  }

  const toolName = requireString(fixtureCase, 'toolName');
  const call = buildNeutralCall(CLAUDE_CODE_PROTOCOL, toolName, fixtureCase.toolInput ?? {}, null, 'fixture-runner');
  if (call === null) return [];
  const hit = await inspectPreToolUse(call);
  return hit ? [{ verdict: hit.verdict.verdict, ruleId: hit.verdict.ruleId }] : [];
}
