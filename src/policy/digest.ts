import { createHash } from 'node:crypto';
import type { ActiveOverride, ActiveRelaxation } from './load.ts';
import type { RulesPolicy } from './schema.ts';

type CanonicalValue = boolean | number | string | null | CanonicalValue[] | { [key: string]: CanonicalValue; };

function canonicalize(value: unknown): CanonicalValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== 'object') throw new Error(`policy digest cannot canonicalize ${typeof value}`);

  const source = value as Record<string, unknown>;
  const result: { [key: string]: CanonicalValue; } = {};
  for (const key of Object.keys(source).toSorted()) {
    if (key === 'reason' || key === 'sourceFile' || key === 'sourceFiles' || key === 'shadows') continue;
    const item = source[key];
    if (item !== undefined) result[key] = canonicalize(item);
  }
  return result;
}

/** Hashes the policy decisions, excluding explanations and load provenance. */
export function policyDigest(
  policy: RulesPolicy,
  overrides: readonly ActiveOverride[],
  relaxations: readonly ActiveRelaxation[],
): string {
  const canonicalJson = JSON.stringify(canonicalize({ policy, overrides, relaxations }));
  return createHash('sha256').update(canonicalJson).digest('hex').slice(0, 12);
}
