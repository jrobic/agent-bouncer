// Harness declarations are policy data shared by the embedded baseline and
// overlays. This module owns their leaf shape, dialect, witness, and local
// uniqueness validation so neither source can drift.

import { lintRegexSource } from './lint.ts';
import { compileRules } from './match.ts';
import type { DerivedHarnessRule, HarnessDeclaration, HarnessOverlay, HarnessPersistent, RegexRule } from './schema.ts';

type HarnessFields = Readonly<{
  id: string;
  dir?: readonly string[];
  parents?: readonly string[];
  env?: readonly string[];
  witness?: string;
  reason?: string;
  persistent?: readonly HarnessPersistent[];
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
