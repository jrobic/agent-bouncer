import { describe, expect, test } from 'bun:test';
import { checkMcpWrite, MCP_READ_PREFIXES } from '../src/mcp-write-rules.ts';

// Every MCP write, on every connected server, asks; reads pass through an
// allowlist of nine operation-name prefixes.
//
// What this file is built around: the module is FAIL-OPEN by construction —
// whatever is not recognised as a write passes. A sloppy allowlist or a
// sloppy extraction therefore breaks nothing visible, it opens. Nine read
// vectors DO NOT PIN THE CONTENT of the allowlist, since an allowlist
// shrunk to single initials (`g`, `l`, `se`, …) satisfies all nine while
// letting `deleteIssue` and `dropTable` through. The nine write NEIGHBOURS
// below are what pins the boundary — `deleteFoo` proves the prefix is
// `describe` and not `d`, `grantFoo` that it is `get` and not `g`. Read
// vectors alone are decorative.

// One read vector per allowlist prefix, and one write neighbour per prefix
// that shares its opening letters without being it. Kept as separate tables,
// one row per prefix, because one proves allowed reads while the other proves
// the fail-open boundary against writes.
const READ_VECTORS: ReadonlyArray<readonly [prefix: string, tool: string]> = [
  ['get', 'mcp__anything__getFoo'],
  ['list', 'mcp__anything__listFoo'],
  ['search', 'mcp__anything__searchFoo'],
  ['fetch', 'mcp__anything__fetchFoo'],
  ['read', 'mcp__anything__readFoo'],
  ['query', 'mcp__anything__queryFoo'],
  ['lookup', 'mcp__anything__lookupFoo'],
  ['describe', 'mcp__anything__describeFoo'],
  ['view', 'mcp__anything__viewFoo'],
];

const WRITE_NEIGHBOURS: ReadonlyArray<readonly [prefix: string, tool: string]> = [
  ['get', 'mcp__anything__grantFoo'],
  ['list', 'mcp__anything__loadFoo'],
  ['search', 'mcp__anything__setFoo'],
  ['fetch', 'mcp__anything__flushFoo'],
  ['read', 'mcp__anything__renameFoo'],
  ['query', 'mcp__anything__quitFoo'],
  ['lookup', 'mcp__anything__lockFoo'],
  ['describe', 'mcp__anything__deleteFoo'],
  ['view', 'mcp__anything__voidFoo'],
];

function operationFromVector(tool: string): string {
  const firstSeparator = tool.indexOf('__');
  const secondSeparator = tool.indexOf('__', firstSeparator + 2);
  if (!tool.startsWith('mcp__') || secondSeparator === -1) {
    throw new Error(
      `invalid MCP coverage vector ${JSON.stringify(tool)}: expected mcp__<server>__<operation>`,
    );
  }

  const operation = tool.slice(secondSeparator + 2);
  if (operation.length === 0) {
    throw new Error(
      `invalid MCP coverage vector ${JSON.stringify(tool)}: the operation must not be empty`,
    );
  }
  return operation;
}

function uncoveredReadPrefixes(): string[] {
  return MCP_READ_PREFIXES.filter((prefix) =>
    !READ_VECTORS.some(([vectorPrefix, tool]) =>
      vectorPrefix === prefix
      && operationFromVector(tool).startsWith(prefix)
      && checkMcpWrite(tool) === null
    )
  );
}

function uncoveredWriteNeighbourPrefixes(): string[] {
  return MCP_READ_PREFIXES.filter((prefix) => {
    if (prefix.length === 0) {
      throw new Error(
        'MCP read prefix coverage cannot derive a write neighbour for an empty prefix',
      );
    }

    const initial = prefix.slice(0, 1);
    return !WRITE_NEIGHBOURS.some(([vectorPrefix, tool]) => {
      const operation = operationFromVector(tool);
      const verdict = checkMcpWrite(tool);
      return vectorPrefix === prefix
        && operation.startsWith(initial)
        && !operation.startsWith(prefix)
        && verdict?.ruleId === 'mcp-write'
        && verdict.verdict === 'confirm';
    });
  });
}

function namedGap(gap: readonly string[]): string {
  return gap.length === 0 ? 'none' : gap.join(', ');
}

describe('mcp-write-rules: MCP_READ_PREFIXES', () => {
  test('the read allowlist is exported and holds nine prefixes', () => {
    // Cardinality remains an immediate size signal. It cannot name a rename or
    // reorder; the ordered digest does that, while the coverage diff below
    // binds every current prefix to both behavioural tables.
    expect(MCP_READ_PREFIXES.length).toBe(9);
  });

  const missingReads = uncoveredReadPrefixes();
  test(`every allowlisted prefix has a passing read vector; missing: ${namedGap(missingReads)}`, () => {
    expect(missingReads, `allowlisted prefixes without a passing read: ${namedGap(missingReads)}`)
      .toEqual([]);
  });

  const missingWriteNeighbours = uncoveredWriteNeighbourPrefixes();
  test(`every allowlisted prefix has an asking write neighbour; missing: ${namedGap(missingWriteNeighbours)}`, () => {
    expect(
      missingWriteNeighbours,
      `allowlisted prefixes without an asking write neighbour: ${namedGap(missingWriteNeighbours)}`,
    ).toEqual([]);
  });
});

describe('mcp-write-rules: an MCP write asks, on any server', () => {
  test('mcp__anything__createFoo asks, with ruleId mcp-write and decision ask', () => {
    const verdict = checkMcpWrite('mcp__anything__createFoo');
    expect(verdict?.ruleId).toBe('mcp-write');
    expect(verdict?.verdict).toBe('confirm');
    expect(verdict?.target).toBe('mcp__anything__createFoo');
  });

  test('the interception does not depend on the server: memory and atlassian both ask', () => {
    expect(checkMcpWrite('mcp__memory__create_entities')?.ruleId).toBe('mcp-write');
    expect(checkMcpWrite('mcp__atlassian__createIssue')?.ruleId).toBe('mcp-write');
  });

  test('a snake_case write is caught like a camelCase one', () => {
    expect(checkMcpWrite('mcp__memory__delete_observations')?.verdict).toBe('confirm');
  });

  test('atlassianUserInfo, historically allowed by a tenant allowlist, now asks', () => {
    // A legacy guard carried a fifth read prefix, `atlassianUserInfo`,
    // scoped to one tenant. It does not survive into the generic trunk — a
    // tenant-scoped allowlist belongs in a sidecar, not in the trunk.
    expect(checkMcpWrite('mcp__atlassian__atlassianUserInfo')?.ruleId).toBe('mcp-write');
  });
});

describe('mcp-write-rules: a read passes, and each prefix\'s boundary holds', () => {
  for (const [prefix, tool] of READ_VECTORS) {
    test(`read prefix ${prefix}: ${tool} passes`, () => {
      expect(checkMcpWrite(tool)).toBeNull();
    });
  }

  // The load-bearing half of this file. Each neighbour shares the opening
  // letters of its prefix without being it, so it only passes if the
  // allowlist entry has been shortened — which is precisely the mutant the
  // nine read vectors above cannot see.
  for (const [prefix, tool] of WRITE_NEIGHBOURS) {
    test(`write neighbour of ${prefix}: ${tool} asks`, () => {
      expect(checkMcpWrite(tool)?.ruleId).toBe('mcp-write');
    });
  }

  test('searchAndDelete is allowed — recognition is on the name\'s start, not its meaning', () => {
    // Accepted residue: correcting it with a list of write verbs would be
    // fail-open in the other direction.
    expect(checkMcpWrite('mcp__anything__searchAndDelete')).toBeNull();
  });
});

describe('mcp-write-rules: the operation is everything after the SECOND __', () => {
  test('a real underscored server passes: mcp__plugin_claude-mem_mcp-search__query_corpus', () => {
    expect(checkMcpWrite('mcp__plugin_claude-mem_mcp-search__query_corpus')).toBeNull();
  });

  test('an underscored server\'s write still asks: mcp__claude_ai_Gmail__createDraft', () => {
    expect(checkMcpWrite('mcp__claude_ai_Gmail__createDraft')?.ruleId).toBe('mcp-write');
  });

  test('a server identifier containing __ cuts at the second __: mcp__plugin__deploy__getStatus asks', () => {
    // The vector that actually discriminates the cut point. The two above do
    // not: both names hold exactly two `__`, so greedy and non-greedy split
    // them at the same place. Here there are three: non-greedy reads the
    // operation as `deploy__getStatus` and asks; greedy reads only the tail,
    // `getStatus`, matches the `get` prefix and lets the call through
    // silently. The module cuts at the second `__` and errs toward asking
    // when the server identifier is itself ambiguous — friction on a read,
    // never a hole.
    expect(checkMcpWrite('mcp__plugin__deploy__getStatus')?.ruleId).toBe('mcp-write');
  });
});

describe('mcp-write-rules: out-of-scope inputs return null', () => {
  test('an empty name passes (the glue coalesces a missing tool_name to \'\')', () => {
    expect(checkMcpWrite('')).toBeNull();
  });

  test('a non-MCP tool passes: Bash', () => {
    expect(checkMcpWrite('Bash')).toBeNull();
  });

  test('a non-MCP tool passes: Read', () => {
    expect(checkMcpWrite('Read')).toBeNull();
  });

  test('a tool containing mcp__ away from its start stays out of scope', () => {
    // The module re-checks the `^mcp__` boundary instead of trusting the
    // adapter's own matcher, so widening the wiring cannot pull an embedded
    // MCP-looking suffix into this guard. `proxy_mcp__anything__createFoo`
    // starts asking, so this mutation is stricter friction rather than a
    // permissive hole.
    expect(checkMcpWrite('proxy_mcp__anything__createFoo')).toBeNull();
  });

  test('a name that only looks MCP-shaped passes: mcp__server (no second __)', () => {
    expect(checkMcpWrite('mcp__server')).toBeNull();
  });

  test('an MCP name with an empty operation passes: mcp__server__', () => {
    expect(checkMcpWrite('mcp__server__')).toBeNull();
  });
});
