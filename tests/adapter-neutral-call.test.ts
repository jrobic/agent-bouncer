// The tools-map selector engine (src/adapter/neutral-call.ts) — the seam
// this file protects is (toolName, tool_input) -> NeutralCall, driven by a
// `[harness.protocol.tools]` row instead of the pre-15a hardcoded readers
// (src/targets.ts's extractTargets/isGuardedToolName, src/adapter/
// dispatch.ts's NATIVE_FILE_PATH_FIELD/writeSecretText). Composes a small
// hand-built protocol locally, proving the extraction primitive itself is
// usable on the new neutral seam — not a duplicate of the real
// claude-code declaration's own coverage (tests/fixtures-protocol.test.ts,
// tests/fixtures.test.ts already prove that end to end).

import { describe, expect, test } from 'bun:test';
import { buildCommandInputBag, buildNeutralCall, expandPathCandidates } from '../src/adapter/neutral-call.ts';
import type { HarnessProtocol } from '../src/policy/schema.ts';

const PROTOCOL: HarnessProtocol = {
  transport: 'stdin-json',
  input: { event: 'e', tool: 't', input: 'i', session: 's', prompt: 'p', cwd: 'c' },
  events: { pre_tool: 'PreToolUse', prompt: 'UserPromptSubmit', session_start: 'SessionStart' },
  tools: {
    Bash: { role: 'command', command: 'command' },
    Read: { role: 'read', path: 'file_path' },
    Glob: { role: 'read', path: 'path', pattern: 'pattern' },
    Write: { role: 'write', path: 'file_path', text: 'content' },
    MultiEdit: { role: 'write', path: 'file_path', text: 'edits[].new_string' },
    BatchExec: { role: 'command', command: 'commands[].command' },
    FetchIndex: { role: 'fetch', url: 'url', urls: 'requests[].url' },
    'mcp__*': { role: 'mcp' },
  },
  output: { block: 'deny', confirm: 'ask', observe: 'silent', flag: 'context', on_malformed: 'allow', ask_probe: 'x' },
  templates: {},
};

describe('buildNeutralCall: row resolution', () => {
  test('a name matching no row (exact or glob) is not judged — returns null', () => {
    expect(buildNeutralCall(PROTOCOL, 'TodoWrite', {}, null, 'test')).toBeNull();
  });

  test('an exact row wins over a glob row for the same prefix', () => {
    const call = buildNeutralCall(PROTOCOL, 'Bash', { command: 'ls' }, null, 'test');
    expect(call?.role).toBe('command');
    expect(call?.mcpName).toBeNull();
  });

  test('an unclaimed mcp__ name falls through to the glob row', () => {
    const call = buildNeutralCall(PROTOCOL, 'mcp__github__create_issue', {}, null, 'test');
    expect(call?.role).toBe('mcp');
    expect(call?.mcpName).toBe('mcp__github__create_issue');
  });
});

describe('buildNeutralCall: plain selectors', () => {
  test('a plain command selector reads a single string', () => {
    const call = buildNeutralCall(PROTOCOL, 'Bash', { command: 'rm -rf /' }, null, 'test');
    expect(call?.commands).toEqual(['rm -rf /']);
  });

  test('read role: pattern and path both populate, independently', () => {
    const call = buildNeutralCall(PROTOCOL, 'Glob', { path: '~/.ssh', pattern: '*.pem' }, null, 'test');
    expect(call?.paths).toEqual(['~/.ssh']);
    expect(call?.pattern).toBe('*.pem');
  });

  test('a missing field is silently absent — no value, no warning', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', {}, null, 'test');
    expect(call?.paths).toEqual([]);
  });

  test('a wrong-typed field logs a diagnostic and resolves to no value', () => {
    const logs: string[] = [];
    const original = console.error;
    console.error = (msg: string) => logs.push(msg);
    try {
      const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: 42 }, null, 'test');
      expect(call?.paths).toEqual([]);
    } finally {
      console.error = original;
    }
    expect(logs.some((l) => l.includes('expected string for tool_input.file_path'))).toBe(true);
  });
});

describe('buildNeutralCall: array selectors', () => {
  test('commands[].command accepts a bare string element', () => {
    const call = buildNeutralCall(PROTOCOL, 'BatchExec', { commands: ['ls -la'] }, null, 'test');
    expect(call?.commands).toEqual(['ls -la']);
  });

  test('commands[].command accepts an object element with a .command field', () => {
    const call = buildNeutralCall(PROTOCOL, 'BatchExec', { commands: [{ label: 'x', command: 'rm -rf /' }] }, null, 'test');
    expect(call?.commands).toEqual(['rm -rf /']);
  });

  test('commands[].command mixes string and object entries in one call, order preserved', () => {
    const call = buildNeutralCall(
      PROTOCOL,
      'BatchExec',
      { commands: ['ls -la', { label: 'danger', command: 'rm -rf /' }] },
      null,
      'test',
    );
    expect(call?.commands).toEqual(['ls -la', 'rm -rf /']);
  });

  test('an unreadable entry is skipped, not thrown on', () => {
    const call = buildNeutralCall(PROTOCOL, 'BatchExec', { commands: ['ls', 42, { no_command: true }] }, null, 'test');
    expect(call?.commands).toEqual(['ls']);
  });

  test('text[].field joins every element with a newline, substituting "" for a malformed entry', () => {
    const call = buildNeutralCall(
      PROTOCOL,
      'MultiEdit',
      { file_path: '/tmp/x', edits: [{ new_string: 'a' }, { no_new_string: true }, { new_string: 'c' }] },
      null,
      'test',
    );
    expect(call?.text).toBe('a\n\nc');
  });

  test('requests[].url silently drops entries missing a string url (no diagnostic)', () => {
    const call = buildNeutralCall(
      PROTOCOL,
      'FetchIndex',
      { url: 'https://example.com', requests: [{ url: 'https://a.example' }, { source: 'no-url' }] },
      null,
      'test',
    );
    expect(call?.urls).toEqual(['https://example.com', 'https://a.example']);
  });
});

describe('buildNeutralCall: cwd-relative path resolution', () => {
  test('a relative path is joined against cwd before being returned', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: 'sub/file.txt' }, '/session/dir', 'test');
    expect(call?.paths).toEqual(['/session/dir/sub/file.txt']);
  });

  test('an absolute path is left untouched even when cwd is set', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: '/etc/passwd' }, '/session/dir', 'test');
    expect(call?.paths).toEqual(['/etc/passwd']);
  });

  test('no cwd (harness never sends one) leaves a relative path exactly as given', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: 'relative.txt' }, null, 'test');
    expect(call?.paths).toEqual(['relative.txt']);
  });
});

// Review round 1 L-1 (lead): `~/.zsh_history:1-5`, `proj/secrets.pem:1-2`,
// `proj/.envrc; proj/README.md`, and `archive.zip:inner/.env` all read as
// `allow` against the raw string alone — every `$`-anchored path rule is
// written against the LITERAL target, never a superstring carrying a
// trailing selector or list. `expandPathCandidates` is exercised directly
// (no `[harness.protocol.tools]` row involved) so a bug in the candidate
// algorithm itself can't hide behind buildNeutralCall's own role gate
// (covered separately below).
describe('expandPathCandidates', () => {
  test('a plain path with no ":" or ";" yields exactly itself', () => {
    expect(expandPathCandidates('~/.ssh/id_rsa')).toEqual(['~/.ssh/id_rsa']);
  });

  test('a trailing ":N-M" selector also yields the bare path', () => {
    expect(expandPathCandidates('~/.zsh_history:1-5')).toEqual(['~/.zsh_history:1-5', '~/.zsh_history']);
  });

  test('a trailing ":raw"/":N-M" selector on a dotfile also yields the bare path', () => {
    expect(expandPathCandidates('proj/.env:1-3')).toEqual(['proj/.env:1-3', 'proj/.env']);
    expect(expandPathCandidates('proj/.env:raw')).toEqual(['proj/.env:raw', 'proj/.env']);
  });

  test('a trailing ":N-M" selector on a non-dotfile also yields the bare path', () => {
    expect(expandPathCandidates('proj/secrets.pem:1-2')).toEqual(['proj/secrets.pem:1-2', 'proj/secrets.pem']);
  });

  test('a ";"-joined list yields each trimmed segment plus the raw joined string', () => {
    expect(expandPathCandidates('proj/.envrc; proj/README.md')).toEqual([
      'proj/.envrc; proj/README.md',
      'proj/.envrc',
      'proj/README.md',
    ]);
  });

  test('multiple colon segments strip progressively, right to left ("a:b:c" -> "a:b", "a")', () => {
    expect(expandPathCandidates('a:b:c')).toEqual(['a:b:c', 'a:b', 'a']);
  });

  test('an archive member selector also yields the bare archive path (db.sqlite:table convention)', () => {
    expect(expandPathCandidates('archive.zip:inner/.env')).toEqual(['archive.zip:inner/.env', 'archive.zip']);
  });

  // Review round 2 C-2: the "db.sqlite:table convention" cited above (and
  // in src/adapter/neutral-call.ts's own header comment) was only ever a
  // test NAME, never an assertion against the literal string — this is
  // the real one.
  test('a sqlite row selector also yields the bare database path', () => {
    expect(expandPathCandidates('db.sqlite:table')).toEqual(['db.sqlite:table', 'db.sqlite']);
    expect(expandPathCandidates('db.sqlite:table:key')).toEqual(['db.sqlite:table:key', 'db.sqlite:table', 'db.sqlite']);
  });

  test('a raw path that is entirely a colon (degenerate) never loops forever and never adds an empty string', () => {
    expect(expandPathCandidates(':')).toEqual([':']);
  });

  test('duplicate candidates across the raw value and its segments are deduplicated', () => {
    // ";"-splitting "a;a" trims to two identical "a" segments, plus the
    // unsplit raw "a;a" itself — three inputs, two distinct outputs.
    expect(expandPathCandidates('a;a')).toEqual(['a;a', 'a']);
  });
});

describe('buildNeutralCall: path-list expansion applies to role="read" only (review round 1 L-1)', () => {
  test('a read-role path selector is expanded to the full candidate set', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: '~/.zsh_history:1-5' }, null, 'test');
    expect(call?.paths).toEqual(['~/.zsh_history:1-5', '~/.zsh_history']);
  });

  test('a write-role path selector is NOT expanded — exactly the raw value, unchanged scope', () => {
    const call = buildNeutralCall(PROTOCOL, 'Write', { file_path: 'proj/.envrc; proj/README.md', content: 'x' }, null, 'test');
    expect(call?.paths).toEqual(['proj/.envrc; proj/README.md']);
  });

  test('expansion composes with cwd-joining: every candidate is joined, not just the raw one', () => {
    const call = buildNeutralCall(PROTOCOL, 'Read', { file_path: 'a:b' }, '/session/dir', 'test');
    expect(call?.paths).toEqual(['/session/dir/a:b', '/session/dir/a']);
  });
});

// Review round 4 R4-1: the inverse of readCommandsSelector's own parsing
// — check (src/cli-commands.ts) is the one caller, since it has no real
// envelope, only a command string and the row it's dry-running against.
// Each case here round-trips through buildNeutralCall + the SAME row's
// selector, proving the bag this function builds is what the reading
// side actually reads back, not just a plausible-looking shape.
describe('buildCommandInputBag: the inverse of a command selector', () => {
  test('a plain key places the command directly under that key', () => {
    expect(buildCommandInputBag('cmd', 'rm -rf /')).toEqual({ cmd: 'rm -rf /' });
    const call = buildNeutralCall(
      { ...PROTOCOL, tools: { sh: { role: 'command', command: 'cmd' } } },
      'sh',
      buildCommandInputBag('cmd', 'rm -rf /'),
      null,
      'test',
    );
    expect(call?.commands).toEqual(['rm -rf /']);
  });

  test('a selector containing a literal dot is a flat key, not nested traversal', () => {
    expect(buildCommandInputBag('payload.cmd', 'rm -rf /')).toEqual({ 'payload.cmd': 'rm -rf /' });
    const call = buildNeutralCall(
      { ...PROTOCOL, tools: { sh: { role: 'command', command: 'payload.cmd' } } },
      'sh',
      buildCommandInputBag('payload.cmd', 'rm -rf /'),
      null,
      'test',
    );
    expect(call?.commands).toEqual(['rm -rf /']);
  });

  test('a `[]` selector with a subfield wraps one object in a one-element array', () => {
    expect(buildCommandInputBag('commands[].command', 'rm -rf /')).toEqual({ commands: [{ command: 'rm -rf /' }] });
    const call = buildNeutralCall(PROTOCOL, 'BatchExec', buildCommandInputBag('commands[].command', 'rm -rf /'), null, 'test');
    expect(call?.commands).toEqual(['rm -rf /']);
  });

  test('a bare `[]` selector with no subfield wraps the command string itself', () => {
    expect(buildCommandInputBag('items[]', 'rm -rf /')).toEqual({ items: ['rm -rf /'] });
    const call = buildNeutralCall(
      { ...PROTOCOL, tools: { sh: { role: 'command', command: 'items[]' } } },
      'sh',
      buildCommandInputBag('items[]', 'rm -rf /'),
      null,
      'test',
    );
    expect(call?.commands).toEqual(['rm -rf /']);
  });
});

describe('buildNeutralCall: codec drift (S-3)', () => {
  // A name `rules lint` accepted (a member of KNOWN_INPUT_CODECS) but the
  // runtime registry (src/adapter/codecs/input/registry.ts) does not
  // implement — the lint-time/runtime pair drifting apart, reachable in
  // practice only as a bug in this repo, never from a real declaration.
  // Before the S-3 fix this failed CLOSED ("not judged") but SILENTLY;
  // it must now also warn, matching doctor.ts's own wiring-drift branch.
  const DRIFTED_PROTOCOL: HarnessProtocol = {
    ...PROTOCOL,
    tools: { ...PROTOCOL.tools, DriftedTool: { role: 'write', codec: 'nonexistent-codec' } },
  };

  test('an unresolvable codec name fails closed to not-judged AND warns on stderr', () => {
    const logs: string[] = [];
    const original = console.error;
    console.error = (msg: string) => logs.push(msg);
    try {
      const call = buildNeutralCall(DRIFTED_PROTOCOL, 'DriftedTool', {}, null, 'test');
      expect(call).toEqual({
        toolName: 'DriftedTool',
        role: 'write',
        commands: [],
        paths: [],
        pattern: null,
        text: null,
        urls: [],
        mcpName: null,
      });
    } finally {
      console.error = original;
    }
    expect(logs.some((l) => l.includes('input codec') && l.includes('nonexistent-codec') && l.includes('no runtime implementation'))).toBe(
      true,
    );
  });
});
