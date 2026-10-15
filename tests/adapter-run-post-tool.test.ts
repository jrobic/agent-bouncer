// Post-tool redaction through run() (ADR-0008): every tool's output,
// before the model sees it, with the value of a protected environment variable
// replaced by `[redacted: NAME]` in the response's OWN shape. Every name and
// value is made up, and the environment is handed to run() as `options.env` —
// never the machine's (tests/setup.ts also drops the protected names from this
// process).

import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { POST_TOOL_WITHHELD } from '../src/adapter/post-tool.ts';
import * as render from '../src/adapter/render.ts';
import { run } from '../src/adapter/run.ts';
import type { EnvRecord } from '../src/env-value-rules.ts';
import { tmpDir } from './tmp.ts';

const VALUE = 'Zq7-made-up-0042';
const ENV: EnvRecord = { FAKE_API_TOKEN: VALUE, HOME: '/tmp/home' };
const MARKER = '[redacted: FAKE_API_TOKEN]';
const b64 = (value: string): string => Buffer.from(value).toString('base64');
const hex = (value: string): string => Buffer.from(value).toString('hex');
const SPELLINGS = [VALUE, b64(VALUE), b64(VALUE).replaceAll('=', ''), hex(VALUE), hex(VALUE).toUpperCase()];

const ACCOUNT_VARS = ['HOME', 'CLAUDE_CONFIG_DIR', 'PI_CODING_AGENT_DIR'] as const;
const SAVED = ACCOUNT_VARS.map((name) => [name, process.env[name]] as const);
let accountDir: string;

beforeEach(() => {
  accountDir = tmpDir('bouncer-post-tool-');
  process.env.HOME = accountDir;
  process.env.CLAUDE_CONFIG_DIR = join(accountDir, '.claude');
  process.env.PI_CODING_AGENT_DIR = join(accountDir, '.pi');
});

afterEach(() => {
  for (const [name, saved] of SAVED) {
    if (saved === undefined) delete process.env[name];
    else process.env[name] = saved;
  }
});

async function readLog(dir = '.claude'): Promise<string> {
  return readFile(join(accountDir, dir, 'logs', 'hooks', 'bouncer.log'), 'utf-8').catch(() => '');
}

async function logEntries(dir = '.claude'): Promise<Record<string, unknown>[]> {
  return (await readLog(dir)).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
}
const ENV_VALUE_AUDIT_FIELDS = [
  'build',
  'env_vars',
  'family',
  'harness',
  'policy',
  'rule_id',
  'session_id',
  'target',
  'timestamp',
  'tool_name',
  'verdict',
];

function postToolUse(toolName: string, toolResponse: unknown): string {
  return JSON.stringify({
    hook_event_name: 'PostToolUse',
    session_id: 'session-1',
    tool_name: toolName,
    tool_input: {},
    tool_response: toolResponse,
  });
}

function postToolFailure(toolName: string, error: string): string {
  return JSON.stringify({
    hook_event_name: 'PostToolUseFailure',
    session_id: 'session-1',
    tool_name: toolName,
    tool_input: { command: 'fake command' },
    error,
  });
}

async function installSilentFlagHarness(): Promise<void> {
  const dir = join(accountDir, '.agents', 'bouncer', 'harness.d');
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, 'failed-tool-alert-silent.toml'),
    `
[[harness]]
id = "failed-tool-alert-silent"
dir = ["~/.claude"]
witness = "~/.claude"
env = ["CLAUDE_CONFIG_DIR"]
reason = "failed-tool alert test harness"

[harness.protocol]
transport = "stdin-json"
wiring = "hook-file"

[harness.protocol.input]
event = "hook_event_name"
tool = "tool_name"
input = "tool_input"
session = "session_id"
cwd = "cwd"
error = "error"

[harness.protocol.events]
pre_tool = "PreToolUse"
post_tool_failure = "PostToolUseFailure"

[harness.protocol.tools]
Bash = { role = "command", command = "command" }

[harness.protocol.output]
block = "deny"
confirm = "deny"
observe = "silent"
flag = "silent"
on_malformed = "allow"

[harness.protocol.output.deny]
stdout = '{"decision":"deny","reason":\${reason}}'

[harness.protocol.output.failure_context]
stdout = '{"hookSpecificOutput":{"hookEventName":"PostToolUseFailure","additionalContext":\${context}}}'
`,
    'utf-8',
  );
}

function toolResult(toolName: string, content: unknown, isError = false): string {
  return JSON.stringify({ event: 'tool_result', toolName, input: {}, content, isError, session: 'session-1', cwd: null });
}

/** The `updatedToolOutput` a Claude Code answer carries, or null when run() stayed silent. */
function updatedToolOutput(stdout: string | null): unknown {
  if (stdout === null) return null;
  const { hookSpecificOutput } = JSON.parse(stdout);
  expect(hookSpecificOutput.hookEventName).toBe('PostToolUse');
  return hookSpecificOutput.updatedToolOutput;
}

// Each tool's real response shape (measured live, 2026-10-13), built
// around one text: the input carries a spelling of the value, the expected
// output the marker — so "same keys and value types" is the shape itself.
const RESPONSES: Readonly<Record<string, (text: string) => unknown>> = {
  Bash: (text) => ({ stdout: `token=${text}\n`, stderr: '', interrupted: false, isImage: false, noOutputExpected: false }),
  Read: (text) => ({
    type: 'text',
    file: { filePath: '/tmp/work/secret.txt', content: `1\ttoken_line=${text}`, numLines: 1, startLine: 1, totalLines: 1 },
  }),
  Grep: (text) => ({
    mode: 'content',
    numFiles: 0,
    filenames: [],
    content: `/tmp/work/secret.txt:1:token_line=${text}`,
    numLines: 1,
    totalLines: 1,
  }),
  mcp__probe__leak: (text) => [{ type: 'text', text: `mcp says: ${text}` }],
};

describe('post-tool redaction and failed-output alerts: Claude Code', () => {
  test.each(SPELLINGS)('a failed tool output carrying %s gives the model a name-only alert', async (spelling) => {
    const { stdout } = await run(postToolFailure('Bash', `Exit code 1\n${spelling}`), { env: ENV });
    expect(JSON.parse(stdout!).hookSpecificOutput).toEqual({
      hookEventName: 'PostToolUseFailure',
      additionalContext:
        'bouncer: the failed tool output above contains the value of FAKE_API_TOKEN, a protected environment variable. Do not repeat, store or send it; reference the variable by name.',
    });
    expect(stdout).not.toContain(VALUE);
  });

  test('clean failed output is silent and does not create an audit entry', async () => {
    const { stdout } = await run(postToolFailure('Bash', 'Exit code 1\nordinary failure'), { env: ENV });
    expect(stdout).toBeNull();
    expect(await readLog()).toBe('');
  });

  test.each([
    ['absent', JSON.stringify({ hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_input: {} })],
    ['non-string', JSON.stringify({ hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_input: {}, error: 42 })],
  ])('an %s failed-output error is silent and unlogged', async (_label, envelope) => {
    const { stdout } = await run(envelope, { env: ENV });
    expect(stdout).toBeNull();
    expect(await readLog()).toBe('');
  });

  test('flag = "silent" logs a hit without rendering failure context', async () => {
    await installSilentFlagHarness();
    const result = await run(postToolFailure('Bash', VALUE), { harness: 'failed-tool-alert-silent', env: ENV });
    expect(result.exit).toBeUndefined();
    expect(result.stdout).toBeNull();
    const entry = (await logEntries()).at(-1)!;
    expect(entry).toMatchObject({
      family: 'write-secret',
      verdict: 'flag',
      env_vars: ['FAKE_API_TOKEN'],
    });
    expect(Object.keys(entry).toSorted()).toEqual(ENV_VALUE_AUDIT_FIELDS);
  });

  test('a hit logs tool and names only with the existing env-value fields', async () => {
    await run(postToolFailure('Bash', `Exit code 1\n${VALUE} ${b64(VALUE)} ${hex(VALUE)}`), { env: ENV });
    const log = await readLog();
    const entry = (await logEntries()).at(-1)!;
    expect(entry).toMatchObject({
      family: 'write-secret',
      verdict: 'flag',
      rule_id: 'env-value',
      target: '(failed tool output)',
      tool_name: 'Bash',
      env_vars: ['FAKE_API_TOKEN'],
    });
    expect(Object.keys(entry).toSorted()).toEqual(ENV_VALUE_AUDIT_FIELDS);
    for (const spelling of SPELLINGS) expect(log).not.toContain(spelling);
  });

  test('multiple protected variables are all named in the alert and log', async () => {
    const env = { ALPHA_TOKEN: 'alpha-value-0042', BETA_SECRET: 'beta-value-0042' };
    const { stdout } = await run(
      postToolFailure('Read', `Exit code 1\n${env.ALPHA_TOKEN} and ${env.BETA_SECRET}`),
      { env },
    );
    expect(JSON.parse(stdout!).hookSpecificOutput.additionalContext).toBe(
      'bouncer: the failed tool output above contains the values of ALPHA_TOKEN, BETA_SECRET, protected environment variables. Do not repeat, store or send them; reference the variables by name.',
    );
    expect((await logEntries()).at(-1)).toMatchObject({ tool_name: 'Read', env_vars: ['ALPHA_TOKEN', 'BETA_SECRET'] });
    expect(stdout).not.toContain(env.ALPHA_TOKEN);
    expect(stdout).not.toContain(env.BETA_SECRET);
  });

  test('--shadow logs a hit without sending the alert', async () => {
    const { stdout } = await run(postToolFailure('Bash', `Exit code 1\n${VALUE}`), { env: ENV, shadow: true });
    expect(stdout).toBeNull();
    expect((await logEntries()).at(-1)).toMatchObject({
      verdict: 'flag',
      env_vars: ['FAKE_API_TOKEN'],
      mode: 'shadow',
    });
  });

  for (const [toolName, response] of Object.entries(RESPONSES)) {
    test.each(SPELLINGS)(`${toolName}: %s is replaced in the response's own shape`, async (spelling) => {
      const { stdout, exit } = await run(postToolUse(toolName, response(spelling)), { env: ENV });
      expect(updatedToolOutput(stdout)).toEqual(response(MARKER));
      expect(exit).toBeUndefined();
    });
  }

  test('a response with no protected value is silent: no rewrite emitted, nothing logged', async () => {
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!('hello')), { env: ENV });
    expect(stdout).toBeNull();
    expect(await readLog()).toBe('');
  });

  test('a PostToolUse envelope with no tool_response is silent: nothing to rewrite', async () => {
    const envelope = JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
    expect((await run(envelope, { env: ENV })).stdout).toBeNull();
  });

  test('a value inside a JSON-escaped string leaf is matched on the decoded leaf', async () => {
    const escaped = 'quo"te\\back\nline-0042';
    const envelope = postToolUse('Bash', RESPONSES.Bash!(escaped));
    expect(envelope).not.toContain(escaped); // on the wire it is escaped
    const { stdout } = await run(envelope, { env: { FAKE_API_TOKEN: escaped } });
    expect(updatedToolOutput(stdout)).toEqual(RESPONSES.Bash!(MARKER));
  });

  test('a protected name whose value is under 8 characters is left alone', async () => {
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!('short-7')), { env: { FAKE_API_TOKEN: 'short-7' } });
    expect(stdout).toBeNull();
  });

  test('two variables whose values overlap: one span naming both, no tail left in clear', async () => {
    const env = { ALPHA_TOKEN: 'abcdefgh-1234', BETA_TOKEN: '1234-zyxwvuts' };
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!('abcdefgh-1234-zyxwvuts')), { env });
    expect(updatedToolOutput(stdout)).toEqual(RESPONSES.Bash!('[redacted: ALPHA_TOKEN, BETA_TOKEN]'));
  });

  test('a value contained in a longer one: the longer value names the span', async () => {
    const env = { INNER_TOKEN: 'inner-value-42', OUTER_TOKEN: 'prefix-inner-value-42-suffix' };
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!('prefix-inner-value-42-suffix and inner-value-42')), { env });
    expect(updatedToolOutput(stdout)).toEqual(RESPONSES.Bash!('[redacted: OUTER_TOKEN] and [redacted: INNER_TOKEN]'));
  });

  test('image data is left alone: an image block in an MCP result is returned untouched', async () => {
    const image = { type: 'image', data: b64(VALUE), mimeType: 'image/png' };
    const { stdout } = await run(postToolUse('mcp__probe__leak', [{ type: 'text', text: VALUE }, image]), { env: ENV });
    expect(updatedToolOutput(stdout)).toEqual([{ type: 'text', text: MARKER }, image]);
  });

  test('a Read of an image (file.base64) alone is silent', async () => {
    const response = { type: 'image', file: { base64: b64(VALUE), type: 'image/png', originalSize: 70 } };
    expect((await run(postToolUse('Read', response), { env: ENV })).stdout).toBeNull();
  });

  test('a hit is logged with the tool name and the variable name — verdict "redact", rule env-value', async () => {
    await run(postToolUse('Grep', RESPONSES.Grep!(VALUE)), { env: ENV });
    expect((await logEntries()).at(-1)).toMatchObject({
      harness: 'claude-code',
      session_id: 'session-1',
      tool_name: 'Grep',
      family: 'write-secret',
      verdict: 'redact',
      rule_id: 'env-value',
      target: '(tool output)',
      env_vars: ['FAKE_API_TOKEN'],
    });
  });

  test('--shadow: detected and logged with mode "shadow", nothing printed', async () => {
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: ENV, shadow: true });
    expect(stdout).toBeNull();
    expect((await logEntries()).at(-1)).toMatchObject({ verdict: 'redact', env_vars: ['FAKE_API_TOKEN'], mode: 'shadow' });
  });
});

describe('post-tool redaction: pi-agent tool_result', () => {
  test('a text block carrying the value comes back as a { content } patch, other blocks untouched', async () => {
    const image = { type: 'image', data: 'iVBORw0KGgo=', mimeType: 'image/png' };
    const { stdout } = await run(toolResult('bash', [{ type: 'text', text: `token=${VALUE}\n` }, image]), {
      harness: 'pi-agent',
      env: ENV,
    });
    expect(JSON.parse(stdout!)).toEqual({ content: [{ type: 'text', text: `token=${MARKER}\n` }, image] });
  });

  test('a failed tool (isError: true) is redacted too', async () => {
    const { stdout } = await run(toolResult('bash', [{ type: 'text', text: `Exit code 3\n${VALUE}` }], true), {
      harness: 'pi-agent',
      env: ENV,
    });
    expect(JSON.parse(stdout!)).toEqual({ content: [{ type: 'text', text: `Exit code 3\n${MARKER}` }] });
  });

  test('nothing to redact: silent (the shim then returns undefined)', async () => {
    const { stdout } = await run(toolResult('read', [{ type: 'text', text: 'hello' }]), { harness: 'pi-agent', env: ENV });
    expect(stdout).toBeNull();
  });
});

describe('post-tool redaction: a failure never falls through to silence', () => {
  const stderrLines: string[] = [];
  const spies: { mockRestore: () => void; }[] = [];

  beforeEach(() => {
    stderrLines.length = 0;
    spies.push(
      spyOn(console, 'error').mockImplementation((...args: unknown[]) => void stderrLines.push(args.join(' '))),
      spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
        stderrLines.push(String(chunk));
        return true;
      }) as typeof process.stderr.write),
    );
  });

  afterEach(() => {
    for (const spy of spies.splice(0)) spy.mockRestore();
  });

  function expectNoValueAnywhere(...surfaces: readonly (string | null)[]): void {
    for (const surface of [...surfaces, ...stderrLines]) {
      for (const secret of SPELLINGS) expect(surface ?? '').not.toContain(secret);
    }
  }

  // An environment that cannot be read at all — the in-process failure the
  // redactor cannot get past, on both dispatcher attempts — and whose error
  // message embeds the value.
  function unreadableEnv(): EnvRecord {
    const broken: Record<string, string> = {};
    Object.defineProperty(broken, 'FAKE_API_TOKEN', {
      enumerable: true,
      get() {
        throw new Error(`cannot read the environment, last value ${VALUE}`);
      },
    });
    return broken;
  }

  test('Bash: the withheld message in the response\'s own shape (keys, booleans and empty strings kept)', async () => {
    const { stdout, exit } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: unreadableEnv() });
    expect(updatedToolOutput(stdout)).toEqual({
      stdout: POST_TOOL_WITHHELD,
      stderr: '',
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    expect(exit).toBeUndefined();
  });

  test('Read: the `type` discriminator and the numbers are kept, every text that could hold a value withheld', async () => {
    const { stdout } = await run(postToolUse('Read', RESPONSES.Read!(VALUE)), { env: unreadableEnv() });
    expect(updatedToolOutput(stdout)).toEqual({
      type: 'text',
      file: { filePath: POST_TOOL_WITHHELD, content: POST_TOOL_WITHHELD, numLines: 1, startLine: 1, totalLines: 1 },
    });
  });

  test('Grep: a string under the value floor (the `mode` enum) is kept — it cannot hold a value — longer texts withheld', async () => {
    const { stdout } = await run(postToolUse('Grep', RESPONSES.Grep!(VALUE)), { env: unreadableEnv() });
    expect(updatedToolOutput(stdout)).toEqual({
      mode: 'content',
      numFiles: 0,
      filenames: [],
      content: POST_TOOL_WITHHELD,
      numLines: 1,
      totalLines: 1,
    });
  });

  test('a redacted answer that fails to render: the withheld answer instead, the failure logged without the value', async () => {
    spies.push(
      spyOn(render, 'renderRedaction').mockImplementationOnce(() => {
        throw new Error(`cannot render ${VALUE}`);
      }),
    );
    const { stdout, exit } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: ENV });
    expect(updatedToolOutput(stdout)).toEqual({
      stdout: POST_TOOL_WITHHELD,
      stderr: '',
      interrupted: false,
      isImage: false,
      noOutputExpected: false,
    });
    expect(exit).toBeUndefined();
    const warnings = (await logEntries()).filter((entry) => entry.kind === 'policy-warning').map((entry) => entry.message);
    expect(warnings).toEqual([
      'post-tool check failed, output withheld (error message withheld: it contains the value of a protected environment variable: FAKE_API_TOKEN)',
    ]);
    expectNoValueAnywhere(await readLog(), stdout);
  });

  test('the withheld answer itself fails to render: no stdout, exit 2, one stderr line (the shim withholds on any non-zero exit)', async () => {
    spies.push(
      spyOn(render, 'renderRedaction').mockImplementation(() => {
        throw new Error('cannot render');
      }),
    );
    const { stdout, exit } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: unreadableEnv() });
    expect({ stdout, exit }).toEqual({ stdout: null, exit: 2 });
    expect(stderrLines.join('')).toContain('post-tool check failed and the withheld answer could not be rendered — failing closed');
    expectNoValueAnywhere(await readLog(), stdout);
  });

  test('pi-agent: a { content } patch with every text block withheld', async () => {
    const { stdout } = await run(toolResult('bash', [{ type: 'text', text: VALUE }]), { harness: 'pi-agent', env: unreadableEnv() });
    expect(JSON.parse(stdout!)).toEqual({ content: [{ type: 'text', text: POST_TOOL_WITHHELD }] });
  });

  test('the failure is logged as a policy-warning that withholds the error text, and nothing carries the value', async () => {
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: unreadableEnv() });
    const log = await readLog();
    const warnings = (await logEntries()).filter((entry) => entry.kind === 'policy-warning').map((entry) => entry.message);
    expect(warnings).toContain('post-tool check failed, output withheld (error message withheld: the environment could not be scanned)');
    expectNoValueAnywhere(log, stdout);
  });

  test('failure-event scanner errors stay silent and log only fixed policy warnings', async () => {
    const { stdout, exit } = await run(postToolFailure('Bash', `Exit code 1\n${VALUE}`), { env: unreadableEnv() });
    const log = await readLog();
    const warnings = (await logEntries()).filter((entry) => entry.kind === 'policy-warning').map((entry) => entry.message);
    expect({ stdout, exit }).toEqual({ stdout: null, exit: undefined });
    expect(warnings).toEqual([
      'post-tool failure alert check failed, retrying with the embedded baseline',
      'post-tool failure alert check failed',
    ]);
    expectNoValueAnywhere(log, stdout);
  });

  test('a transient environment read failure retries against the baseline and logs the finding', async () => {
    let reads = 0;
    const flaky: Record<string, string> = {};
    Object.defineProperty(flaky, 'FAKE_API_TOKEN', {
      enumerable: true,
      get() {
        reads += 1;
        if (reads === 1) throw new Error('first environment read failed');
        return VALUE;
      },
    });
    const { stdout } = await run(postToolFailure('Bash', `Exit code 1\n${VALUE}`), { env: flaky });
    expect(JSON.parse(stdout!).hookSpecificOutput.additionalContext).toContain('FAKE_API_TOKEN');
    expect((await logEntries()).at(-1)).toMatchObject({ verdict: 'flag', env_vars: ['FAKE_API_TOKEN'] });
    expect(await readLog()).not.toContain('first environment read failed');
  });

  test('a failed alert render logs only the fixed warning, never exception text', async () => {
    spies.push(
      spyOn(render, 'renderFailureContext').mockImplementationOnce(() => {
        throw new Error('renderer rejected a harmless context');
      }),
    );
    const { stdout, exit } = await run(postToolFailure('Bash', VALUE), { env: ENV });
    expect({ stdout, exit }).toEqual({ stdout: null, exit: undefined });
    const entries = await logEntries();
    const warnings = entries.filter((entry) => entry.kind === 'policy-warning').map((entry) => entry.message);
    expect(warnings).toEqual(['post-tool failure alert render failed']);
    expect(await readLog()).not.toContain('renderer rejected a harmless context');
  });

  test('--shadow: a failure prints nothing either', async () => {
    expect((await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: unreadableEnv(), shadow: true })).stdout).toBeNull();
  });

  test('a first failure only: the baseline retry still redacts', async () => {
    let reads = 0;
    const flaky: Record<string, string> = {};
    Object.defineProperty(flaky, 'FAKE_API_TOKEN', {
      enumerable: true,
      get() {
        reads += 1;
        if (reads === 1) throw new Error('simulated failure while reading the environment');
        return VALUE;
      },
    });
    const { stdout } = await run(postToolUse('Bash', RESPONSES.Bash!(VALUE)), { env: flaky });
    expect(updatedToolOutput(stdout)).toEqual(RESPONSES.Bash!(MARKER));
  });

  test('a redaction run: the value is in no log line, stdout or stderr — the name and the tool name are', async () => {
    const response = RESPONSES.Bash!(`${VALUE} ${b64(VALUE)} ${hex(VALUE)}`);
    const { stdout } = await run(postToolUse('Bash', response), { env: ENV });
    const log = await readLog();
    const entry = (await logEntries()).at(-1)!;
    expect(log).toContain('"env_vars":["FAKE_API_TOKEN"]');
    expect(log).toContain('"tool_name":"Bash"');
    expect(Object.keys(entry).toSorted()).toEqual(ENV_VALUE_AUDIT_FIELDS);
    expectNoValueAnywhere(log, stdout);
  });
});

describe('post-tool redaction: one switch, the env-value row', () => {
  async function overlay(toml: string): Promise<void> {
    const dir = join(accountDir, '.claude', 'bouncer');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'policy.toml'), toml, 'utf-8');
  }
  const envelope = postToolUse('Bash', RESPONSES.Bash!(VALUE));
  const failureEnvelope = postToolFailure('Bash', `Exit code 1\n${VALUE}`);

  test('[[override]] disable: redaction and failed-output alert are off', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "disable"\nreason = "fixtures share the dev password"\n');
    expect((await run(envelope, { env: ENV })).stdout).toBeNull();
    expect((await run(failureEnvelope, { env: ENV })).stdout).toBeNull();
    expect(await readLog()).toBe('');
  });

  test('[[override]] relax: redaction and failed-output alert are off too', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "relax"\nverdict = "confirm"\nreason = "review each write"\n');
    expect((await run(envelope, { env: ENV })).stdout).toBeNull();
    expect((await run(failureEnvelope, { env: ENV })).stdout).toBeNull();
    expect(await readLog()).toBe('');
  });

  test('[[override]] replace governs writes only: an output its regex does not match is still redacted', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "replace"\nregex = "^only-this$"\nreason = "only one text"\n');
    const { stdout } = await run(envelope, { env: ENV });
    expect(updatedToolOutput(stdout)).toEqual(RESPONSES.Bash!(MARKER));
  });

  test('[[override]] replace controls writes only: a non-matching failed output still alerts', async () => {
    await overlay('[[override]]\nrule = "env-value"\naction = "replace"\nregex = "^only-this$"\nreason = "only one text"\n');
    const { stdout } = await run(failureEnvelope, { env: ENV });
    expect(JSON.parse(stdout!).hookSpecificOutput.hookEventName).toBe('PostToolUseFailure');
    expect(stdout).toContain('FAKE_API_TOKEN');
  });
});

// The answer is the whole rewritten output, so it can be large: the CLI must
// hand all of it to the pipe before it exits. Spawned the way the shim spawns
// it — a blocking spawnSync reading stdout — the reader most likely to see a
// truncated write (pipes are asynchronous on macOS; exiting at once drops what
// the pipe has not taken yet).
describe('post-tool redaction: the CLI delivers a large answer whole', () => {
  test('a 1 MiB tool output with the value in it comes back complete and parseable', () => {
    const chunk = `${'x'.repeat(16 * 1024 - VALUE.length - 1)}${VALUE}\n`;
    const content = [{ type: 'text', text: chunk.repeat(64) }];
    const child = spawnSync('bun', ['run', 'src/cli.ts', 'run', '--harness', 'pi-agent'], {
      cwd: join(import.meta.dir, '..'),
      input: toolResult('mcp', content),
      env: { ...process.env, HOME: accountDir, PI_CODING_AGENT_DIR: join(accountDir, '.pi'), FAKE_API_TOKEN: VALUE },
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout)).toEqual({ content: [{ type: 'text', text: chunk.replaceAll(VALUE, MARKER).repeat(64) }] });
  }, 30_000);
});
