// ADR-0006 § 4: `[harness.protocol]` lint — one test per rejection rule,
// each showing the block rejected AS A UNIT (the whole `[[harness]]`
// entry drops, not just its `protocol` sub-table) and the baseline
// standing (claude-code's own declaration, and every non-harness rule,
// stay fully effective). Six of the seven rules are exercised end to end
// through the real overlay pipeline (loadPolicyFromOverlayFiles), the
// same way every other lint rule in this test suite is proved — a
// `harness.d/acme.toml`-shaped file declaring a BRAND NEW harness with one
// deliberately broken `[harness.protocol]` field.
//
// Rule 6 ("an overlay may not relax an EXISTING BASELINE harness's
// 'deny' confirm to 'ask'") is the one exception: no baseline harness in
// ticket 15a's scope carries a `deny` confirm (only claude-code has a
// protocol at all, and its own confirm is `ask` — 15b's codex.toml is the
// first baseline `deny`), so there is no real baseline fixture to drive
// this rule through the pipeline yet. It is proved directly against
// src/policy/harness.ts's pure lintHarnessProtocolConfirmRelaxation
// (the same function src/policy/load.ts's mergeHarnesses wires into the
// real merge — see that module for the call site) and, separately,
// proved WIRED (not dead code) by confirming a same-shaped RELAXATION on
// an OVERLAY-declared harness (never a "baseline measured fact") is
// allowed — the negative space that would catch an accidentally too-broad
// check.

import { describe, expect, test } from 'bun:test';
import { lintHarnessProtocolConfirmRelaxation } from '../src/policy/harness.ts';
import { loadPolicyFromLayers, loadPolicyFromOverlayFiles, type OverlayFile } from '../src/policy/load.ts';

function file(filename: string, text: string): OverlayFile {
  return { filename, text };
}

// A minimal, otherwise-valid protocol table — each test below applies
// exactly one targeted string substitution to violate exactly one rule,
// never appends a second `[harness.protocol.output]` (TOML forbids
// redefining a table).
function validProtocol(): string {
  return `
[harness.protocol]
transport = "stdin-json"

[harness.protocol.input]
event = "hook_event_name"
tool = "tool_name"
input = "tool_input"
session = "session_id"
prompt = "prompt"
cwd = "cwd"

[harness.protocol.events]
pre_tool = "PreToolUse"
prompt = "UserPromptSubmit"
session_start = "SessionStart"

[harness.protocol.tools]
Bash = { role = "command", command = "command" }

[harness.protocol.output]
block = "deny"
confirm = "ask"
observe = "silent"
flag = "context"
on_malformed = "allow"
ask_probe = "test probe"

[harness.protocol.output.deny]
stdout = '{"decision":"deny","reason":\${reason}}'
[harness.protocol.output.ask]
stdout = '{"decision":"ask","reason":\${reason}}'
[harness.protocol.output.context]
stdout = '{"context":\${context}}'
[harness.protocol.output.session_start]
stdout = '{"context":\${context}}'
`;
}

function harnessFile(filename: string, protocolText: string, extraFields = ''): OverlayFile {
  return file(
    filename,
    `
[[harness]]
id = "acme"
dir = ["(^|/)\\\\.acme"]
witness = "~/.acme"
env = ["ACME_HOME"]
reason = "Acme test harness"
${extraFields}${protocolText}
`,
  );
}

function replaceOne(source: string, needle: string, replacement: string): string {
  if (!source.includes(needle)) throw new Error(`test fixture bug: ${JSON.stringify(needle)} not found in the base protocol`);
  return source.replace(needle, replacement);
}

describe('[harness.protocol.output] lint: one rejection rule at a time', () => {
  test('block mapped to anything but "deny" rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'block = "deny"', 'block = "ask"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('output.block must be "deny"'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
    expect(result.policy.harness.find((h) => h.id === 'claude-code')).toBeDefined();
  });

  test('confirm mapped to anything but "deny"/"ask" rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'confirm = "ask"', 'confirm = "silent"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('output.confirm must be "deny" or "ask"'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('observe mapped to anything but "silent" rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'observe = "silent"', 'observe = "deny"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('output.observe must be "silent"'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('flag mapped to anything but "context"/"silent" rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'flag = "context"', 'flag = "deny"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('output.flag must be "context" or "silent"'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('"ask" without a non-empty ask_probe rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'ask_probe = "test probe"\n', '');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('ask_probe must be a non-empty string'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('an unknown transport rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'transport = "stdin-json"', 'transport = "carrier-pigeon"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('protocol.transport must be one of'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  // `wiring` is a SIBLING branch to `transport` (harness.ts's
  // parseHarnessProtocol), not the same one — each has its own known-value
  // set and its own message, so this is its own test, not covered by the
  // transport case above.
  test('an unknown wiring rejects the block as a unit', () => {
    const protocol = replaceOne(validProtocol(), 'transport = "stdin-json"', 'transport = "stdin-json"\nwiring = "carrier-pigeon"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('protocol.wiring must be one of'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  // `codec` has no dedicated validation branch at all in 15a (no tool row
  // may declare one yet — `apply-patch` etc. are 15b/15c) — it is caught by
  // parseToolRow's unrecognized-field check, the same one that would catch
  // any other typo'd key on a tool row.
  test('a tool row codec field rejects the block as a unit (unrecognized field, not a dedicated branch)', () => {
    const protocol = replaceOne(
      validProtocol(),
      'Bash = { role = "command", command = "command" }',
      'Bash = { role = "command", command = "command", codec = "apply-patch" }',
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('.tools["Bash"].codec is not a recognized field'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });
});

describe('review round 1 S-1: template stdout placeholder safety', () => {
  test('a placeholder wrapped in quotes rejects the block as a unit', () => {
    const protocol = replaceOne(
      validProtocol(),
      `stdout = '{"decision":"deny","reason":\${reason}}'`,
      `stdout = '{"decision":"deny","reason":"\${reason}"}'`,
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('placeholders are JSON-encoded; write ${reason}, not "${reason}"')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('a template broken some other way (unbalanced braces) rejects the block as a unit', () => {
    const protocol = replaceOne(
      validProtocol(),
      `stdout = '{"decision":"deny","reason":\${reason}}'`,
      `stdout = '{"decision":"deny","reason":\${reason}'`,
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('does not parse as JSON once its placeholders are substituted')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });
});

describe('review round 2 C-1: per-template allowed placeholders', () => {
  test('${rule} and ${verdict} in a deny/ask template lint OK — the renderer actually fills them', () => {
    const protocol = replaceOne(
      validProtocol(),
      `stdout = '{"decision":"deny","reason":\${reason}}'`,
      `stdout = '{"decision":"deny","reason":\${reason},"rule":\${rule},"verdict":\${verdict}}'`,
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings).toEqual([]);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeDefined();
  });

  test('an unknown placeholder is rejected, naming it and the allowed set for that template', () => {
    const protocol = replaceOne(
      validProtocol(),
      `stdout = '{"decision":"deny","reason":\${reason}}'`,
      `stdout = '{"decision":"deny","reason":\${reason},"foo":\${foo}}'`,
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('unknown placeholder ${foo}') && w.includes('reason, rule, verdict')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('${reason} in a session_start template is rejected — that template only fills ${context}', () => {
    const protocol = replaceOne(
      validProtocol(),
      `[harness.protocol.output.session_start]\nstdout = '{"context":\${context}}'`,
      `[harness.protocol.output.session_start]\nstdout = '{"context":\${context},"reason":\${reason}}'`,
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('unknown placeholder ${reason}') && w.includes('this template only fills context')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });
});

describe('rule 6: an overlay cannot relax a BASELINE "deny" confirm to "ask"', () => {
  test('lintHarnessProtocolConfirmRelaxation rejects deny -> ask', () => {
    const issues = lintHarnessProtocolConfirmRelaxation('deny', 'ask', 'harness "codex"');
    expect(issues.length).toBe(1);
    expect(issues[0]).toContain('cannot relax');
  });

  test('lintHarnessProtocolConfirmRelaxation allows ask -> deny (tightening, never a relaxation)', () => {
    expect(lintHarnessProtocolConfirmRelaxation('ask', 'deny', 'harness "x"')).toEqual([]);
  });

  test('lintHarnessProtocolConfirmRelaxation allows deny -> deny (no change)', () => {
    expect(lintHarnessProtocolConfirmRelaxation('deny', 'deny', 'harness "x"')).toEqual([]);
  });

  test('wired into the real merge: an overlay-declared (non-baseline) harness may freely replace its OWN protocol, deny to ask included', () => {
    // Negative space for the rule: acme carries no "baseline measured
    // fact" the way a real baseline harness would, so a second overlay
    // file relaxing ITS OWN prior deny to ask is a normal replacement,
    // never rejected — proving the rule is scoped to `configSources`
    // including "baseline", not to "any existing protocol".
    //
    // R2-1: with confirm = "deny" the [harness.protocol.output.ask]
    // table from validProtocol() would be a dead template (confirm isn't
    // "ask"), so it is stripped along with the confirm value itself.
    const denyProtocol = replaceOne(
      replaceOne(validProtocol(), 'confirm = "ask"', 'confirm = "deny"'),
      `[harness.protocol.output.ask]\nstdout = '{"decision":"ask","reason":\${reason}}'\n`,
      '',
    );
    const declareAcmeDeny = harnessFile('harness.d/acme.toml', denyProtocol);
    const extendAcmeAsk = harnessFile('harness.d/acme.toml', validProtocol(), '');

    // Cross-LAYER extension (common declares, profile relaxes) — two
    // files declaring the SAME id in the SAME layer is a same-layer
    // conflict (ADR-0001), a different rule from this one; loadPolicyFromLayers
    // is what actually exercises "a later layer replaces an earlier one".
    const result = loadPolicyFromLayers([
      { name: 'common', files: [declareAcmeDeny] },
      { name: 'profile', files: [extendAcmeAsk] },
    ]);
    expect(result.warnings).toEqual([]);
    const acme = result.policy.harness.find((h) => h.id === 'acme');
    expect(acme?.protocol?.output.confirm).toBe('ask');
  });
});

// Review round 2 R2-1: `input.prompt`/`events.prompt`/`events.session_start`
// were mandatory — a minimal declared harness (pre_tool + deny only, the
// exact case of a user testing an unknown assistant, ADR-0006 § 7's
// pi-agent by design) was rejected outright with four unrelated
// messages. Lead decision: make the three optional, gated by six
// coherence rules so a HALF-declared prompt/session_start surface still
// fails loud rather than silently doing nothing.
function minimalProtocol(): string {
  return `
[harness.protocol]
transport = "stdin-json"

[harness.protocol.input]
event = "hook_event_name"
tool = "tool_name"
input = "tool_input"
session = "session_id"
cwd = "cwd"

[harness.protocol.events]
pre_tool = "PreToolUse"

[harness.protocol.tools]
Bash = { role = "command", command = "command" }

[harness.protocol.output]
block = "deny"
confirm = "deny"
observe = "silent"
flag = "silent"
on_malformed = "allow"

[harness.protocol.output.deny]
stdout = '{"decision":"deny"}'
`;
}

describe('review round 2 R2-1: minimal declaration (no prompt/session_start surface)', () => {
  test('lints OK — pre_tool + deny alone is a complete, usable protocol', () => {
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', minimalProtocol())]);
    expect(result.warnings).toEqual([]);
    const acme = result.policy.harness.find((h) => h.id === 'acme');
    expect(acme?.protocol).toBeDefined();
    expect(acme?.protocol?.events.prompt).toBeUndefined();
    expect(acme?.protocol?.events.session_start).toBeUndefined();
  });

  test('events.prompt present without input.prompt rejects the block as a unit', () => {
    const protocol = replaceOne(
      minimalProtocol(),
      'pre_tool = "PreToolUse"',
      'pre_tool = "PreToolUse"\nprompt = "UserPromptSubmit"',
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('input.prompt is required when events.prompt is declared'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('events.prompt absent with flag != "silent" rejects the block as a unit', () => {
    const protocol = replaceOne(minimalProtocol(), 'flag = "silent"', 'flag = "context"');
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('output.flag must be "silent" when events.prompt is not declared')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('output.context present without flag = "context" rejects the block as a unit (dead template)', () => {
    const protocol = `${minimalProtocol()}\n[harness.protocol.output.context]\nstdout = '{"context":\${context}}'\n`;
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('output.context is present but flag is not "context"')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('events.session_start present without output.session_start rejects the block as a unit', () => {
    const protocol = replaceOne(
      minimalProtocol(),
      'pre_tool = "PreToolUse"',
      'pre_tool = "PreToolUse"\nsession_start = "SessionStart"',
    );
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(result.warnings.some((w) => w.includes('output.session_start must be a table'))).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('output.session_start present without events.session_start rejects the block as a unit (dead template)', () => {
    const protocol = `${minimalProtocol()}\n[harness.protocol.output.session_start]\nstdout = '{"context":\${context}}'\n`;
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('output.session_start is present but events.session_start is not declared')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });

  test('output.ask present without confirm = "ask" rejects the block as a unit (dead template)', () => {
    const protocol = `${minimalProtocol()}\n[harness.protocol.output.ask]\nstdout = '{"decision":"ask"}'\n`;
    const result = loadPolicyFromOverlayFiles([harnessFile('harness.d/acme.toml', protocol)]);
    expect(
      result.warnings.some((w) => w.includes('output.ask is present but confirm is not "ask"')),
    ).toBe(true);
    expect(result.policy.harness.find((h) => h.id === 'acme')).toBeUndefined();
  });
});
