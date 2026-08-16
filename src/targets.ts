// Guarded-tool target extraction. Normalizes a tool call — whatever shape
// it arrived in — into the commands / paths / urls a rule module actually
// inspects. Pure rule logic, no filesystem or network I/O — the only
// side effect is a `console.error` diagnostic when a tool call's shape
// doesn't match what a target reader expects, so a future surface change
// is visible on stderr instead of silently passing through.
//
// `GuardedToolCall` is deliberately narrower than any one harness's hook
// envelope (no session id, no event name, no protocol fields) — it carries
// only what target extraction needs: a tool name and its input bag. The
// full Claude Code envelope (`HookInput`) lives in src/adapter/protocol.ts;
// an adapter maps its own envelope down to this shape before calling in.
//
// Workstation delta folded into the engine convergence: the catalog
// generation this repository otherwise ports verbatim only ever recognised
// `Bash`. A sandboxed tool-execution plugin (context-mode) reroutes work
// that would otherwise be a Bash call into its own sandbox, under MCP tool
// names — those calls carry the same shell commands and file paths as Bash,
// in a different shape. Because an adapter's guard wiring keys on tool name,
// a Bash-only guard never sees them, and every command/path/secret rule is
// bypassed by the reroute unless the guards also accept these names.

export interface GuardedToolCall {
  readonly toolName?: string | undefined;
  readonly toolInput?: Record<string, unknown> | undefined;
}

const CTX_TOOL =
  /^mcp__plugin_context-mode_context-mode__ctx_(execute|execute_file|batch_execute|index|fetch_and_index)$/;

export function isGuardedToolName(toolName: string | undefined): boolean {
  return toolName === 'Bash' || (toolName !== undefined && CTX_TOOL.test(toolName));
}

// What a guard has to inspect, decoupled from the shape it arrived in.
// `commands` holds anything executable (a Bash string, a ctx_execute `code`
// block in any language), `paths` anything read off disk, `urls` anything
// fetched over the network.
export interface Targets {
  commands: string[];
  paths: string[];
  urls: string[];
}

// Helper: safely extract a string field from tool_input, logging on
// stderr if a non-string value is encountered (so future tool surface
// changes don't silently pass through unexpected shapes).
export function readStringField(
  ti: Record<string, unknown>,
  key: string,
  hookName: string,
): string | null {
  const value = ti[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') {
    console.error(
      `[${hookName}] expected string for tool_input.${key}, got ${typeof value} — allowing`,
    );
    return null;
  }
  return value;
}

// Reads `commands: [{label, command}]` (ctx_batch_execute). A malformed
// entry is skipped rather than thrown on: a shape change upstream must not
// crash the guard into failing open silently, so the drift goes to stderr.
function readBatchCommands(
  ti: Record<string, unknown>,
  hookName: string,
): string[] {
  const raw = ti.commands;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    console.error(`[${hookName}] expected array for tool_input.commands, got ${typeof raw}`);
    return [];
  }
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') {
      out.push(entry);
      continue;
    }
    if (
      entry && typeof entry === 'object'
      && typeof (entry as { command?: unknown }).command === 'string'
    ) {
      out.push((entry as { command: string }).command);
      continue;
    }
    console.error(`[${hookName}] skipping unreadable entry in tool_input.commands`);
  }
  return out;
}

// Reads `requests: [{url, source}]` (ctx_fetch_and_index batch shape).
function readBatchUrls(ti: Record<string, unknown>, hookName: string): string[] {
  const raw = ti.requests;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    console.error(`[${hookName}] expected array for tool_input.requests, got ${typeof raw}`);
    return [];
  }
  return raw
    .filter((e): e is { url: string } =>
      Boolean(e) && typeof e === 'object' && typeof (e as { url?: unknown }).url === 'string'
    )
    .map((e) => e.url);
}

// Appends a field that readStringField may have rejected. An absent or
// empty field is not a target — matching "" would deny nothing and cost a
// pass through every rule.
function push(bucket: string[], value: string | null): void {
  if (value !== null && value !== '') bucket.push(value);
}

// Normalizes any guarded tool call into commands / paths / urls.
//
// `code` counts as a command whatever `language` says: a Python or JS snippet
// reads ~/.ssh/id_rsa just as effectively as a shell one, and the guards match
// on literal strings rather than on shell semantics anyway.
export function extractTargets(call: GuardedToolCall, hookName: string): Targets {
  const ti = call.toolInput ?? {};
  const tool = call.toolName;
  const targets: Targets = { commands: [], paths: [], urls: [] };

  switch (tool) {
    case 'Bash':
      push(targets.commands, readStringField(ti, 'command', hookName));
      break;
    case 'mcp__plugin_context-mode_context-mode__ctx_execute':
      push(targets.commands, readStringField(ti, 'code', hookName));
      break;
    case 'mcp__plugin_context-mode_context-mode__ctx_execute_file':
      push(targets.commands, readStringField(ti, 'code', hookName));
      push(targets.paths, readStringField(ti, 'path', hookName));
      break;
    case 'mcp__plugin_context-mode_context-mode__ctx_batch_execute':
      targets.commands.push(...readBatchCommands(ti, hookName));
      break;
    case 'mcp__plugin_context-mode_context-mode__ctx_index':
      push(targets.paths, readStringField(ti, 'path', hookName));
      break;
    case 'mcp__plugin_context-mode_context-mode__ctx_fetch_and_index':
      push(targets.urls, readStringField(ti, 'url', hookName));
      targets.urls.push(...readBatchUrls(ti, hookName));
      break;
    default:
      break;
  }

  return targets;
}
