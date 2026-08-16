// The Claude Code hook envelope — the one harness protocol shape this
// adapter reads off stdin. Moved out of the engine (src/targets.ts) because
// it names CC-specific fields (`session_id`, `hook_event_name`,
// `tool_use_id`) that a protocol-agnostic rule module has no business
// knowing about; the engine's own `GuardedToolCall` (src/targets.ts) is
// what target extraction actually needs, and this type maps down to it.

export interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  hook_event_name?: string;
  tool_use_id?: string;
  // UserPromptSubmit's payload — the two events share one envelope shape,
  // discriminated by hook_event_name, so this lives on the same type rather
  // than forking a second one the adapter would have to reconcile.
  prompt?: string;
}
