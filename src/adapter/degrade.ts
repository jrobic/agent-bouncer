// The abstract-verdict -> harness-action degradation (ADR-0006 § 3/4):
// looks the verdict kind up in the harness's OWN declared output table
// instead of a hardcoded Claude Code switch (the pre-15a
// src/adapter/degradation.ts). Fail-closed by construction: `rules lint`
// (src/policy/harness.ts) already proved `block` can only map to "deny",
// `confirm` only to "deny"/"ask", `observe` only to "silent", `flag` only
// to "context"/"silent" — this function is a pure table lookup, never a
// second place that could re-decide what's safe.

import type { HarnessAction, HarnessOutputTable } from '../policy/schema.ts';
import { isPreToolKind, type VerdictKind } from '../types.ts';

// `flag` is event-driven (UserPromptSubmit or PostToolUseFailure) and `redact`
// is PostToolUse-only (ADR-0008). `strictestOf` already throws on either,
// through the same `isPreToolKind` test; this is defense in depth against the
// same misrouting bug reaching this table through some OTHER path, exactly as
// the pre-15a degradation table did.
export function degradePreToolUseVerdict(kind: VerdictKind, output: HarnessOutputTable): HarnessAction {
  if (!isPreToolKind(kind)) {
    throw new Error(
      `degradePreToolUseVerdict: a "${kind}" verdict reached the PreToolUse degradation table `
        + `— not a pre-tool verdict (flag belongs to event-driven prompt/failure paths, redact to PostToolUse)`,
    );
  }
  return output[kind];
}
