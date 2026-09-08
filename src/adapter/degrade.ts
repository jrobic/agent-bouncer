// The abstract-verdict -> harness-action degradation (ADR-0006 § 3/4):
// looks the verdict kind up in the harness's OWN declared output table
// instead of a hardcoded Claude Code switch (the pre-15a
// src/adapter/degradation.ts). Fail-closed by construction: `rules lint`
// (src/policy/harness.ts) already proved `block` can only map to "deny",
// `confirm` only to "deny"/"ask", `observe` only to "silent", `flag` only
// to "context"/"silent" — this function is a pure table lookup, never a
// second place that could re-decide what's safe.

import type { HarnessAction, HarnessOutputTable } from '../policy/schema.ts';
import type { VerdictKind } from '../types.ts';

// `flag` is UserPromptSubmit-only — src/adapter/dispatch.ts's
// strictestOf already throws if a PreToolUse family emits one; this is
// defense in depth against the same misrouting bug reaching this table
// through some OTHER path, exactly as the pre-15a degradation table did.
export function degradePreToolUseVerdict(kind: VerdictKind, output: HarnessOutputTable): HarnessAction {
  if (kind === 'flag') {
    throw new Error(
      'degradePreToolUseVerdict: a "flag" verdict reached the PreToolUse degradation table '
        + '— flag belongs to UserPromptSubmit only',
    );
  }
  return output[kind];
}
