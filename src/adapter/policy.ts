// Resolves and loads the per-account policy overlay — the one piece of
// policy loading that is genuinely Claude-Code-specific (which account,
// which directory, reading the file off disk). The parsing/merge/lint
// logic itself (src/policy/load.ts) has no opinion on where the file
// lives and no filesystem access at all — src/policy/ stays I/O-free, this
// is the one adapter module that owns the `node:fs` read.

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadPolicyFromOverlayText, type LoadResult } from '../policy/load.ts';
import { configDir } from './log-path.ts';

// <configDir>/bouncer/policy.toml — sibling to logs/hooks/ under the same
// per-account root, so a second account (client seat) gets its own overlay
// the same way it gets its own log.
export function overlayPath(): string {
  return join(configDir(), 'bouncer', 'policy.toml');
}

/**
 * Reads the overlay file at `overlayPath()` (if any) and loads it. A
 * missing file is treated exactly like "no overlay" — silent, no
 * warning: an absent overlay is the normal, unconfigured case, not a
 * failure.
 */
export async function loadCurrentPolicy(): Promise<LoadResult> {
  const path = overlayPath();
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return loadPolicyFromOverlayText(null);
  }
  return loadPolicyFromOverlayText(text);
}
