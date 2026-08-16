// The real engine, wired once so fixtures.test.ts (proof of conformance)
// and fixtures-mutation.test.ts (proof of behavior-sensitivity) share the
// exact same wiring — a divergence between the two would undermine the
// mutation proof, which only means something if it mutates the same engine
// fixtures.test.ts asserts against.

import { checkBash } from '../src/command-rules.ts';
import { checkMcpWrite } from '../src/mcp-write-rules.ts';
import { scanPrompt } from '../src/prompt-rules.ts';
import { checkPath, checkSecretBash, checkUrl } from '../src/secret-rules.ts';
import { extractTargets, isGuardedToolName } from '../src/targets.ts';
import { scanSecrets } from '../src/write-secret-rules.ts';
import type { Engine } from './fixture-runner.ts';

export const REAL_ENGINE: Engine = {
  checkBash,
  checkSecretBash,
  checkPath,
  checkUrl,
  checkMcpWrite,
  scanSecrets,
  scanPrompt,
  extractTargets,
  isGuardedToolName,
};
