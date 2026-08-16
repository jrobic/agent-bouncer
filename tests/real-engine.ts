// The real, unmutated engine functions — the exact same imports
// src/adapter/dispatch.ts uses. fixtures-mutation.test.ts builds broken
// overrides of these to prove specific fixtures are behavior-sensitive.
//
// This is engine-layer testing, not adapter-layer: dispatch.ts imports its
// check functions directly (ES module bindings are read-only from the
// importing module's side), so there is no seam to inject a broken engine
// INTO the real dispatch without adding dependency-injection machinery to
// production code purely for test convenience. fixtures.test.ts already
// proves the real dispatch end to end; this file proves the rule functions
// underneath it are not decorative.

import { checkBash } from '../src/command-rules.ts';
import { checkMcpWrite } from '../src/mcp-write-rules.ts';
import { scanPrompt } from '../src/prompt-rules.ts';
import { checkPath, checkSecretBash } from '../src/secret-rules.ts';
import { scanSecrets } from '../src/write-secret-rules.ts';

export const REAL = {
  checkBash,
  checkSecretBash,
  checkPath,
  checkMcpWrite,
  scanSecrets,
  scanPrompt,
};
