// Test-session safety net, loaded via bunfig.toml's [test] preload before
// any test file runs. src/adapter/log-path.ts's configDir() defaults to
// ~/.claude when CLAUDE_CONFIG_DIR is unset — and this project's own rule
// is that no test may ever touch live config. Every test in this suite that
// reaches logVerdict() (directly or through run()) must write into a
// throwaway directory, never the real one, without every test file having
// to remember to set this up itself.
//
// tests/adapter-log-path.test.ts still exercises configDir()'s OWN override
// behavior explicitly (it saves and restores CLAUDE_CONFIG_DIR around each
// of its cases) — this preload only sets the default for everything else.
//
// Ticket 20 (ADR-0001): src/adapter/policy.ts's commonRoot() reads
// ~/.agents/bouncer/ straight off the home directory, with NO env var to
// override per-test the way CLAUDE_CONFIG_DIR does — this machine's own
// dev account genuinely has one (dotfiles, several active rules), so
// without a throwaway HOME every test reaching loadCurrentPolicy()/run()
// would silently pick up real personal policy. Same discipline as above,
// same lesson (ticket 13): a test that needs to exercise the common layer
// itself sets its OWN throwaway HOME (save/restore), same pattern
// adapter-log-path.test.ts uses for CLAUDE_CONFIG_DIR.

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.CLAUDE_CONFIG_DIR = mkdtempSync(join(tmpdir(), 'bouncer-test-config-'));
process.env.HOME = mkdtempSync(join(tmpdir(), 'bouncer-test-home-'));
