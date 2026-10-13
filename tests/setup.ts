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
// override per-test the way CLAUDE_CONFIG_DIR does — a development account
// can genuinely have an installed shared common layer, so without a
// throwaway HOME every test reaching loadCurrentPolicy()/run() would
// silently pick up real personal policy. Same discipline as above, same
// lesson (ticket 13): a test that needs to exercise the common layer itself
// sets its OWN throwaway HOME (save/restore), same pattern
// adapter-log-path.test.ts uses for CLAUDE_CONFIG_DIR.
//
// Ticket 39: directory creation itself (including these two throwaways)
// now lives in tests/tmp.ts, the one file under tests/ that creates
// temporary directories — see installGlobalFallbacks()'s own doc comment
// there for the fallback-reassignment and exit-cleanup contract.
//
// Ticket 58: the env-value guard reads the hook process's own environment, and
// `run()` defaults to `process.env`. A development account's environment holds
// real credentials (that is the point of the guard), so the suite must neither
// depend on them nor carry them: every variable with a protected name
// (src/protected-names.ts) is dropped from this test process before any test
// file loads — in-process `run()` calls, and every child a test spawns with
// `env: { ...process.env, … }` (what the suite's spawns do), inherit that.
// A child spawned with NO `env` option still gets the shell's original
// environment (Bun does not see a `delete`): the suite's few such children
// (CLI rendering, skill, doctor) judge no write, and a new one that does must
// pass an env — that rule is this comment, nothing enforces it. A test that
// needs a protected variable hands the guard a fake environment
// (`run(…, { env })`, `createDispatcher(policy, env)`) rather than setting one
// on this process.
import { protectedNamesIn } from '../src/protected-names.ts';
import { installGlobalFallbacks } from './tmp.ts';

for (const name of protectedNamesIn(process.env)) delete process.env[name];

installGlobalFallbacks();
