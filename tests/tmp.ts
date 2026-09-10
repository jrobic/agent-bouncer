// The one entry point every tests/*.test.ts file uses to create a
// throwaway `bouncer-*`-prefixed scratch directory (ticket 39: `bun run
// verify` left 7 489 of them behind in $TMPDIR — every test that
// mkdtemp(Sync)'d one cleaned it up on its own, inconsistently, and
// several didn't at all: a directory created inside a per-file helper
// called from many tests, or once per case in a loop
// (tests/fixtures-protocol.test.ts: 3 835 leaks alone), had no cleanup
// path that actually ran for every one of them). This is also the ONLY
// file under tests/ that calls mkdtemp/mkdtempSync at all — including
// tests/setup.ts's own two global throwaways (installGlobalFallbacks()
// below) — so `grep -n mkdtemp tests/` names only this file.
//
// The cleanup hook below is registered HERE, at this module's own top
// level — never inside a test file that merely imports tmpDir. Verified
// empirically before writing this (see the ticket 39 report): an
// afterEach() call sitting in a module that several test files `import`
// only fires for the FIRST file to import it, because ES module bodies
// run exactly once and are cached — every later importer gets the
// cached module with no top-level re-execution, so its afterEach() call
// never re-registers for THAT file. This module is different only
// because tests/setup.ts (bunfig.toml's own [test] preload) imports it
// before any test file loads at all: registering afterEach() at that
// point makes it a ROOT-scope hook (bun:test, like Jest, scopes a hook
// to wherever it is called) — proven to fire after EVERY test, in every
// file, regardless of which describe block, helper function, or loop
// iteration created the directory being swept. The same applies to
// installGlobalFallbacks()'s own afterAll() below, including through
// the one level of function-call indirection — also verified directly.
//
// Review round 1 (R1-2): that root-scoping guarantee depends entirely on
// tests/setup.ts's preload actually having run BEFORE this module's own
// top level does — true whenever bunfig.toml is discovered (any `bun
// test` invoked from the project root), false the moment it isn't (e.g.
// `cd tests && bun test x.test.ts`, reproduced live by both reviewers):
// this module then becomes an ordinary shared module, afterEach()
// registers only for the first file that happens to import it, and
// EVERY OTHER file's tmpDir() calls would leak silently — the exact bug
// this ticket exists to close, reintroduced by a broken invocation.
// tmpDir() refuses to run at all in that state (see its own comment)
// instead of creating a directory nothing will reliably clean up.
import { afterAll, afterEach } from 'bun:test';
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

// src/adapter/policy.ts's commonRoot() GUARD FOR TEST AUTHORS comment,
// generalized: every one of these is a harness account-directory
// variable (src/adapter/log-path.ts's configDirFor(), each
// policy/harness/*.toml's own `env` row) whose empty-or-deleted
// fallback is node:os's homedir() — this MACHINE's real home, never a
// safe default. If the directory a test pointed one of these at (or a
// PATH UNDER it — tests/adapter-run.test.ts:519/542's own
// `CODEX_HOME = join(accountDir, '.codex')` shape, a subdirectory of
// what tmpDir() actually registered) is the one being removed below, it
// is REASSIGNED to a fallback that survives (never deleted, never set
// to '').
const PROTECTED_ENV_VARS = ['HOME', 'CLAUDE_CONFIG_DIR', 'CODEX_HOME', 'PI_CODING_AGENT_DIR'] as const;
type ProtectedEnvVar = (typeof PROTECTED_ENV_VARS)[number];

let fallbacks: Readonly<Record<ProtectedEnvVar, string>> | undefined;

// Defensive, not hypothetical: a directory (or a file inside it) a test
// left chmod'd down for its OWN scenario — an unreadable policy.d entry,
// an unwritable log directory — can make even rmSync's force:true throw
// (force only swallows ENOENT, never EACCES/ENOTEMPTY: measured against
// a real 0o000 root and a real 0o500-no-`x` nested directory while
// designing this, see the ticket 39 report). Only reached on the rare
// path where the fast rmSync below actually throws.
//
// lstatSync, never statSync/readdirSync-then-follow: a symlink inside
// the tree being swept must be unlinked as itself, never traversed —
// review round 1 (R1-1) measured a real corruption otherwise (statSync
// follows the link; chmod'ing what it points at reached OUTSIDE the
// swept tree entirely, and a link to an ancestor directory recurses
// forever). rmSync itself removes a symlink without following it, so
// returning immediately here is enough — there is nothing to chmod on
// the link itself that would help rmSync remove it.
function makeRemovable(path: string): void {
  let entryStat;
  try {
    entryStat = lstatSync(path);
  } catch {
    return; // already gone
  }
  if (entryStat.isSymbolicLink()) return;
  if (!entryStat.isDirectory()) {
    try {
      chmodSync(path, 0o600);
    } catch {
      // best effort — a real failure surfaces from the rmSync retry below
    }
    return;
  }
  try {
    chmodSync(path, 0o700);
  } catch {
    // best effort, see above
  }
  let entries: string[] = [];
  try {
    entries = readdirSync(path);
  } catch {
    return;
  }
  for (const entry of entries) makeRemovable(join(path, entry));
}

function removeDir(dir: string): void {
  // fallbacks is always defined here: every directory this function ever
  // sees arrives through `pending`, which only tmpDir() populates, and
  // tmpDir() itself throws before creating anything if fallbacks is
  // still undefined (review round 1, R1-2) — so the undefined case this
  // function used to guard against can no longer reach it.
  const survivors = fallbacks!;
  for (const name of PROTECTED_ENV_VARS) {
    const value = process.env[name];
    if (value === dir || value?.startsWith(dir + sep)) process.env[name] = survivors[name];
  }
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    makeRemovable(dir);
    rmSync(dir, { recursive: true, force: true });
  }
}

const pending: string[] = [];

afterEach(() => {
  // Review round 1 (R1-3): one directory per iteration, its own
  // try/catch — this afterEach is root-scoped (runs after EVERY test in
  // the whole suite), so an exception escaping it would fail whichever
  // FOREIGN test happens to run next, and splice(0) has already dropped
  // every directory in this batch from `pending` before the loop starts,
  // so a thrown removeDir() would also strand the remaining directories
  // unswept forever. A stubborn directory is logged and skipped instead.
  for (const dir of pending.splice(0)) {
    try {
      removeDir(dir);
    } catch (err) {
      console.error(`tests/tmp.ts: failed to remove ${dir}:`, err);
    }
  }
});

/**
 * Creates a fresh `<prefix><random>` directory under the OS tmpdir and
 * registers it for removal after the CURRENT test — the one entry point
 * every tests/*.test.ts file uses for a throwaway directory (ticket 39).
 * `prefix` is used verbatim (its own trailing `-` included, by
 * convention); every call site keeps choosing its own `bouncer-…-`
 * shape, which is what the $TMPDIR leak count greps for.
 *
 * Throws instead of creating anything if tests/setup.ts's preload has
 * not run yet (review round 1, R1-2): every guarantee this module makes
 * — the per-test sweep firing for every file, the protected-env-var
 * reassignment above — depends on `fallbacks` having been set by
 * installGlobalFallbacks(), which only happens when this module is
 * reached through that preload. A directory created without that
 * guarantee would be exactly the silent-leak (and silent-real-HOME-
 * fallthrough) bug this ticket exists to close.
 */
export function tmpDir(prefix: string): string {
  if (fallbacks === undefined) {
    throw new Error(
      'tests/tmp.ts: tests/setup.ts\'s preload did not run before this file loaded '
        + '— tmpDir()\'s cleanup would not be root-scoped, refusing to run',
    );
  }
  const dir = mkdtempSync(join(tmpdir(), prefix));
  pending.push(dir);
  return dir;
}

/**
 * Called exactly once, by tests/setup.ts's own preload top level: creates
 * the two throwaway HOME/CLAUDE_CONFIG_DIR directories every test in the
 * run defaults to, points process.env at them, and registers them as the
 * survivor tmpDir()'s per-test sweep above reassigns HOME/CLAUDE_CONFIG_DIR/
 * CODEX_HOME/PI_CODING_AGENT_DIR to whenever the directory one of them
 * currently holds is swept out from under it (never delete, never '').
 * CODEX_HOME/PI_CODING_AGENT_DIR have no ambient default the way HOME/
 * CLAUDE_CONFIG_DIR do (nothing sets them unless a test does) — the HOME
 * fallback is already a safe, isolated, always-live directory, and
 * nothing requires their own reassignment target to look like a real
 * $CODEX_HOME/$PI_CODING_AGENT_DIR shape, so it is reused for both
 * rather than minting two more throwaways that would only ever serve
 * this one emergency path.
 *
 * These two directories must outlive every test in the run, so they are
 * never registered through tmpDir() itself (which sweeps after every
 * test) — they are removed by a root-scoped afterAll() instead, which
 * fires exactly once, at the true end of the whole run, after every
 * file's own tests (verified empirically to fire even when a test
 * fails). `process.on('exit', …)` and `'beforeExit'` were tried first
 * and do NOT fire at all under `bun test` — Bun's test runner ends the
 * process some other way; afterAll() is the one mechanism that actually
 * runs here.
 */
export function installGlobalFallbacks(): void {
  const fallbackConfigDir = mkdtempSync(join(tmpdir(), 'bouncer-test-config-'));
  const fallbackHome = mkdtempSync(join(tmpdir(), 'bouncer-test-home-'));

  process.env.CLAUDE_CONFIG_DIR = fallbackConfigDir;
  process.env.HOME = fallbackHome;

  fallbacks = {
    HOME: fallbackHome,
    CLAUDE_CONFIG_DIR: fallbackConfigDir,
    CODEX_HOME: fallbackHome,
    PI_CODING_AGENT_DIR: fallbackHome,
  };

  afterAll(() => {
    rmSync(fallbackConfigDir, { recursive: true, force: true });
    rmSync(fallbackHome, { recursive: true, force: true });
  });
}
