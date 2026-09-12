# ADR-0003: Liveness — Claude Code runs hooks fail-open, so bouncer fails closed in three layers

**Date**: 2026-09-04
**Status**: Accepted
**Deciders**: Jonathan Robic (design session, 2026-09-04)

## Context

### Current situation

Claude Code runs its hook chain fail-open. Per the hooks reference (checked
2026-09-04): exit 0 without a decision lets the call proceed; exit 2 blocks;
any other exit code, a command that is not found, or a crash is a
"non-blocking error" and the tool call proceeds; a timeout is not documented;
no setting makes hook failures blocking. Matching `PreToolUse` hooks run in
parallel and a `deny` from any of them wins. `SessionStart` cannot block a
session.

`bouncer`'s never-crash contract (`src/adapter/run.ts`: a throw during
dispatcher construction retries once against the embedded baseline) covers
policy bugs. It cannot cover a binary that is absent, not executable,
half-written during a rebuild, or a Bun runtime that fails to start — in
every one of those cases the hook simply is not there to answer, and Claude
Code carries on.

Two signals existed before this decision: the `SessionStart` doctor scream
(`additionalContext`, advisory, and it dies with the `hooks` block) and the
declarative layer in `settings.json` — 34 `permissions.deny` entries, of
which 18 `Read(**/…)` globs duplicate what the `secret` family already
guards through Read/Edit/Grep/Glob and the Bash path-token scan. Those 18
globs are the measured source of the auto-mode classifier's prompts on
`grep -r` and `cd && rg` (permission engine, not the classifier), and are
being removed on the workstation.

### Problem

Removing the declarative duplicates makes `bouncer` the only guard for
those paths — so "bouncer cannot run" must turn into a deny **for the
session in progress**, not a message the next session might read.

### Constraints

- Claude Code offers no fail-closed switch; whatever fails closed must do so
  by emitting a `deny` Claude Code can parse, with exit 0 — a non-zero exit
  from the safety net itself reads as one more crashed hook.
- `bouncer` never emits `allow` (`src/adapter/envelopes.ts`): a liveness
  probe must not become an allow-lister or short-circuit the permission
  engine or the classifier.
- `doctor` recognises the main wiring by `basename == bouncer` as the first
  token plus `run` in the arguments (`src/adapter/doctor.ts`,
  `pointsAtBouncer`); that recogniser must stay strict — a `/bin/sh`
  wrapper is not bouncer wiring.
- Cost per tool call must stay in the same order of magnitude: `bouncer
  check true` measured under 50 ms wall on 2026-09-04.
- A removed `hooks` block and a hook timeout are outside what any hook
  entry can defend against.

## Options considered

### Option 1: Keep the declarative layer whole

Leave the 18 `Read(**/…)` globs as the backstop.

**Pros**: nothing to build; a deny rule needs no process to run.

**Cons**: it is the measured cause of the classifier prompts the
workstation wants gone; it duplicates the `secret` family with a second
grammar (globs) that drifts; it covers Read only, not Bash, Grep, Glob,
Edit, MCP.

**Effort**: none. Rejected as the sole layer; kept, reduced, as layer 3.

### Option 2: Wrap the main entry in a shell that denies on failure

`sh -c '<bouncer> run || printf <deny>'` as the one `PreToolUse` entry.

**Pros**: one entry.

**Cons**: `pointsAtBouncer` would read the entry as unwired unless
loosened to accept `/bin/sh` — which would also accept any wrapper, and the
main wiring check would stop meaning "bouncer judges this call". The
wrapper also swallows bouncer's own exit codes and stdout handling in one
more layer of quoting.

**Effort**: low. Rejected: the check must stay strict.

### Option 3: A separate canary entry, a `ping` subcommand, a dedicated doctor check (chosen)

A second `PreToolUse` entry on the same matcher as the main entry, POSIX
`sh`, depending on nothing but the binary path: it runs `<binary> ping` and,
on any non-zero exit, prints one `hookSpecificOutput` deny and exits 0.
`ping` is a runnability probe (binary starts, embedded baseline compiles,
layered policy loads through `run`'s own path with its baseline retry,
config directory readable), not a policy check. `doctor` gains
`wiring:canary` that recognises the canonical shape by shell tokens, and
`--print-canary` prints the entry to paste.

**Pros**: the main entry and its check are untouched; the canary emits a
deny Claude Code applies; parallel hooks + "deny wins" make the two entries
independent; the shape is generated in one place (`src/adapter/canary.ts`)
and recognised by tokens, so a hook merely containing the word `ping` is
not mistaken for it.

**Cons**: doubles the process count per tool call (not the order of
magnitude: `ping` does less than `check`); it dies with the `hooks` block
and cannot see a timeout.

**Effort**: medium (subcommand, doctor check, docs, end-to-end test on the
built binary).

### Option 4: A launcher that refuses to start Claude Code when doctor fails

A shell function `claude` running `bouncer doctor` first (exit 1 on a
corrupt settings file, 0 healthy — measured 2026-09-04).

**Pros**: the only layer that survives a wiped `hooks` block.

**Cons**: covers the next session, not the one in progress; lives in the
workstation's shell config, not in this repository.

**Effort**: low. Adopted as layer 2, owned by dotfiles.

## Decision

Three layers, each covering what the one above cannot:

1. **Canary (this repository, ticket 25, commit `903b052`)** — covers the
   session in progress against a binary that is missing, not executable,
   corrupted, replaced mid-session by a rebuild, or a Bun runtime that
   fails to start. Canonical entry, printed by `bouncer doctor
   --print-canary`:

   ```
   sh -c 'if ! "$0" ping; then printf "%s\n" "$1"; fi' '<binary>' '<deny JSON>'
   ```

   `$0` is the binary path and `$1` the deny envelope, both passed as
   arguments so the script is a constant and no path or JSON is ever
   interpolated into it. The deny reason is fixed:
   `bouncer-canary: bouncer cannot run (missing, not executable, or policy
   failed to load) — failing closed`. The script always exits 0.
   `wiring:canary` fails naming the fault — absent entry, different binary
   path, no deny-on-failure branch — and the `SessionStart` scream carries
   it. The canary is not shadow-aware: it judges runnability, never a tool
   call, so it stays enforcing while the main entry observes; `doctor` says
   so in the check message.
2. **Launcher (dotfiles)** — the `claude` shell function guarded by
   `bouncer doctor`; covers the next session against a wiped or edited
   `hooks` block. `ask: Edit(~/.claude/settings.json)` (ticket 01) covers
   the agent editing the wiring.
3. **Declarative layer, reduced (dotfiles)** — `Read(~/.ssh/**)`,
   `Read(~/.gnupg/**)`, `Read(~/.aws/**)` stay in `permissions.deny`; the
   18 `Read(**/…)` globs go.

### Justification

One `PreToolUse` entry cannot be both the judge and its own liveness
check: if it crashes it emits nothing. A second entry that depends only on
`sh` and the binary path turns that silence into a parseable deny, and
Claude Code's own "deny wins across parallel hooks" rule is what makes the
two entries compose without either knowing about the other. `ping` shares
`run`'s dispatcher construction so that "runnable" means what `run` means —
with one deliberate divergence: an unreadable config directory exits 1 even
though `run` would silently enforce the baseline, because the ticket wants
that failure to surface (documented in `docs/reference/cli.md` § `ping`).

## Consequences

### Positive

- "bouncer cannot run" is a deny in the session in progress, with a reason
  the human reads in the transcript.
- The main wiring check stays strict; the canary has its own.
- The 18 duplicate globs can leave `settings.json` without lowering the
  guard.

### Negative

- Two processes per guarded tool call instead of one.
- `doctor` exits 1 on every profile until the canary entry is pasted in —
  true on both workstation profiles right after the 2026-09-04 install; the
  `SessionStart` scream names it meanwhile.
- An unreadable config directory now denies every tool call (canary) where
  `run` alone would have enforced the baseline. Accepted: fail-closed, and
  the case is nearly impossible in practice since Claude Code reads
  `settings.json` from the same directory.

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Canary entry removed or edited by the agent | Low | High | ticket 01's `ask` on `Edit(~/.claude/settings.json)`; layer 2 refuses the next launch; `doctor` names the missing entry |
| Half-written binary during a reinstall denies every call for a moment | Medium, transient | Low | install atomically (`cp` to `bouncer.new`, `mv -f`), as the provenance memory prescribes — the deny is the intended behaviour, the window is the thing to shrink |
| A hook timeout leaves the call to proceed | Unknown (undocumented) | Medium | outside any hook's reach; `ping` does the minimum; measured cost keeps both entries far under any plausible timeout |
| `doctor` red on every session blamed on bouncer | High until layer 2 lands | Low | the check message names the fix (`--print-canary`); tracked as the dotfiles follow-up of ticket 25 |

## Implementation plan

### Phase 1 — this repository (ticket 25)
- [x] `bouncer ping` through `withDispatcherLikeRun` (shared with `run`),
      plus the config-dir readability probe; exit 0/1, no stdin, no stdout.
- [x] `src/adapter/canary.ts`: one builder for the canonical line, one
      token-level recogniser; `doctor` `wiring:canary` with three named
      failure classes and the shadow note; `doctor --print-canary`.
- [x] End-to-end test on the built binary (absent path → one deny JSON +
      exit 0; `dist/bouncer` → empty stdout + exit 0); doctor cases
      present/absent/other path/no deny/shadow; `pointsAtBouncer` unchanged.
- [x] `docs/reference/cli.md` (`ping`, `--print-canary`, the check),
      `docs/how-to/wire-into-claude-code.md` step 4, seven `[pass]` lines.
- [x] Shipped in the grouped reinstall of 2026-09-04 (`903b052`).

### Phase 2 — workstation (dotfiles lead, gated there)
- [ ] Canary entry pasted into both profiles' `settings.json`; `doctor` ×2
      seven `[pass]`.
- [ ] `claude` shell function guarded by `bouncer doctor`.
- [ ] 18 `Read(**/…)` globs removed; the three home-absolute reads kept;
      5-minute friction test on `grep -r`/`rg`.

## Success metrics

- With the canary installed: renaming the binary makes the next tool call
  fail with the `bouncer-canary:` reason; restoring it makes the call pass
  through the main entry again. `doctor` ×2 exit 0 with seven `[pass]`.
- No measurable latency change in a session: two sub-50 ms processes per
  guarded call.

## References

- `.scratch/bouncer/issues/25-liveness-canary-fail-closed.md` (ticket,
  hooks-reference findings, measurements),
  `.scratch/bouncer/reports/25-report.md` (review round).
- `src/adapter/canary.ts`, `src/adapter/doctor.ts`, `src/cli-commands.ts`,
  `src/adapter/run.ts` (`withDispatcherLikeRun`).
- `docs/reference/cli.md` § `ping`, § `doctor`;
  `docs/how-to/wire-into-claude-code.md` step 4.
- Ticket 01 (settings hardening, `ask` on settings edits), ticket 07
  (doctor + SessionStart scream), ticket 08 (shadow mode).
- Claude Code hooks reference (exit-code semantics, parallel hooks, deny
  wins), as read on 2026-09-04.

---

## History

| Date | Action | By |
|---|---|---|
| 2026-09-04 | Created, Accepted — design session decision; layer 1 shipped the same day, layers 2–3 pending on the workstation | Jonathan Robic |
