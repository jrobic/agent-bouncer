# Wire bouncer into pi-agent (and omp)

Goal: install the printed shim as an extension in pi-agent's (and omp's — omp
is a layer on pi-agent, the relation of oh-my-zsh to zsh, ADR-0006 fact 5)
own configuration directory, so every tool call and every session start goes
through `bouncer run --harness pi-agent`.

Unlike Claude Code and Codex, pi-agent and omp are **in-process** harnesses
(ADR-0006 § 7): neither writes a stdin-JSON envelope itself. There is no
`hooks.json`/`settings.json` to point at bouncer — a guard is reached only
through an **extension**, a small TypeScript module `pi`/`omp` load at boot
and call on every tool call and session start. `bouncer harness shim
pi-agent` prints that extension, embedded in the binary and byte-identical
every time: it forwards the harness's own event object to `bouncer run
--harness pi-agent` unmodified and returns bouncer's stdout to the harness
as is. It carries **no policy** — `policy/harness/pi-agent.toml` is the one
file that knows both pi-agent's own extension API and bouncer's abstract
verdict vocabulary.

## Homebrew

Installed with Homebrew? Use the stable `$(brew --prefix)/bin/bouncer` path
below, never the versioned Cellar path (`brew upgrade` removes it, and
`doctor` fails a shim that bakes one); see [Install](install.md). Print the
extension with:

```sh
bouncer harness shim pi-agent --bin "$(brew --prefix)/bin/bouncer"
```

## Steps

1. Choose the compiled binary to wire:

   - Installed with Homebrew: use `$(brew --prefix)/bin/bouncer`.
   - From a checkout: build the binary from the repository root:

     ```sh
     bun run build
     ```

     This produces `dist/bouncer`. `bouncer harness shim pi-agent` bakes
     **the path bouncer was invoked through** into the printed shim's
     `BOUNCER` constant (made absolute, never resolved: a symlink to
     `dist/bouncer` keeps its own path; the binary's own resolved path,
     `process.execPath`, when the invoked path cannot be told) — always run
     it through the compiled binary you intend to keep installed, never a
     `bun run src/cli.ts` source invocation (that would bake in `bun`'s own
     path instead of a useful one).

2. Decide the target `$PI_CODING_AGENT_DIR` — `~/.omp/agent` or
   `~/.pi/agent` for your primary account (both share one convention,
   ADR-0005), or a second directory for a client seat running the same
   binary. `bouncer doctor --harness pi-agent` checks
   `$PI_CODING_AGENT_DIR/extensions/bouncer.ts` by default.

3. Print the shim and write it into the extensions directory of **both**
   pi-agent and omp — they load the identical file:

   ```sh
   bouncer harness shim pi-agent > ~/.pi/agent/extensions/bouncer.ts
   bouncer harness shim pi-agent > ~/.omp/agent/extensions/bouncer.ts
   ```

   (Substitute `$PI_CODING_AGENT_DIR` for either path if you're wiring a
   second account.) `extensions/bouncer.ts` is already a protected write
   (`pi-agent-extensions`, derived from `policy/harness/pi-agent.toml`'s
   own `[[harness.persistent]]` row) — editing or deleting it directly,
   through a Bash redirect, or through `edit`'s hashline grammar asks for
   confirmation, the same protection every other harness's own wiring
   file has.

4. Restart the session (`pi`/`omp` load extensions at boot — an already
   running session keeps whatever it loaded when it started).

5. Verify the wiring:

   ```sh
   bouncer doctor --harness pi-agent
   ```

   A healthy, byte-identical install prints `[pass]` for `wiring:shim`
   (the installed file matches what `bouncer harness shim pi-agent`
   prints today, compared with the SAME `BOUNCER` path the installed
   copy already carries — a doctor run from a different checkout never
   claims drift just because its own binary lives somewhere else),
   `wiring:binary` (that baked `BOUNCER` path is an executable that is not a
   versioned Homebrew Cellar path), `policy`,
   and `log`, and exits 0. `[fail] wiring:shim` names the exact reprint
   command (`bouncer harness shim pi-agent`) when the installed file has
   drifted from a prior version or was hand-edited; `[fail] wiring:binary`
   means the shim's own baked bouncer path no longer resolves to an
   executable (a moved or removed `dist/bouncer` after `wiring:shim`
   already passed) — every tool call fails closed until either is fixed —
   or is a versioned Homebrew Cellar path
   (`<prefix>/Cellar/bouncer/<version>/bin/bouncer`) that `brew upgrade`
   will remove: reprint with `--bin <prefix>/bin/bouncer`, the command the
   failure line names.

   If omp runs under a profile on this machine, `doctor` also prints one
   `wiring:shim (profile <name>)` line per profile — see
   [omp profiles](#omp-profiles): a profile does not load the shim installed
   above.

## Shadow first (recommended before cutover)

Unlike Claude Code and Codex, there is no `--shadow` flag to append to a
hook command line: the shim (`policy/harness/pi-agent.shim.ts`) hardcodes
its own spawn — `run --harness pi-agent`, no other argv, ever (ADR-0006
§ 7's own "carries no policy" contract; the shim is not configurable by
design). The shim's own `BOUNCER` constant, however, already reads
`process.env.BOUNCER_BIN` as a runtime override (falling back to the
baked path) — point it at a small wrapper script instead of `dist/
bouncer` directly to inject `--shadow`:

```sh
cat > ~/.pi/agent/bouncer-shadow-wrapper.sh <<'EOF'
#!/bin/sh
exec /path/to/dist/bouncer "$@" --shadow
EOF
chmod +x ~/.pi/agent/bouncer-shadow-wrapper.sh
```

Then export `BOUNCER_BIN` for the pi/omp process itself (its own shell
profile, or `env BOUNCER_BIN=~/.pi/agent/bouncer-shadow-wrapper.sh pi`) —
`run`'s own argv parsing accepts `--shadow` anywhere in the token list
(`docs/reference/cli.md`'s own `--shadow` section), so appending it after
the shim's own fixed `run --harness pi-agent` args works exactly like
prepending it would. Use the session normally for a while; `bouncer
audit --harness pi-agent` reads what it would have done
(`mode:"shadow"`-tagged log entries). At cutover, unset `BOUNCER_BIN` (or
point it back at the real binary) so the shim spawns `dist/bouncer`
directly again — `bouncer doctor --harness pi-agent`'s `wiring:binary`
check is unaffected either way, since it verifies the SHIM's own baked
fallback path, never whatever `BOUNCER_BIN` happens to override at
runtime.

## What an `ask` looks like in the UI, and headless

pi-agent's own `confirm` degrades to **`ask`** as of this writing
(`policy/harness/pi-agent.toml`'s dated measurement, run 2026-10-11 and
repeated 2026-10-12 under `pi` 0.84.1 and `omp` 18.9.1). In a real TUI
session the shim opens a numbered, one-key dialog (`ctx.ui.select`,
ADR-0006 § 7) titled `bouncer`, with bouncer's own reason above two
options:

```
bouncer
git-protected: git branch can rewrite history, mutate a remote, or discard work — confirm before running

  1. Allow
  2. Block
```

Only the exact answer `1. Allow` lets the tool run. `2. Block`, Esc, an
aborted dialog, or a dialog that fails for any reason blocks the tool with
bouncer's own reason. There is no timeout: an unanswered dialog waits for
you. What the keys do differs per binary — measured live, never assumed:

| | `omp` 18.9.1 | `pi` 0.84.1 |
|---|---|---|
| Default highlight | `2. Block` (`initialIndex: 1` honoured) | `1. Allow` (`initialIndex` ignored) |
| `1` / `2` | select instantly, no Enter needed | do nothing |
| Enter, nothing else pressed | blocks | **allows** |
| ↑/↓ moves the highlight, Enter confirms it | yes | yes |
| Esc | blocks | blocks |
| Ctrl+C (the key) | blocks, like Esc | blocks, like Esc |

So under `omp` the dialog is answered in one key and a stray Enter never
approves. Under `pi` 0.84.1 you move with the arrow keys and confirm with
Enter, and a stray Enter approves the highlighted `1. Allow` — as pi's
former Yes/No dialog did (its `confirm` is the same selector with `Yes`
first, `showExtensionConfirm` in pi 0.84.1's source): read the highlighted
line before pressing Enter under `pi`.

A headless session (`pi -p "…"`/`omp -p "…"`) has no UI at all, so
`hasUI` is `false` and the call is blocked outright — no dialog opened,
nothing emitted — never left hanging (measured live, both binaries).

### Herdr, and other status integrations

While the dialog is open — and only when a UI exists — the shim emits
omp's `herdr:blocked` event on the extension bus: `{ active: true,
label: "bouncer: <reason>" }` before the dialog opens, `{ active: false }`
once it closes, whatever the answer. Herdr's own omp integration listens
for that event, so the agent is expected to show `blocked` for the
duration of the dialog instead of `working` (omp's own dialogs emit
nothing, so without the signal an agent waiting on a Bouncer ask looks
busy). The signal is an observability signal, not policy: it changes no
verdict, it is emitted whether or not anything subscribes, and a `pi`/
`omp` with no event bus, or an `emit` that throws (a throwing subscriber
is already contained by omp's own bus), can neither keep the dialog from
opening nor change its outcome. Measured live on both binaries with a
stand-in subscriber on `pi.events`: it saw `active: true` when the dialog
opened and `active: false` right after the answer, Esc or Ctrl+C. With
the dialog open and the process itself sent SIGINT, SIGTERM or SIGHUP,
`omp` still releases it (its shutdown settles the dialog first); `pi`
0.84.1 exits with the dialog still pending and never emits `active:
false` — the signal dies with the process. Herdr's own `blocked` flip is
an operator check (Verify, below).

Known limit: vibe-island listens to omp's native `tool_approval_*`
events, not to `herdr:blocked`, so it stays blind to a Bouncer ask.

## Doctor notices at session start

`bouncer run --harness pi-agent session_start`'s own doctor text (wiring
problems, active policy relaxations) reaches you two ways, both fixed
rules the shim always runs (never a per-harness choice):

1. `ctx.ui.notify` — an immediate, best-effort toast. Confirmed live: it
   renders as a startup warning banner under `pi` 0.84.1's TUI. Not
   independently isolated under `omp` 18.1.10's TUI (the one live `omp`
   run that showed a startup banner used a shim build where the second
   path below was already live too, and only that second path left hard
   proof in the session's own transcript) — present or absent for this
   toast specifically on `omp` is unconfirmed either way.
2. A message queued for the session's FIRST `before_agent_start` turn
   (`customType: "bouncer-doctor"`, `display: true`) — delivered exactly
   once, then cleared. Confirmed live two ways: headless (`-p`), on
   **both** binaries directly (the doctor text reaches the model's own
   context the moment real turn processing begins, regardless of
   whether a UI is attached); and, on `omp`, from a real interactive
   session's own persisted transcript (a `custom_message` entry,
   `customType: "bouncer-doctor"`, matching this delivery's own shape
   exactly) — the banner Jonathan saw at the top of `omp`'s screen
   during probe 2 was this path, not (provably) the toast above. This
   is why a wiring or policy problem is never silent even in a headless
   session, on either binary.

## `PI_CODING_AGENT_DIR` for a second account

The same binary guards a second pi-agent/omp account by pointing
`PI_CODING_AGENT_DIR` at that account's own directory before starting the
session — its profile overlay (`$PI_CODING_AGENT_DIR/bouncer/`), audit log
(`$PI_CODING_AGENT_DIR/logs/hooks/bouncer.log`), and printed shim stay
entirely separate from the primary account's. Reprint and reinstall the
shim under that directory too (step 3) — nothing is shared automatically.

## omp profiles

omp can run under a **profile**: `OMP_PROFILE=<name>`, `PI_PROFILE=<name>`
(`OMP_PROFILE` wins when both are set) or `omp --profile <name>`. The session
then uses its own agent directory, `~/.omp/profiles/<name>/agent`, **instead
of** `~/.omp/agent`, and it loads extensions from that directory only. The
shim installed in `~/.omp/agent/extensions` is not loaded there: **a profile
without its own copy of the shim runs without bouncer.**

Observed live on omp 18.9.1, in a temporary `HOME` (`omp -p … --no-session`,
with `BOUNCER_PROBE_LOG` set: the shim appends the `session_start` payload it
sends to that file, so an empty log means the shim never loaded):

- shim only in `~/.omp/agent/extensions`: a plain session loaded it, a
  session under `OMP_PROFILE=<name>` did not;
- shim in `~/.omp/profiles/<name>/agent/extensions/bouncer.ts`: the profiled
  session loaded it;
- the same with `PI_PROFILE` and with `--profile`;
- with `PI_CODING_AGENT_DIR` set as well, the profile wins: omp ignores
  `PI_CODING_AGENT_DIR` under a profile and exports the profile's own agent
  directory in its place.
- the name rule (checked with `omp --profile=<name> --alias <x>`, which
  validates the name without a model call): `Work`, `con`, `CON.txt`,
  `aux.txt`, `com1`, `lpt9`, `prn`, `nul`, `work.`, `.work`, `-work`,
  `_work`, `a b` and a 65-character name exit 1 with `Error: Invalid OMP
  profile "Work". Profile names must match ^[a-z0-9][a-z0-9._-]{0,63}$, cannot
  be "." or "..", cannot end with ".", and cannot be a Windows reserved device
  name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, or any of those with an
  extension).`; `work`, `client-2`, `w.o-r_k`, a 64-character name, `console`,
  `com10`, `con-x` and `0abc` are accepted;
- `OMP_PROFILE=default` opens the default agent directory: a marker extension
  in `~/.omp/agent/extensions` loaded, one in
  `~/.omp/profiles/default/agent/extensions` did not;
- on a case-insensitive filesystem (the macOS default), `OMP_PROFILE=work`
  opens a folder spelled `Work`: its extension loaded.

Install the shim in each profile, the way step 3 does for the default
directory:

```sh
mkdir -p ~/.omp/profiles/<name>/agent/extensions
bouncer harness shim pi-agent > ~/.omp/profiles/<name>/agent/extensions/bouncer.ts
```

(`mkdir -p`: omp creates a profile's `agent/` the first time it launches, with
no `extensions/` in it.) Do it **before the first launch** of a new profile: a
folder under `~/.omp/profiles/` that was never launched has no `agent/` yet, so
`doctor` does not list it, and that first session runs without bouncer.

omp hands the profile's agent directory to the shim's `bouncer run` as
`PI_CODING_AGENT_DIR`, so each profile is its own bouncer account: its profile
overlay is `<profile agent dir>/bouncer/` and its audit log
`<profile agent dir>/logs/hooks/bouncer.log` (the common layer,
`~/.agents/bouncer/`, stays shared).

`bouncer doctor --harness pi-agent` reports every directory
`~/.omp/profiles/*/agent` it finds, one line each:

```
[pass] wiring:shim (profile client) — /home/me/.omp/profiles/client/agent/extensions/bouncer.ts matches the printed shim
[fail] wiring:shim (profile work) — extensions/bouncer.ts is missing — a session under this profile loads nothing from the default agent directory and runs without bouncer; install it with `mkdir -p ~/.omp/profiles/work/agent/extensions && bouncer harness shim pi-agent > ~/.omp/profiles/work/agent/extensions/bouncer.ts`
```

- `[fail]` when `extensions/bouncer.ts` is missing (the line carries the
  command for that profile) or differs from what `bouncer harness shim
  pi-agent` prints today (`extensions/bouncer.ts differs from … ; reprint it`
  — reprint it into that profile); `[pass]` when it is identical. Exit code 1
  while any profile fails.
- No `~/.omp/profiles` directory: no profile line at all. A stray file, or a
  folder with no `agent/` directory, is not a profile and is not listed. A
  `profiles` directory that exists but cannot be listed is itself a
  `[fail]` (`wiring:shim (profiles)`).
- A folder whose name omp 18.9.1 refuses is not a profile and is not listed:
  no session can open it, and a standing `[fail]` for it would be a false
  alarm. The rule is the one measured above: `^[a-z0-9][a-z0-9._-]{0,63}$`,
  not ending with `.`, not a Windows device name (`con`, `prn`, `aux`, `nul`,
  `com0`–`com9`, `lpt0`–`lpt9`, with or without an extension), and not
  `default` (which omp reads as "no profile"). The one exception is case,
  and it errs towards listing: omp refuses `Work`, but launched as `work` it
  opens `profiles/Work/agent` on a case-insensitive filesystem, so a
  capitalised folder **is** listed. (On a case-sensitive filesystem it can
  never run: rename or delete it.) The rule mirrors omp 18.9.1 — re-measure
  it after an omp upgrade.
- `doctor` never installs anything: reprinting is yours, a doctor that
  writes into an agent directory is a different threat model. The command it
  prints is only built from a plain path (letters, digits, `.`, `_`, `-`,
  `/`); anything else it prints from the file system is shown with control
  characters escaped.
- **Session-start notice.** The failing profile lines also reach the notice
  every pi-agent/omp session receives at start (see above), whichever profile
  that session runs under — on lines of their own, never under the "this
  session may be running partially or fully unguarded" header, which stays
  for the session's own wiring: a guarded session does not read as unguarded
  because another profile is not.

  ```
  bouncer doctor: another omp profile has no Bouncer shim: work — install it with `mkdir -p ~/.omp/profiles/work/agent/extensions && bouncer harness shim pi-agent > ~/.omp/profiles/work/agent/extensions/bouncer.ts`
  bouncer doctor: another omp profile carries a stale Bouncer shim: client — reprint it with `mkdir -p ~/.omp/profiles/client/agent/extensions && bouncer harness shim pi-agent > ~/.omp/profiles/client/agent/extensions/bouncer.ts`
  ```

  A shim file that cannot be read reads "another omp profile's Bouncer shim
  cannot be read: <name> — …"; a `profiles` directory that cannot be listed,
  "omp profiles cannot be checked, they may run without Bouncer: ~/.omp/profiles
  is unreadable (EACCES)". The profile a session runs under is not "another":
  it is reported by the plain `wiring:shim` line only. `doctor` recognises it
  by `PI_CODING_AGENT_DIR`, which omp exports as that profile's agent
  directory (observed) — it reads the account directory it already resolves,
  nothing more.
- `bouncer doctor --harness pi-agent --settings <path>` checks that one file
  and lists no profile.
- Only omp's `~/.omp/profiles` is read; `pi` is not covered.

## After an upgrade

`bouncer harness shim pi-agent`'s output can change between bouncer
releases (a bug fix in the fixed fail-closed rules, ADR-0006 § 7). Reprint
and overwrite `extensions/bouncer.ts` after every `bun run build`/binary
upgrade — `bouncer doctor --harness pi-agent`'s `wiring:shim` check is
exactly the reminder: it fails the moment an installed copy no longer
matches what the CURRENT binary would print, naming the reprint command.

Bouncer 1.6.0 is one such release: the ask dialog became the numbered
select above and the shim now emits `herdr:blocked`. Every install reads
`[fail] wiring:shim` until it is reprinted (`bouncer harness shim
pi-agent > <dir>/extensions/bouncer.ts` — with the same `--bin` as at
install time — for each of `~/.pi/agent` and `~/.omp/agent`, or any
`PI_CODING_AGENT_DIR` seat), then restart the session; `bouncer doctor
--harness pi-agent` is `[pass]` again once it matches.

Every [omp profile](#omp-profiles) holds its own copy of the shim: reprint it
into each one too. `doctor` names every profile whose copy is stale or missing.

## Verify

- `bouncer doctor --harness pi-agent` exits 0 with every check `[pass]`
  (every `wiring:shim (profile …)` line included).
- A guarded command inside the session (e.g. `rm -rf /tmp/some-test-dir`)
  is denied, with the reason visible to the model.
- Editing `extensions/bouncer.ts` directly (or deleting it) asks for
  confirmation before it proceeds — the file's own protected-write row.
- Under Herdr, a Bouncer ask (e.g. `git push` under `omp`) is *expected*
  to show the agent `blocked`, with the `bouncer: …` label, in `herdr
  agent get` while the dialog is open, and `working` again after the
  answer — expected, to be confirmed by the operator's live Herdr run
  (pending: not observed yet). An agent that stays `working` through an
  ask: check `bouncer doctor --harness pi-agent` first — a shim printed
  before 1.6.0 does not emit the signal.

---
Source: policy/harness/pi-agent.toml, policy/harness/pi-agent.shim.ts,
src/adapter/shim.ts, src/adapter/codecs/wiring/shim-file.ts,
src/adapter/codecs/input/hashline.ts, src/adapter/doctor.ts,
src/cli-commands.ts, src/cli.ts, scripts/probe-pi-agent.sh
