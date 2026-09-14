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
below; see [Install](install.md). Print the extension with:

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
     **this process's own absolute path** (`process.execPath`) into the
     printed shim's `BOUNCER` constant — always run it through the compiled
     binary you intend to keep installed, never a `bun run src/cli.ts`
     source invocation (that would bake in `bun`'s own path instead of a
     useful one).

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
   `wiring:binary` (that baked `BOUNCER` path is executable), `policy`,
   and `log`, and exits 0. `[fail] wiring:shim` names the exact reprint
   command (`bouncer harness shim pi-agent`) when the installed file has
   drifted from a prior version or was hand-edited; `[fail] wiring:binary`
   means the shim's own baked bouncer path no longer resolves to an
   executable (a moved or removed `dist/bouncer` after `wiring:shim`
   already passed) — every tool call fails closed until either is fixed.

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

## What `confirm` looks like in the UI, and headless

pi-agent's own `confirm` degrades to **`ask`** as of this writing
(`policy/harness/pi-agent.toml`'s dated measurement): a live probe under
both `pi` 0.84.1 and `omp` 18.1.10 confirmed real `ctx.ui.confirm` dialogs.
Decline blocked the tool with bouncer's own reason; accept let it run. The
shim's own contract (ADR-0006 § 7) is `ctx.hasUI ? await
ctx.ui.confirm("bouncer", reason) : false` — a real TUI session prompts and
waits for accept/decline; a headless session (`pi -p "…"`/`omp -p "…"`) has
no UI at all, so `hasUI` is `false` and the call is blocked outright, never
left hanging (also measured live, both binaries).

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

## After an upgrade

`bouncer harness shim pi-agent`'s output can change between bouncer
releases (a bug fix in the fixed fail-closed rules, ADR-0006 § 7). Reprint
and overwrite `extensions/bouncer.ts` after every `bun run build`/binary
upgrade — `bouncer doctor --harness pi-agent`'s `wiring:shim` check is
exactly the reminder: it fails the moment an installed copy no longer
matches what the CURRENT binary would print, naming the reprint command.

## Verify

- `bouncer doctor --harness pi-agent` exits 0 with every check `[pass]`.
- A guarded command inside the session (e.g. `rm -rf /tmp/some-test-dir`)
  is denied, with the reason visible to the model.
- Editing `extensions/bouncer.ts` directly (or deleting it) asks for
  confirmation before it proceeds — the file's own protected-write row.

---
Source: policy/harness/pi-agent.toml, policy/harness/pi-agent.shim.ts,
src/adapter/shim.ts, src/adapter/codecs/wiring/shim-file.ts,
src/adapter/codecs/input/hashline.ts, src/adapter/doctor.ts,
src/cli-commands.ts, src/cli.ts, scripts/probe-pi-agent.sh
