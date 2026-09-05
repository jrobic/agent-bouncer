# ADR-0005: Harness declarations — one block per assistant, rows derived

**Date**: 2026-09-05
**Status**: Accepted
**Deciders**: Jonathan Robic

## Context

### Current situation

ADR-0004 gave `bouncer` a `protected_write` table whose rows name the files a
harness loads at every session start: `settings(.local).json`, `hooks/`,
`plugins/`, `CLAUDE.md`. Every row is a hand-written regex on a `.claude`
path. Three gaps follow from that shape, all measured on the installed binary
`df9af8d`, both profiles:

1. **The directory itself has no row.** `rm -rf ~/.claude`, `rm -rf
   ~/.claude/*`, `mv ~/.claude ~/.claude.bak`, `cp -r ./cfg ~/.claude`,
   `rsync -a ./cfg/ ~/.claude/`, `ln -sfn /tmp/evil ~/.claude`, `chmod -R
   777 ~/.claude`, `trash ~/.claude`, `tar xzf c.tgz -C ~/.claude` are all
   **allow**. Each of them replaces or destroys every protected file at once;
   the per-file rows never see the directory token. The 35 A/B report
   recorded this as the `harness-config-dir` candidate.
2. **Only Claude Code is described.** The workstation runs four assistants.
   `echo x > ~/.omp/agent/config.yml` (model roles, `approvalMode`),
   `rm -rf ~/.omp/agent/extensions`, `echo x > ~/.codex/config.toml`,
   `echo x > ~/.codex/AGENTS.md`, `echo x > ~/.config/opencode/opencode.json`
   are all **allow**. These files play exactly the role of `settings.json`
   for their harness, and omp is the harness the workstation actually uses.
   ADR-0004 did not exclude them; it did not see them.
3. **Environment names are opaque.** `$HOME/.claude/hooks` matches only
   because the regex finds `.claude/hooks` inside the token; the engine
   expands nothing. `rm -rf "$CLAUDE_CONFIG_DIR"` and `rm -rf
   "$CLAUDE_CONFIG_DIR/hooks"` are **allow**, although
   `CLAUDE_CONFIG_DIR` is the documented way to name the profile directory
   and the one the adapter itself honours (`src/adapter/log-path.ts`).

Adding twelve more regex rows would close the first two gaps for the four
harnesses present today and leave the third open. It would also leave the
next assistant to whoever knows the regex dialect: a harness is four facts
(a directory, the variables that name it, the files it loads at boot, the
subdirectories it loads on demand), and the rows are a function of those
facts.

### Constraints carried over

- ADR-0004 § 4 keeps `agents/`, `commands/`, `skills/` and
  `projects/**/memory/` out of the table: written often and legitimately,
  loaded on demand, the scripts they carry meet the command table when run.
  A directory row must not re-protect them by accident.
- Overlay semantics are ADR-0001's: an invalid overlay is rejected as a unit
  and the baseline stands alone. Whatever a workstation adds must degrade to
  a still-correct baseline.
- Verdict `confirm`, not `block` (ADR-0004): deleting or moving one's own
  configuration is legitimate during a reinstall; the human must see it, not
  be prevented.

## Decision

1. **A `[[harness]]` table** in a new baseline file `policy/harness.toml`,
   overlayable from `policy.d/`. One block per assistant:

   ```toml
   [[harness]]
   id = "claude-code"
   dir = ["(^|/)\\.claude"]              # regex fragments; the directory, no trailing slash
   env = ["CLAUDE_CONFIG_DIR"]           # variables that name that directory
   reason = "Claude Code configuration directory"

   [[harness.persistent]]                # files loaded at every session start
   id = "harness-hooks"                  # explicit: stable in logs, audit, docs
   path = "hooks(/|$)"                   # relative to each dir
   reason = "Claude Code hooks can alter future tool-call enforcement"
   ```

   Optional `parents = [...]`: directories whose deletion takes the config
   dir with them but which carry no persistent files of their own
   (`~/.omp` above `~/.omp/agent`). They derive a directory row only.

2. **Derivation.** The loader turns each block into `protected_write` rows,
   in this order, before the hand-written rows of the same family:
   - `<id>-config-dir` — for every `dir` and `parents` fragment `D`:
     `D/?$`. The directory token only: `~/.claude`, `~/.claude/`, and — via
     the empty-name glob reading of ADR-0004 — `~/.claude/*`. Children are
     not matched; they keep their own rows or none.
   - one row per `persistent` entry, id as declared, regex `D/<path>` for
     every `dir` fragment `D`.
   Derived rows carry provenance `[harness:<id>]` in `rules list` and
   `doctor`; `rules lint` compiles every fragment, rejects duplicate harness
   or persistent ids, and requires upper-case `env` names.

3. **Environment expansion.** Before path matching, a Bash token of the form
   `$NAME`, `${NAME}`, `"$NAME…"` whose `NAME` is declared in some block's
   `env` is rewritten to a canonical witness path for that block's first
   `dir` (`CLAUDE_CONFIG_DIR` → `~/.claude`, `CODEX_HOME` → `~/.codex`,
   `PI_CODING_AGENT_DIR` → `~/.omp/agent`). Only declared names expand; an
   undeclared `$CONFIG/hooks` stays opaque. The rewrite feeds the existing
   matchers, so the persistent rows cover `"$CLAUDE_CONFIG_DIR/hooks"`
   without change. Same-line assignments (`D=~/.claude; rm -rf $D/hooks`)
   are a known limit, not expanded.

4. **Brace expansion** in the Bash tokenizer: `~/.{claude,codex}` yields one
   candidate token per alternative, each matched independently. A pure
   function on the token; nested braces and ranges stay unsupported.

5. **Baseline harnesses** — the ones with a documented directory convention
   (the build cites the source for each in the row `reason` or the policy
   comment):

   | id | dir | env | persistent |
   |---|---|---|---|
   | `claude-code` | `~/.claude` | `CLAUDE_CONFIG_DIR` | `settings(\.local)?\.json$`, `hooks(/\|$)`, `plugins(/\|$)`, `CLAUDE\.md$` |
   | `codex` | `~/.codex` | `CODEX_HOME` | `config\.toml$`, `AGENTS\.md$` |
   | `opencode` | `~/.config/opencode` | — | `opencode\.jsonc?$`, `AGENTS\.md$`, `plugins?(/\|$)` |
   | `omp` (pi) | `~/.omp/agent`, `~/.pi/agent` ; parents `~/.omp`, `~/.pi` | `PI_CODING_AGENT_DIR` | `config\.ya?ml$`, `models\.ya?ml$`, `extensions(/\|$)` |
   | `gemini-cli` | `~/.gemini` | — | `settings\.json$`, `GEMINI\.md$` |
   | `cursor` | `~/.cursor` | — | `hooks\.json$`, `mcp\.json$` |

   Excluded everywhere, by ADR-0004 § 4: `agents/`, `agent/`, `commands/`,
   `skills/`, `projects/**/memory/`, logs, caches, sessions. `extensions/`
   (omp) is in: an extension executes at every boot.

6. **Migration.** The four `harness-*` rows of `policy/protected-write.toml`
   (`harness-settings`, `harness-hooks`, `harness-plugins`,
   `harness-instructions`) move into the `claude-code` block with their ids
   unchanged. `harness-global-config` (`~/.claude.json`, a sibling of the
   directory, not inside it) and the command row `harness-self-config` stay
   where they are.

7. **The profile suffix leaves the baseline.** Today's rows accept
   `.claude(-[\w.-]+)?`; the suffix is a convention of this workstation
   (`~/.claude-work`), not of the harness. Baseline `dir` is `~/.claude`
   only. **Overlay merge is by `id`**: a `[[harness]] id = "claude-code"`
   block in `policy.d/` appends its `dir`, `parents` and `env` to the
   baseline block and inherits its `persistent` list — a profile that forgot
   a persistent file is exactly the bug the merge is there to prevent.
   Consequence to state plainly: `~/.claude-work/settings.json` is protected
   by the common overlay (`~/.agents/bouncer/policy.d/`), and if that overlay
   is rejected the baseline protects `~/.claude` alone.

8. **Unknown heads** (`trash`, `ditto`, `tar -C`, `unzip -d`) are not
   registered as writers. A derived row matching one of their tokens reaches
   the conservative fallback of ADR-0004 and confirms with the generic
   message; the readers set in code (`ls`, `cat`, `find`, `grep`, …) keeps
   reads free.

### Alternatives considered

- **Twelve hand-written rows plus a small `[[env]]` table.** Closes the
  measured gaps, teaches the engine nothing: the next assistant is four
  regexes again, and the env table is a second concept beside the rows.
- **Derived rows for new harnesses only, Claude rows untouched.** Two ways
  of saying the same thing side by side; the migration is the point.
- **Directory subtree (`(/|$)`) instead of the directory token.**
  Re-protects `skills/`, `agents/` and the memory directory ADR-0004
  excluded; asks at every memory write.
- **Container subdirectories (`agents/`, `skills/`) as `rm -rf` targets
  only.** Restorable from the repository behind the symlinks; the ask
  fatigue is not paid for by a persistence threat.
- **`block` like `~/.ssh`.** A reinstall deletes its own configuration.

## Consequences

- `rm -rf ~/.claude`, `mv ~/.claude x`, `rm -rf ~/.claude/*`, `rsync … ~/.claude/`,
  `cp -r x ~/.codex`, `rm -rf ~/.omp/agent`, `echo x > ~/.omp/agent/config.yml`,
  `rm -rf "$CLAUDE_CONFIG_DIR"`, `rm -rf ~/.{claude,codex}` → confirm.
- `ls ~/.claude`, `cat ~/.omp/agent/config.yml`, `rm -rf ~/.claude/skills`,
  `echo x > ~/.claude/projects/x/memory/MEMORY.md`, `rm -rf ~/.claude_backup`,
  `rm -rf $CONFIG/hooks` → allow.
- Baseline only: `rm -rf ~/.claude-work`, `echo x > ~/.claude-work/settings.json`
  → allow. The workstation overlay restores them (dotfiles, after the ship).
- `fixtures/protected-write.json` cases written against the profile suffix
  are rewritten to baseline semantics; overlay merge gets its own cases.
- Known limits, documented in `docs/reference/policy.md`: truncated globs
  (`~/.cla*`, `~/.claude/set*` — both readings miss), same-line variable
  assignment, nested braces.

## History

| Date | Change |
|---|---|
| 2026-09-05 | Proposed after the design session (two rounds, seven decisions); accepted the same day. |
