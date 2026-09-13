# ADR-0004: A `protected_write` table — refuse the write, leave the read free

**Date**: 2026-09-04
**Status**: Accepted
**Deciders**: Jonathan Robic (design session, 2026-09-04, two rounds)

## Context

### Current situation

`bouncer` has one path table, `rules.secret.path`. It answers a single
question — "does this path read as secret-bearing?" — and applies the same
verdict whether the path is being read or written: `Read`, `Edit`,
`MultiEdit`, `Write` and `NotebookEdit` all hand their path to the same
`secret.checkPath` (`src/adapter/dispatch.ts`, `NATIVE_FILE_PATH_FIELD`),
and the Bash path-token scan has no notion of direction either. That design
is right for a secret: reading `~/.ssh/id_ed25519` is the leak, no write
distinction needed.

It is wrong for a second class of files: those the agent legitimately reads
all day and must not modify. The harness settings file is the canonical
one — `bouncer` is wired in it, `doctor` reads it, the agent reads it to
answer questions about hooks — and a write to it is exactly the act that
disarms every other rule. Because the only table blocks both directions,
none of these files can be in it, so today none of them is guarded.
Measured on the installed binary (`903b052`, then `3c80f2b`, both
profiles): `echo x > ~/.claude/settings.json`, `Write(~/.claude.json)`,
`Edit(~/.claude/settings.json)`, `yq -i '.a=1' ~/.claude/settings.json`,
`cat > ~/.zshrc`, `claude mcp add x -- npx y` are all **allow**. The
configuration's documented threat model lists this as its one hole ("not
covered: a write through Bash"), and papers over the tool side with a
declarative `ask: Edit(<configDir>/settings.json)` that covers the `Edit`
tool and nothing else.

Two facts about a configuration repository shape the design:

- `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude/hooks/` and
  `~/.claude/agents/` are symlinks into a configuration repository.
  `canonicalizePath` (`src/adapter/paths.ts`) already resolves native tool
  paths through `realpath`, so the engine sees the configuration-repository
  target — a path no baseline regex written for `.claude/settings.json`
  matches. The Bash token scan is synchronous and resolves nothing.
- Ticket 19 put `bouncer`'s own policy files in `secret.path` with verdict
  `confirm` (`bouncer-policy`, `(^|/)bouncer/(policy\.toml|policy\.d)(/|$)`),
  so reading the installed policy asks too. Every development session reads
  `policy/*.toml`; `bouncer rules list` prints the
  same rules without naming a path. The read-side ask defends nothing.

### Problem

Guard the *write* to a short list of files — harness configuration,
persistence files, `bouncer`'s own policy — through every write surface
`bouncer` sees, while leaving the *read* free, without loosening the
`secret` family and without a second grammar the operator has to keep in
step.

### Constraints

- Baseline universality (ticket 13): a baseline row must be true for any
  Claude Code user; operator-specific paths go to the overlay.
- Per-tool argument policy lives in engine code with fixtures, not in the
  policy file (ticket 26, `SEARCH_PATTERN_ARGUMENT_POLICIES`); the policy
  file carries rows, `[[override]]` carries local exceptions.
- Fail-closed: an unrecognised form is never a silent allow (ADR-0003
  doctrine, ticket 34 wording).
- The two-readings idiom (ticket 28): when a token can be read two ways,
  evaluate both, strictest wins.
- `bouncer` never emits `allow`; the verdict vocabulary is `block |
  confirm | observe` (`src/types.ts`), surfacing as deny/ask.
- Cost per tool call stays in the same order of magnitude (sub-50 ms).

## Options considered

### A — Where the rows live

**A1: a `direction = "write"` field on `secret.path` rows.**
Pros: no new table, no new file. Cons: two semantics under one id space
and one default verdict — `secret` defaults to `block` (disclosure),
protected writes default to `confirm` (integrity); every row would have to
carry its meaning; `rules list` and the digest lock could no longer say
"this table guards secrets". Effort: low. **Rejected.**

**A2: a new table `[[rules.protected_write]]`, family `protected-write`,
rows `{id, regex, reason, flags?, except?, verdict?}` like the five regex
tables, default verdict `confirm`.** Pros: one meaning per table, its own
digest lock, provenance and completeness entry; strictest-wins across
families already composes it with `secret`. Cons: a sixth table to
document. Effort: medium (engine module, schema, lint, docs). **Chosen.**

### B — Default verdict

**B1: `block`, relaxed per row.** Rejected: unlike sops/age (ADR-0002),
the human sometimes wants exactly this change (add a hook, add an MCP
server), and `block` would route every such case through an
`[[override]] action = "relax"`.

**B2: `confirm`.** Chosen. Individual rows may still set `verdict =
"block"`.

### C — What a Bash write is, and what happens to the rest

**C1: recognise a fixed set of write forms; anything else is unseen.**
Rejected: `python -c 'open(p,"w")'`, `code ~/.zshrc`, `yq -i` would pass
in silence — the hole this ADR closes, reopened by any tool not on the
list.

**C2: recognise the fixed set structurally; for any other command that
names a protected path as a token, `confirm` unless the command head is a
known reader.** Chosen. The protected list is a dozen files, so the
fallback's noise is bounded; legitimate Bash reads of those files go
through a small set of heads (`cat`, `jq`, `diff`, …); everything else
naming the file is either a write or rare enough to ask.

### D — Where the known-readers list lives

**D1: declared in the policy (`[rules.protected_write.readers]`).**
Rejected: a second convention beside ticket 26's "per-tool policy = code
+ fixtures"; and a local exception already has a home in `[[override]] …
except`.

**D2: a `ReadonlySet` in engine code, pinned by fixtures.** Chosen.

### E — Symlinks

**E1: realpath only.** Rejected on the measured symlink fact above: the
resolved path of `~/.claude/settings.json` matches no baseline regex, so
the table would be inert on the normal path.

**E2: a second row on the link target.** Rejected as the mechanism: it
moves a baseline concern into every configuration repository and misses
links the human did not think of.

**E3: two readings — raw path and `canonicalizePath` result — strictest
wins, on native tools and on Bash tokens.** Chosen. Covers "write through
the link". It does not cover a direct write to the repository file behind
the link (its realpath is itself); that is an overlay row, named in
Phase 2.

### F — The `bouncer-policy` row

**F1: keep the read-side `confirm` in `secret.path`.** Rejected: it
protects nothing (`rules list`, the docs and the repository expose the
rules by construction, ADR-0001) and it asks on every dev session of this
chantier.

**F2: split — read stays `confirm` in `secret`, write moves.** Rejected:
same reasoning, twice the rows.

**F3: absorb — the row moves to `protected_write`, id kept.** Chosen.
Write asks, read is free. No `[[override]]` in the installed configuration
names the id (checked 2026-09-04), so keeping it costs nothing and keeps
the audit log continuous.

### G — Writes through the harness CLI

`claude mcp add|remove`, `claude plugin install|enable`, `claude config
set` write `.claude.json`/`settings.json` without naming a path.

**G1: out of scope / separate ticket.** Rejected: closing the file-level
hole while the CLI stays open is the "sandbox cannot close `.claude.json`
because the harness writes it" story again, one layer up.

**G2: command rows in ticket 35.** Chosen: a `harness-self-config` row
set in `rules.command.bash`, `confirm`; the ADR names it as a condition
of the mechanism's completeness.

### H — Panel or direct ADR

The design tree was walked in two grilling rounds with every alternative
above named and rejected for a stated reason; a `design-panel` would
re-explore what the session closed. Direct ADR.

## Decision

1. **Table.** `[[rules.protected_write]]` in `policy/protected-write.toml`,
   family `protected-write`, row shape identical to the other regex
   tables, default verdict `confirm`, ids global like every other table,
   `[[override]]` applicable, own digest lock and completeness entries,
   provenance in `rules list`.

2. **Write surfaces.**
   - Native tools: `Write`, `Edit`, `MultiEdit`, `NotebookEdit` on their
     path field. `Read`, `Grep`, `Glob` are never writes.
   - Bash, structural (per segment, after `consumeCommandPrefixes`):
     redirect targets (`>`, `>>`, `>|`, `&>`, `&>>`, fd-prefixed `N>`);
     every non-option operand of `tee`; the last operand of `cp`,
     `install`, `rsync`, `ln`; every operand of `mv`, `rm`, `unlink`,
     `shred`, `truncate`, `touch`, `chmod`, `chown`, `chattr`, `patch`;
     the non-option operands of `sed -i`/`--in-place` and `perl -i`/`-pi`;
     `dd of=`. `cp`'s sources and `<` are reads.
   - Bash, fallback: a token matching a protected row, in a segment whose
     head is not a known reader, confirms with a reason that names the
     unrecognised form. Known readers: `cat less more head tail grep rg ag
     diff cmp jq stat wc file bat shasum sha1sum sha256sum sha512sum
     md5sum ls find fd tree cd pushd test [ source . echo printf bouncer`,
     and `git` for `diff show log blame status ls-files cat-file grep`
     only. `yq`, `code`, `vim`, `python`, `claude` and every other head
     fall to the fallback on purpose.
   - Token scan reuses ticket 26's pattern-argument masking and ticket
     27's prose/heredoc exclusion; `BASH_PATH_TOKEN` is not widened.

3. **Two readings** per path, raw and canonical (`canonicalizePath`,
   which already resolves the parent of a not-yet-existing file),
   strictest wins — on native tools and on Bash tokens, which makes the
   Bash scan asynchronous for this family only.

4. **Baseline rows** (regexes indicative; the build pins them with
   fixtures):

   | id | target |
   |---|---|
   | `harness-settings` | `(^|/)\.claude(-[\w.-]+)?/settings(\.local)?\.json$` |
   | `harness-hooks` | `(^|/)\.claude(-[\w.-]+)?/hooks(/|$)` |
   | `harness-plugins` | `(^|/)\.claude(-[\w.-]+)?/plugins(/|$)` |
   | `harness-instructions` | `(^|/)\.claude(-[\w.-]+)?/CLAUDE\.md$` |
   | `harness-global-config` | `(^|/)\.claude(-[\w.-]+)?\.json$` (`~/.claude.json`, `mcpServers`) |
   | `project-mcp-config` | `(^|/)\.mcp\.json$` |
   | `launch-agents` | `(^|/)Library/Launch(Agents|Daemons)/[^/]+\.plist$` |
   | `user-systemd-units` | `(^|/)\.config/systemd/user(/|$)` |
   | `shell-rc` | `(^|/)\.(zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|bash_login|profile)$`, `(^|/)\.config/fish/config\.fish$` |
   | `bouncer-policy` | `(^|/)bouncer/(policy\.toml|policy\.d)(/|$)` — moved from `secret.path`, id kept |

   Not in the baseline, on purpose: `<configDir>/agents/`, `commands/`,
   `skills/` (loaded on demand, written often and legitimately; the
   scripts they carry meet the command table when executed) and
   `<configDir>/projects/**/memory/` (the agent's own notes). `CLAUDE.md`
   is in: it is loaded at every session start, so a write there persists
   across sessions.

5. **Harness CLI rows** in `rules.command.bash`: `harness-self-config`
   confirms `claude mcp (add|remove)`, `claude plugin
   (install|enable|disable|uninstall)`, `claude config set`.

6. **Overlay (configuration repository, Phase 2).** Rows in the
   configuration repository behind the symlinks, the statusline scripts,
   `RTK.md`, and `~/.agents/` belong in the common layer. At the same time
   the declarative `ask: Edit(<configDir>/settings.json)` and its siblings
   leave `settings.json`.

7. **Interplay.** Strictest-wins with `secret.path` when both match
   (`direnv allow .envrc`: `secret` blocks, `protected_write` is
   irrelevant); with `persistence-scheduler` (ticket 32) both confirm, one
   prompt.

### Justification

A path table that cannot tell a read from a write can only guard files
nobody reads. The files that disarm `bouncer` are precisely the ones the
agent reads to work — so the guard has to be direction-aware, and since
"secret" and "must not be tampered with" are different questions with
different default answers, they are different tables. The write side on
Bash is where the engine work is: the tokenizer already carries offsets
and segments (ticket 29), so redirect and operand extraction is a reading
of that structure, not a new parser; and because the list of protected
files is short, a fail-closed fallback on "this command names the file
and is not a known reader" costs a bounded number of prompts while
closing the interpreter-and-editor gap that a fixed list of write forms
would leave open. Two readings per path is the price of symlinked
configuration: the engine sees the resolved path, the human wrote the row
for the visible one; evaluating both lets the baseline stay universal.

## Consequences

### Positive

- Writing `settings.json`, `.claude.json`, a hook, a LaunchAgent plist, a
  shell rc file, or `bouncer`'s policy asks on every surface `bouncer`
  sees — tools, Bash structure, Bash fallback — and reading them is free.
- The last declarative `ask` on file edits can go; the threat model's
  "not covered: a write through Bash" line goes with it.
- Reading the installed policy no longer prompts.

### Negative

- A sixth table to document and lock; the Bash scan gains an
  asynchronous branch for one family.
- The fallback prompts on unusual but legitimate reads (`yq . settings.json`,
  `git checkout -- ~/.zshrc`); the escape is an `[[override]] … except`
  with a reason, as for any row.
- A direct write to the repository behind a symlink is invisible to the
  baseline until the overlay row exists (Phase 2).

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Fallback noise higher than expected on real sessions | Medium | Low | one day of `bouncer audit` after install; readers set extended by fixture, never by widening a regex |
| A write form neither structural nor caught by the fallback (head is a known reader but writes — `tee` is structural, `sed` without `-i` prints) | Low | Medium | readers are read-only heads by construction; `git` is subcommand-gated; fixture per reader head with a write attempt |
| `harness-global-config` regex catching a project file named `.claude.json` | Low | Low | `confirm`, not `block`; `except` on the row if a real case appears |
| Realpath cost on every Bash token | Low | Low | resolve only tokens that match a row on the raw reading OR whose parent is a known symlinked dir; measure `check` wall time before/after |
| Agent edits the configuration-repository file behind the symlink | Medium on this configuration | High | Phase 2 overlay row; until then the `Edit(settings.json)` declarative ask stays |

## Implementation plan

### Phase 1 — this repository (ticket 35, one dev session, gate mode)
- [ ] `src/protected-write-rules.ts`: row loading, `checkPath` with two
      readings, `checkBashWrites` (structural extraction on the existing
      tokenizer + fallback with the readers set); dispatch wiring for the
      four native tools and Bash; family `protected-write`.
- [ ] `policy/protected-write.toml` with the ten baseline rows;
      `bouncer-policy` removed from `policy/secret.toml`; `harness-self-config`
      in `policy/command.toml`.
- [ ] Schema + lint: sixth table, ids global, `[[override]]` forms,
      `verdict` field validated as for the other tables.
- [ ] `fixtures/protected-write.json` both directions and every form
      above; `tests/guards-digest.test.ts` lock; `tests/completeness.test.ts`
      entries; the ticket-13 triage table amended.
- [ ] `docs/reference/policy.md` ("The six regex tables", the fallback
      and readers, Known limits), `docs/reference/cli.md` if `rules list`
      output changes.
- [ ] Rebuild, atomic install, `doctor` ×2, provenance memory.

### Phase 2 — the config repository (gated there)
- [ ] Overlay rows for the config repository, statusline scripts,
  `RTK.md`, `~/.agents/` in the common layer.
- [ ] `ask: Edit(<configDir>/settings.json)` and siblings removed from
  both `settings.json`; the documented write-through-Bash coverage-gap note updated.
- [ ] One day of `bouncer audit --days 1 --sessions-only` on both profiles: count
      `protected-write` fallback prompts, extend the readers set by fixture
      if a legitimate read repeats.

## Success metrics

- On the installed binary, both profiles: `echo x > ~/.claude/settings.json`,
  `Edit(~/.claude/settings.json)`, `Write(~/.claude.json)`, `cat > ~/.zshrc`,
  `cp x ~/Library/LaunchAgents/y.plist`, `yq -i … settings.json`, `claude
  mcp add …` ask; `cat ~/.claude/settings.json`, `jq . ~/.claude.json`,
  `Read(~/.zshrc)`, `git diff ~/.zshrc`, `cat ~/.agents/bouncer/policy.d/100-personal.toml`
  allow.
- `bouncer check` wall time unchanged in order of magnitude.
- Zero `bouncer-policy` prompts on reads in the next day's audit.

## References

- `src/adapter/dispatch.ts` (`NATIVE_FILE_PATH_FIELD`, `secretPathHit`),
  `src/adapter/paths.ts` (`canonicalizePath`), `src/secret-rules.ts`
  (`BASH_PATH_TOKEN`, `globPathReadings`), `src/command-rules.ts`
  (`tokenizeShellSegments`, `consumeCommandPrefixes`).
- ADR-0001 (layers, rules public by construction), ADR-0002 (why `block`
  is reserved for acts that are human-only), ADR-0003 (fail-closed
  doctrine); tickets 13 (baseline universality), 19 (`bouncer-policy`
  row), 26/27/28 (token readings), 32 (`persistence-scheduler`).

---

## History

| Date | Action | By |
|---|---|---|
| 2026-09-04 | Created, Accepted — two grilling rounds, fourteen decisions; Phase 1 is ticket 35 | Jonathan Robic |
| 2026-09-07 | Ticket 36: the one-day audit step names `--sessions-only` | Jonathan Robic |
