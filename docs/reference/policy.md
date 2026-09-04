# Policy format reference

The policy is TOML, in three layers.

## Baseline vs. overlay

**Baseline** — five files in this repository, one per rule family,
compiled into the binary at build time (`bun build --compile`):
`policy/command.toml`, `policy/secret.toml`, `policy/mcp-write.toml`,
`policy/write-secret.toml`, `policy/prompt.toml`. Each file's own
top-level TOML header (`[[rules.command.bash]]`, `[rules.secret...]`,
...) already scopes it to its family, so merging the five at build time
is a plain shallow merge — no file ever contributes to another's key.
Always present, never edited at runtime. The vetted starting point.

**Overlay** — two named layers on top of the baseline (ADR-0001), each a
SET of files with the same shape, read from disk on every `bouncer
run`/`check`/`rules`/`doctor`/`audit` invocation (no caching, no restart
needed after an edit):

1. **common** — `~/.agents/bouncer/`, a harness-neutral product
   convention: no file anywhere names this root, and every adapter reads
   the same one (today only the Claude Code adapter exists; a future
   harness's adapter — ticket 15 — reads it unchanged). Meant for rules
   shared across every profile on a workstation (personal and client
   seats alike) without a per-profile mount gesture.
2. **profile** — `<configDir>/bouncer/`, resolved by the calling
   harness's adapter (for Claude Code: `<configDir>` is `~/.claude`
   unless the `CLAUDE_CONFIG_DIR` environment variable is set, in which
   case it's that value — `~` expanded, trailing slash normalized).

Both layers have the identical internal shape:

1. `<root>/policy.toml` — the single overlay file, if present.
2. `<root>/policy.d/*.toml` — every `.toml` file in that directory, in
   lexicographic FILENAME order (not write time), merged after
   `policy.toml`. A conf.d-style split for personal rules by theme
   (`10-npm.toml`, `20-client-x.toml`, ...).

No files at all, in EITHER layer, is baseline only, silently — a fresh
account with no overlay file is a normal, healthy state, not a warning.
An absent common layer specifically (no `~/.agents/` on the machine at
all) is likewise never a failure — `common: absent` in `doctor`/`rules
lint` output, never a warning — a fresh install simply has no common
layer yet.

The effective policy `bouncer` actually runs on is baseline merged with
the common layer's files, merged with the profile layer's files, in that
order, per-table (see § Merge order below), plus `[[override]]` and
`[[relax]]` applied on top — with the profile winning wherever the two
layers target the same thing (see § Precedence below).

## The rule row: `{id, regex, reason, flags?, except?, special?, verdict?}`

Every entry in the five regex tables below shares this shape:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique across ALL FIVE tables combined (ids resolve globally, not per-table). Lint-enforced against two things: an id already owned by an embedded BASELINE rule, in either overlay layer, is rejected — use `[[override]]` (§ below) to touch a baseline rule instead of shadowing it; an id shared between two DIFFERENT FILES of the SAME layer is rejected too (§ Cross-file conflicts). The same id repeated twice WITHIN one file is not a lint error — it stays the existing `[[override]]` batch semantics, an override naming that id applies to every row carrying it. |
| `regex` | string | yes | Must compile and stay inside the RE2-like dialect (§ below). |
| `reason` | string | yes | Shown in `bouncer check`/`rules list` output and in the degraded Claude Code verdict text. |
| `flags` | string | no | Regex flags — `i`, `m`, `s` only (§ below). |
| `except` | string | no | A second regex; if it ALSO matches, the rule does not fire (e.g. `.env.example`/`.env.test` excepted from the `.env` block). |
| `special` | string | no | An engine-recognized marker for logic no regex alone expresses. Today only `"git_remote_url"`, on the `secret.bash` entry that also needs the structural git parser to distinguish a config read from a write. |
| `verdict` | `"block"` \| `"confirm"` \| `"observe"` | no | A per-row static override of the family's default verdict (e.g. every `secret.path` row defaults to `"block"`; `transcript-backup` sets `verdict = "confirm"`). Lint-validated against the same three kinds `[[override]]`'s `action = "relax"` can name. A live `[[override]]` relax still wins over this field when both apply — this is the row's own static default, not the loudest word on the subject. |

## The five regex tables

| Table | Family | Guards |
|---|---|---|
| `rules.command.bash` | command | destructive/exfiltration/escalation shell patterns; proxy execution through file finders, pipeline executors, and preprocessors |
| `rules.secret.path` | secret | file paths that read as secret-bearing |
| `rules.secret.bash` | secret | shell commands that reveal plaintext (sops/age decryption, git config, embedded URL credentials); see [Override a baseline rule](../how-to/override-a-baseline-rule.md) to relax a baseline row |
| `rules.write_secret` | write-secret | text about to be written that matches a known secret token shape |
| `rules.prompt` | prompt | submitted prompts matching a prompt-injection signature |

The command baseline also confirms outbound `publish` actions (package registries, Docker images, and `gh`/`glab` releases) and `forge-api-write` actions (a mutating HTTP verb or body-field flag on `gh api`/`glab api`). `forge-api-write` deliberately confirms `gh api graphql -f query=...` reads: flag-only matching cannot distinguish their query body from a mutation. `base64-decode-exec` blocks Base64, `xxd -r`, or `openssl enc -d` output piped directly into a shell or interpreter.

The secret baseline names `keychain-dump` for macOS Security commands that
print passwords or private keys. `credential-printer`, `shell-history`, and
`session-transcripts` confirm before exposing a live credential, a shell
history file, or a live Claude Code transcript; the `dotenv` row also covers
direnv's `.envrc`. `session-transcripts` targets only
`.claude[-profile]/projects/<slug>/<session>.jsonl`, leaving memory notes
available. A transcript observer is a workstation-specific workflow, so it
can relax that row in its profile overlay with a reason; no such override is
part of the baseline.

`direnv-trust` confirms before trusting a project `.envrc` to run on later
directory changes. `persistence-scheduler` confirms before `crontab`,
launchd, user-systemd, or `at` can schedule or start work beyond the session.


### Infrastructure mutation rows

The command table's `terraform-mutating`, `kubectl-mutating`, `helm-mutating`,
`docker-destructive`, and `sql-destructive-inline` rows return `confirm` before
infrastructure, cluster, release, Docker volume, or inline SQL mutations. They
do not infer whether a target is local or remote.

`kubectl-mutating` (`apply`/`create`), `helm-mutating` (`install`),
`docker-destructive`, and `sql-destructive-inline` are **Debatable (ticket
33)**. A profile can relax a row with `[[override]]`, `action = "relax"`, and
`verdict = "observe"` without removing the baseline guard.


### Known limits

- A sops command hidden behind a package script or launched by direnv is not
  seen; production-decryption scripts remain human-run.
- Plaintext inherited from the agent's launch environment is outside this
  guard's scope.
- A non-default `SOPS_AGE_KEY_FILE` is a human choice and needs a personal
  overlay row.
- A command hidden inside a finder or pipeline executor's `sh -c` argument is
  not inspected; the guard does not parse shell command strings.
- A pattern-only hidden-file search such as `rg --hidden -i env` can print
  matching dotenv lines. The path scan guards command arguments, not command
  output; `grep -r env .` has the same residual behavior.
- A separator-bearing guarded path literal in a heredoc source file remains
  scanned: this layer cannot distinguish source code from a filesystem target.
- A guarded directory name written with whitespace and no separator inside a
  quoted string, such as `cat "my secrets"`, is not a path candidate.
- A bare glob `*` is not expanded because it can name every path or no path.
- A metacharacter inside an extension, such as `*.p*m` or `*.p*`, has no
  faithful witness: the two readings cover names and prefixes, not extensions.
- A character class such as `*.[pk]em` is not interpreted by the path scan.
- A comma-brace expansion such as `*.{pem,key}` is not interpreted by the
  path scan.
- A variable-expanded glob such as `$KEY*.pem` is not resolved before scanning.
- A command substitution such as `$(ls *.pem)` is not evaluated before scanning.
- An escaped metacharacter such as `\\*.pem` is literal shell syntax, not a
  glob expansion.
- `sql-destructive-inline` sees SQL quoted directly after `-c` or `-e`, or
  SQLite's positional statement argument; statements passed with `-f` or stdin
  remain a known limit.

Example row (from the baseline):

```toml
[[rules.command.bash]]
id = "dd-device-write"
regex = "\\bdd\\s+[^|;&\\n]*\\bof=\\/dev\\/"
reason = "dd writing to a block device (/dev/...) — likely disk wipe"
```

An overlay addition to any of these five tables is pure hardening: it
can only add a new match, never override or shadow an existing baseline
row (baseline entries are always checked first).

## `rules.command.git`: the three declarative conditional forms

Below `rules.command.git`, two plain lists (`safe_subcommands`,
`config_read_modes`) and three declarative tables cover git subcommands
whose safety depends on their arguments — everything else falls through
to `git-protected` (always confirm). `checkout` and `restore` are the
two subcommands these three forms can't express (pathspec detection,
index-only form — `--staged` plus one or more pathspecs) — they stay
engine code under their own names.

**`ask_flags`** — safe unless one of `flags` is present, or (with
`max_positionals`) too many non-flag arguments are given. This is
baseline's own `branch` row verbatim, so pasting it into an overlay as-is
is a SUBSTITUTION of an already-governed subcommand (§ [[relax]] below)
— `reason` is what makes it valid as a real overlay entry, not just a
baseline-shape illustration:

```toml
[[rules.command.git.ask_flags]]
sub = "branch"
flags = ["-d", "-D", "--delete", "-m", "-M", "--move", "-f", "--force"]
reason = "example only — this duplicates the baseline row verbatim"
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `flags` | string[] | yes |
| `max_positionals` | number | no |
| `reason` | string | conditional — see § [[relax]] below |

**`safe_first_arg`** — safety hinges on the first non-flag argument.
Baseline's own `stash` row; same substitution note as above:

```toml
[[rules.command.git.safe_first_arg]]
sub = "stash"
values = ["drop", "clear"]
invert = true
safe_when_absent = true
reason = "example only — this duplicates the baseline row verbatim"
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `values` | string[] | yes |
| `invert` | boolean | no, default `false` (`true`: `values` names the UNSAFE first args, e.g. `stash`'s `drop`/`clear`) |
| `safe_when_absent` | boolean | yes |
| `reason` | string | conditional — see § [[relax]] below |

**`safe_grammar`** — safe only if the arguments match one exact token
sequence (`"*"` matches any single non-flag token). Written on its own
line, `sequences = [ ["--check"] ]` needs a space after the first
`[` — Bun's TOML parser misreads a bare leading `[[` as an
array-of-tables header even mid-value (see `policy/command.toml`'s own
`apply` entry, which avoids it by putting the outer bracket on its own
line — same for `pull`/`merge` in `examples/personal-overlay.toml`,
ticket 13's tracked example of a `safe_grammar` entry living in a
personal overlay instead of the baseline). Baseline's own `apply` row;
same substitution note as `ask_flags` above:

```toml
[[rules.command.git.safe_grammar]]
sub = "apply"
sequences = [ ["--check"], ["--check", "*"] ]
reason = "example only — this duplicates the baseline row verbatim"
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `sequences` | string[][] | yes |
| `reason` | string | conditional — see § [[relax]] below |

## The two algorithm-driven tables

`rm-rf-dangerous`, `sudo` (privilege escalation), and `git-protected`
are produced by engine algorithms, not by a `{id, regex, reason}` row —
`[[override]]` can't target them (§ below). Each is governed by its own
named table instead, additive only (new entries widen what's caught,
never narrow it):

```toml
[rules.command.rm_rf]
dangerous_targets = ["^\\/$", "^~\\/?$", "..."]  # regexes the rm target must NOT match

[rules.command.privilege_escalation]
commands = ["sudo", "doas", "pkexec", "runas", "please"]
```

`git-protected` is governed by `safe_subcommands` and the three
declarative forms above.

### Secret Bash path-token scan

`rules.secret.path` also scans path-like tokens in Bash commands. This is an
engine algorithm: it masks only declared search pattern or program arguments
for `grep`/`egrep`/`fgrep`, `rg`, `ag`, `ack`, `sed`, `awk`/`gawk`, and
`perl -e`/`-ne`/`-pe`, then applies the literal path-token scan to everything
else. In a whitespace-bearing quoted token or a recognized heredoc body, each
path token is considered independently: only a token carrying `/` or a
leading `~` remains scanned. Quoted tokens without whitespace and unquoted
tokens retain the full scan. Shell interpreter and `eval` command strings
retain the full scan.

A token containing `*` or `?` is checked with every metacharacter read as
`x`, then with every metacharacter empty. The stricter matching path verdict
wins. Tokens without either metacharacter keep the literal scan unchanged.

The parser shares the command guard's structural tokenizer and wrapper-prefix
handling; see the header of `src/command-rules.ts`. Pattern files and
file-targeting values (`-f`/`--file`, `-g`/`--glob`/`--iglob`, `--pre`) remain
scanned. An unknown tool, option, argument form, unterminated heredoc, or
unterminated quote retains the full scan.


## `mcp_write.read_prefixes`

A plain string list — an MCP tool call is a silent read when its
operation name (everything after the tool name's second `__`) starts
with one of these prefixes; anything else asks for confirmation. This is
the baseline table (`[rules.mcp_write]` directly) — an overlay can only
ADD to it through `[[relax]]` (§ below), never by writing this table
itself:

```toml
[rules.mcp_write]
read_prefixes = ["get", "list", "search", "fetch", "read", "query", "lookup", "describe", "view"]
```

## `[[override]]`: disable, replace, or relax a regex-table rule

```toml
[[override]]
rule = "curl-file-upload"   # must resolve to an id in one of the five regex tables
action = "disable"          # "disable" | "replace" | "relax"
reason = "..."              # mandatory, non-empty
# action = "replace" also needs:
regex = "..."
# action = "relax" also needs:
verdict = "confirm"         # "block" | "confirm" | "observe"
```

`rule` not resolving to a known id, a missing/empty `reason`, an
unrecognized `action`, `replace` without `regex`, or `relax` without a
valid `verdict` — each independently fails lint and rejects the whole
layer the override lives in (§ Fail-closed behavior below).

## `[[relax]]`: widen a pure allowlist

The only sanctioned way to add to `command.git.safe_subcommands`,
`command.git.config_read_modes`, or `mcp_write.read_prefixes` — a direct
addition to any of the three via the table itself is rejected outright.

```toml
[[relax]]
list = "command.git.safe_subcommands"   # one of the three lists above
value = "push"
reason = "..."   # mandatory, non-empty — this can only relax security
```

A `safe_first_arg`/`ask_flags`/`safe_grammar` overlay entry whose `sub`
is already governed by the baseline is a SUBSTITUTION, not a fresh
addition, and needs the same mandatory `reason` (see the field tables
above) — the overlay entry wins over the baseline one for that
subcommand.

## Regex dialect

Every `regex`/`except` (baseline, overlay, and an `[[override]]`'s
injected `regex`) is compiled and checked:

- **No lookaround** — `(?=`, `(?!`, `(?<=`, `(?<!` are rejected.
- **No backreferences** — `\1` through `\9` are rejected.
- **`flags` restricted to `i`, `m`, `s`** — `g` and `y` are rejected
  (both carry mutable `lastIndex` state across calls on a reused
  `RegExp` object, which this engine always does).
- The pattern must actually compile (`new RegExp(...)`) — an unclosed
  group or other syntax error is rejected the same way.

## Fail-closed behavior

Any failure in an overlay file — invalid TOML, a wrong-shaped table, a
lint-failing regex, an unresolvable or reason-less `[[override]]`/
`[[relax]]`, a malformed declarative git-conditional entry, a cross-file
conflict (§ below) — rejects **its own layer**, not the whole load
(ADR-0001 § Rejection): a good `policy.d/10-npm.toml` sitting next to a
broken `policy.d/20-bad.toml` in the SAME layer still doesn't apply on
its own (one bad file rejects the whole LAYER it lives in), but a broken
common-layer file no longer drops the profile layer, and vice versa — the
healthy layer stays fully active. Never partial application within a
layer, never a silent fallback. Each rejected layer produces its own loud
warning naming the layer and the specific file at fault: in the audit log
(`kind: "policy-warning"`, one entry per rejected layer — see
`docs/reference/audit-log.md`), in `bouncer rules lint`'s output, and in
`bouncer doctor`'s `policy` check.

```
$ bouncer rules lint
lint: FAILED (common: /path/to/.agents/bouncer, profile: /path/to/.claude/bouncer)
  - profile layer rejected — policy.d/30-broken.toml: Failed to parse toml
  layers: common: active (4 files), profile: rejected (policy.d/30-broken.toml)
```

The common layer's four files stay fully effective — only the profile
layer, the one that actually broke, dropped out.

**Both layers broken independently** produces two warnings, one per
layer, and the embedded baseline runs alone:

```
$ bouncer rules lint
lint: FAILED (common: /path/to/.agents/bouncer, profile: /path/to/.claude/bouncer)
  - common layer rejected — policy.toml: Failed to parse toml
  - profile layer rejected — policy.toml: Failed to parse toml
  layers: common: rejected (policy.toml), profile: rejected (policy.toml)
```

**A profile `[[override]]` orphaned by a dropped common layer** is the
one cascade: if the override's target rule lived only in a common-layer
file that just got rejected, the override no longer resolves to anything.
That is a SEPARATE fault in the profile file (not the common one), so the
profile layer is rejected too — never a partial profile that silently
lost the override it depended on. The baseline runs alone, with two
warnings: one naming the common file that broke, one naming the profile
file whose override no longer resolves.

### Migration guard

One more fail-closed case, adapter-specific rather than a broken file:
when the profile ROOT (`<configDir>/bouncer`), or its `policy.d`
directory, resolves — by `realpath`, following any symlink — to the
common root or somewhere under it, the WHOLE profile layer is dropped
(no partial "keep the root `policy.toml`" carve-out — simpler, and
`doctor` already fails until the link is gone either way). Three shapes
all trigger it: `<configDir>/bouncer/policy.d` linked straight to
`~/.agents/bouncer/policy.d`, that same `policy.d` linked to the common
ROOT instead, or `<configDir>/bouncer` itself linked to the common root
with no `policy.d` segment at all. This is the interim per-profile mount
some deployments used before this adapter read the common layer
natively; left in place, the same files would load twice — once as
"common", once as "profile" through the link — identical effect, lying
provenance. The warning names the real linked path:

```
$ bouncer doctor
[fail] policy — profile policy resolves to the common root (/path/to/.agents/bouncer) — remove the link (rm /path/to/.claude/bouncer/policy.d)
```

`SessionStart` repeats this warning every session until the link is
actually removed — an absent `policy.d` afterward is simply an empty
profile layer, the normal unconfigured case.

## Merge order

Three different orders, by scope:

- **The file SET itself, within one layer** — `policy.toml` first (if
  present), then every `policy.d/*.toml` file in lexicographic filename
  order. Where this matters observably: two files IN THE SAME LAYER each
  adding a regex-table rule that could match the same input — "first
  match wins" (src/policy/match.ts) means the earlier FILE's rule fires.
- **The layers themselves** — common, then profile. A common-layer file
  always merges before every profile-layer file, regardless of either
  layer's own filenames — see § Precedence below for what happens when
  the two layers target the same thing.
- **The five regex tables, `rm_rf.dangerous_targets`,
  `privilege_escalation.commands`** — baseline first, then every overlay
  file's additions across both layers, in merge order (common's files,
  then profile's). An overlay addition can only ever add, never shadow a
  baseline entry by position — UNLESS a later layer's row shares the
  earlier layer's row's `id` (§ Precedence), in which case the earlier
  layer's row is dropped rather than both surviving side by side.
- **`ask_flags` / `safe_first_arg` / `safe_grammar`** — overlay entries
  come first. Every consumer looks a `sub` up by `Array.find()`, so an
  overlay entry for an already-governed `sub` wins over the baseline
  one — this asymmetry is what makes such an entry a substitution
  (§ `[[relax]]` above), not a plain addition.

## Precedence: the profile wins on a shared target (ADR-0001)

The common and profile layers are not merged as two more files in one
set — the SAME target contributed by both is not a cross-file conflict,
it is the profile layer replacing the common layer's entry outright. The
targets this applies to (the four case ADR-0001 names):

- A regex-table row `id` (any of the five families).
- An `[[override]]`'s `rule`.
- An `[[relax]]`'s `list` + `value`.
- An `ask_flags` / `safe_first_arg` / `safe_grammar` entry's `sub`
  (within its own table — `ask_flags` and `safe_first_arg` sharing a
  `sub` name is not itself a shared target).

When both layers contribute the same target, the common layer's entry is
dropped from the effective policy entirely (never chained, never applied
alongside the profile's) and the profile's entry carries `shadows
common:<file>` in every provenance line (§ Provenance below) naming the
file it replaced. The profile row keeps its own position in file merge
order (after every common row) — overlay rows are hardening additions
after the baseline, so their mutual order rarely matters, and this shape
has no special case for it.

The cascade is additive, never subtractive: a profile can add or shadow,
never *revoke* a common `[[relax]]` — there is no `[[revoke]]` form (a
backlog idea). A relaxation not wanted on every profile does not belong
in the common layer.

Two files of the SAME layer sharing a target is still the unconditional
lint error described next — layering changes nothing about that.

## Cross-file conflicts: explicit lint error, never last-file-wins

Two DIFFERENT overlay files, IN THE SAME LAYER, targeting the SAME thing
is ambiguous enough to reject outright, rather than silently letting file
order decide (the SAME target across DIFFERENT layers is precedence, not
a conflict — see § Precedence above); a regex-table row whose `id` already
names an embedded BASELINE rule is rejected on the same footing, but
regardless of how many files are involved — even a single file, alone,
carrying the row is enough:

- Two `[[override]]` entries for the same `rule`, in two different files
  of the same layer.
- Two `[[relax]]` entries for the same `list` + `value`, in two different
  files of the same layer.
- Two `ask_flags`/`safe_first_arg`/`safe_grammar` entries for the same
  `sub`, in two different files of the same layer.
- Two regex-table rows (any of the five families) sharing the same `id`,
  in two different files of the same layer — ids resolve GLOBALLY, not
  per-family, so this is checked across all five tables combined, not
  per-table.
- A regex-table row whose `id` already names an embedded BASELINE rule
  (ADR-0001 § Precedence) — in EITHER layer, and regardless of whether any
  other file is involved at all: without this check, the row would
  silently get appended after the baseline row it collides with
  (first-match-wins never lets it fire), while an `[[override]]` naming
  that id would apply to both rows at once. Use `[[override]] action =
  "replace"` on the existing baseline rule instead of adding a same-id
  row.

```
$ bouncer rules lint
lint: FAILED (common: /path/to/.agents/bouncer, profile: /path/to/.claude/bouncer)
  - profile layer rejected — conflicting [[override]] for rule "curl-file-upload" in profile:policy.d/20-relax.toml and profile:policy.d/30-conflict.toml
  layers: common: active (4 files), profile: rejected (profile)

$ bouncer rules lint
lint: FAILED (common: /path/to/.agents/bouncer, profile: /path/to/.claude/bouncer)
  - profile layer rejected — policy.toml: regex rule id "curl-file-upload" reuses a baseline rule id — use [[override]] action = "replace"
  layers: common: active (1 files), profile: rejected (policy.toml)
```

A same-layer conflict names two files, not one — the layer as a whole is
what's at fault, so `layers:`'s per-layer file pointer falls back to
naming the layer itself; the full conflict message (both filenames) still
appears in the warning line above.

Multiple entries for the same target WITHIN one file are unaffected by
the cross-file check specifically — that's existing, single-file behavior
(sequential override chaining, e.g. `replace` then `relax` on the same
rule; first-entry-wins table lookup), unchanged by this rule. This
includes two regex-table rows sharing the same `id` inside ONE file: not
a CROSS-FILE lint error (id uniqueness across files/layers is what the
bullets above check), and — because `[[override]]` matches by id alone,
across every entry that carries it — an override targeting that shared id
applies to BOTH rows, in the same file or not. Stated as the batch
semantics it is, not a bug: `[[override]]` never resolves to "exactly
one" row, only to "every row currently carrying this id". The
baseline-id check above is independent of this and applies per-ROW: a row
inside a multi-row file is rejected on its own merits the moment its `id`
equals a baseline one, whether or not any sibling row in that same file
shares it.

Fail-closed rejection is per LAYER (ADR-0001 § Rejection): a broken file
in one layer rejects that layer alone, exactly like a broken file within
a single layer's own file set — see § Fail-closed behavior above for the
full rejection matrix and the migration guard.

## Provenance: which layer, and which file, a rule came from

`bouncer rules list` names the source file for every overlay-provenance
line — an addition, an override, or a relaxation — in a trailing
`[<layer>:<filename>]`, and marks any entry that won cross-layer
precedence over an earlier layer's with a trailing `shadows
<layer>:<filename>`:

```
override disable curl-file-upload — our CI legitimately uploads build artifacts via curl in every deploy [profile:policy.d/20-relax.toml]
overlay-relax command.git.safe_subcommands push — our CI force-pushes to a scratch branch and the confirm prompt blocks the pipeline [common:policy.d/100-personal.toml]
rule command.bash block-npm-publish overlay [profile:policy.d/10-npm.toml]
rule command.bash curl-file-upload overlay [profile:policy.toml] shadows common:policy.d/100-personal.toml
```

`bouncer rules lint`'s OK line names each layer too, `common/<file>` and
`profile/<file>` (slash, not colon — the same information, formatted for
a one-line summary rather than a per-rule tag), and says `<layer>:
absent` when that layer's ROOT DIRECTORY does not exist on disk at all
— never a failure. A root that DOES exist but happens to hold no
overlay files is a distinct, real state (`<layer>: 0 files`, reachable
in `doctor`'s output — see `docs/reference/cli.md`), never collapsed
into "absent":

```
$ bouncer rules lint
lint: OK (overlay: common: absent, profile/policy.toml)

$ bouncer rules lint
lint: OK (overlay: common/policy.d/100-personal.toml, profile/policy.toml)
```

A `baseline`-provenance line has no file to name (the embedded baseline
has no file on disk) and carries no suffix.

---
Source: src/policy/schema.ts, src/policy/load.ts, src/policy/lint.ts, src/policy/baseline.ts, policy/command.toml, policy/secret.toml, policy/mcp-write.toml, policy/write-secret.toml, policy/prompt.toml, src/adapter/policy.ts, src/adapter/log-path.ts
