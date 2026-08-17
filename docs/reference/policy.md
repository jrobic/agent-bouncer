# Policy format reference

The policy is TOML, in two layers.

## Baseline vs. overlay

**Baseline** — five files in this repository, one per rule family,
compiled into the binary at build time (`bun build --compile`):
`policy/command.toml`, `policy/secret.toml`, `policy/mcp-write.toml`,
`policy/write-secret.toml`, `policy/prompt.toml`. Each file's own
top-level TOML header (`[[rules.command.bash]]`, `[rules.secret...]`,
...) already scopes it to its family, so merging the five at build time
is a plain shallow merge — no file ever contributes to another's key.
Always present, never edited at runtime. The vetted starting point.

**Overlay** — a SET of files, read from disk on every `bouncer
run`/`check`/`rules`/`doctor`/`audit` invocation (no caching, no restart
needed after an edit):

1. `<configDir>/bouncer/policy.toml` — the single overlay file, if present.
2. `<configDir>/bouncer/policy.d/*.toml` — every `.toml` file in that
   directory, in lexicographic FILENAME order (not write time), merged
   after `policy.toml`. A conf.d-style split for personal rules by theme
   (`10-npm.toml`, `20-client-x.toml`, ...).

`<configDir>` is `~/.claude` unless the `CLAUDE_CONFIG_DIR` environment
variable is set, in which case it's that value (`~` expanded, trailing
slash normalized). No files at all (neither `policy.toml` nor a
`policy.d/` directory) = baseline only, silently — a fresh account with
no overlay file is a normal, healthy state, not a warning.

The effective policy `bouncer` actually runs on is baseline merged with
every overlay file in that order, per-table (see § Merge order below),
plus `[[override]]` and `[[relax]]` applied on top.

## The rule row: `{id, regex, reason, flags?, except?, special?, verdict?}`

Every entry in the five regex tables below shares this shape:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique within its table (not enforced by lint — a shared id makes an `[[override]]` targeting either entry apply to both). |
| `regex` | string | yes | Must compile and stay inside the RE2-like dialect (§ below). |
| `reason` | string | yes | Shown in `bouncer check`/`rules list` output and in the degraded Claude Code verdict text. |
| `flags` | string | no | Regex flags — `i`, `m`, `s` only (§ below). |
| `except` | string | no | A second regex; if it ALSO matches, the rule does not fire (e.g. `.env.example`/`.env.test` excepted from the `.env` block). |
| `special` | string | no | An engine-recognized marker for logic no regex alone expresses. Today only `"git_remote_url"`, on the `secret.bash` entry that also needs the structural git parser to distinguish a config read from a write. |
| `verdict` | `"block"` \| `"confirm"` \| `"observe"` | no | A per-row static override of the family's default verdict (e.g. every `secret.path` row defaults to `"block"`; `transcript-backup` sets `verdict = "confirm"`). Lint-validated against the same three kinds `[[override]]`'s `action = "relax"` can name. A live `[[override]]` relax still wins over this field when both apply — this is the row's own static default, not the loudest word on the subject. |

## The five regex tables

| Table | Family | Guards |
|---|---|---|
| `rules.command.bash` | command | destructive/exfiltration/escalation shell patterns |
| `rules.secret.path` | secret | file paths that read as secret-bearing |
| `rules.secret.bash` | secret | shell commands that leak a secret (git config, embedded URL credentials) |
| `rules.write_secret` | write-secret | text about to be written that matches a known secret token shape |
| `rules.prompt` | prompt | submitted prompts matching a prompt-injection signature |

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
staged-only form) — they stay engine code under their own names.

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
overlay.

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

Any failure anywhere in the overlay **file set** — invalid TOML in any
one file, a wrong-shaped table, a lint-failing regex, an unresolvable or
reason-less `[[override]]`/`[[relax]]`, a malformed declarative
git-conditional entry, a cross-file conflict (§ below) — rejects the
**whole set**, not just the broken file. The embedded baseline stays
fully active, and the rejection is a loud warning naming the specific
file at fault: in the audit log (`kind: "policy-warning"`, see
`docs/reference/audit-log.md`), in `bouncer rules lint`'s output, and in
`bouncer doctor`'s `policy` check. Never partial application (a good
`policy.d/10-npm.toml` sitting next to a broken `policy.d/20-bad.toml`
does not apply on its own), never a silent fallback:

```
$ bouncer rules lint
lint: FAILED (/path/to/policy.toml, /path/to/policy.d)
  - overlay policy rejected — falling back to the embedded baseline: policy.d/30-broken.toml: Failed to parse toml
```

## Merge order

Three different orders, by scope:

- **The file SET itself** — `policy.toml` first (if present), then every
  `policy.d/*.toml` file in lexicographic filename order. Where this
  matters observably: two overlay files each adding a regex-table rule
  that could match the same input — "first match wins"
  (src/policy/match.ts) means the earlier FILE's rule fires.
- **The five regex tables, `rm_rf.dangerous_targets`,
  `privilege_escalation.commands`** — baseline first, then every overlay
  file's additions, in file order. An overlay addition can only ever add,
  never shadow a baseline entry by position.
- **`ask_flags` / `safe_first_arg` / `safe_grammar`** — overlay entries
  come first. Every consumer looks a `sub` up by `Array.find()`, so an
  overlay entry for an already-governed `sub` wins over the baseline
  one — this asymmetry is what makes such an entry a substitution
  (§ `[[relax]]` above), not a plain addition.

## Cross-file conflicts: explicit lint error, never last-file-wins

Two DIFFERENT overlay files targeting the SAME thing is ambiguous enough
to reject outright, rather than silently letting file order decide:

- Two `[[override]]` entries for the same `rule`, in two different files.
- Two `[[relax]]` entries for the same `list` + `value`, in two different
  files.
- Two `ask_flags`/`safe_first_arg`/`safe_grammar` entries for the same
  `sub`, in two different files.
- Two regex-table rows (any of the five families) sharing the same `id`,
  in two different files — ids resolve GLOBALLY, not per-family, so this
  is checked across all five tables combined, not per-table.

```
$ bouncer rules lint
lint: FAILED (/path/to/policy.toml, /path/to/policy.d)
  - overlay policy rejected — falling back to the embedded baseline: conflicting [[override]] for rule "curl-file-upload" in policy.d/20-relax.toml and policy.d/30-conflict.toml
```

Multiple entries for the same target WITHIN one file are unaffected —
that's existing, single-file behavior (sequential override chaining,
e.g. `replace` then `relax` on the same rule; first-entry-wins table
lookup), unchanged by this rule. This includes two regex-table rows
sharing the same `id` inside ONE file: not a lint error (id uniqueness is
only checked cross-file, per the table above, and per the rule row's own
`id` field note), and — because `[[override]]` matches by id alone,
across every entry that carries it — an override targeting that id
applies to BOTH rows, in the same file or not. Stated as the batch
semantics it is, not a bug: `[[override]]` never resolves to "exactly
one" row, only to "every row currently carrying this id".

## Provenance: which file a rule came from

`bouncer rules list` names the source file for every overlay-provenance
line — an addition, an override, or a relaxation — in a trailing
`[filename]`:

```
override disable curl-file-upload — our CI legitimately uploads build artifacts via curl in every deploy [policy.d/20-relax.toml]
overlay-relax command.git.safe_subcommands push — our CI force-pushes to a scratch branch and the confirm prompt blocks the pipeline [policy.d/10-npm.toml]
rule command.bash block-npm-publish overlay [policy.d/10-npm.toml]
```

A `baseline`-provenance line has no file to name (the embedded baseline
has no file on disk) and carries no suffix.

---
Source: src/policy/schema.ts, src/policy/load.ts, src/policy/lint.ts, src/policy/baseline.ts, policy/command.toml, policy/secret.toml, policy/mcp-write.toml, policy/write-secret.toml, policy/prompt.toml, src/adapter/policy.ts, src/adapter/log-path.ts
