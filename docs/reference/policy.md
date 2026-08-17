# Policy format reference

The policy is TOML, in two layers.

## Baseline vs. overlay

**Baseline** — `policy/baseline.toml` in this repository, compiled into
the binary at build time (`bun build --compile`). Always present, never
edited at runtime. The vetted starting point.

**Overlay** — `<configDir>/bouncer/policy.toml`, read from disk on every
`bouncer run`/`check`/`rules`/`doctor`/`audit` invocation (no caching, no
restart needed after an edit). `<configDir>` is `~/.claude` unless the
`CLAUDE_CONFIG_DIR` environment variable is set, in which case it's that
value (`~` expanded, trailing slash normalized). Absent overlay = baseline
only, silently — a fresh account with no overlay file is a normal,
healthy state, not a warning.

The effective policy `bouncer` actually runs on is baseline merged with
overlay, per-table (see § Merge order below), plus `[[override]]` and
`[[relax]]` applied on top.

## The rule row: `{id, regex, reason, flags?, except?, special?}`

Every entry in the five regex tables below shares this shape:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique within its table (not enforced by lint — a shared id makes an `[[override]]` targeting either entry apply to both). |
| `regex` | string | yes | Must compile and stay inside the RE2-like dialect (§ below). |
| `reason` | string | yes | Shown in `bouncer check`/`rules list` output and in the degraded Claude Code verdict text. |
| `flags` | string | no | Regex flags — `i`, `m`, `s` only (§ below). |
| `except` | string | no | A second regex; if it ALSO matches, the rule does not fire (e.g. `.env.example`/`.env.test` excepted from the `.env` block). |
| `special` | string | no | An engine-recognized marker for logic no regex alone expresses. Today only `"git_remote_url"`, on the `secret.bash` entry that also needs the structural git parser to distinguish a config read from a write. |

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
`max_positionals`) too many non-flag arguments are given:

```toml
[[rules.command.git.ask_flags]]
sub = "branch"
flags = ["-d", "-D", "--delete", "-m", "-M", "--move", "-f", "--force"]
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `flags` | string[] | yes |
| `max_positionals` | number | no |
| `reason` | string | conditional — see § [[relax]] below |

**`safe_first_arg`** — safety hinges on the first non-flag argument:

```toml
[[rules.command.git.safe_first_arg]]
sub = "stash"
values = ["drop", "clear"]
invert = true
safe_when_absent = true
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `values` | string[] | yes |
| `invert` | boolean | no, default `false` (`true`: `values` names the UNSAFE first args, e.g. `stash`'s `drop`/`clear`) |
| `safe_when_absent` | boolean | yes |
| `reason` | string | conditional — see § [[relax]] below |

**`safe_grammar`** — safe only if the arguments match one exact token
sequence (`"*"` matches any single non-flag token):

```toml
[[rules.command.git.safe_grammar]]
sub = "pull"
sequences = [["--ff-only"]]
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
with one of these prefixes; anything else asks for confirmation.

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

Any failure anywhere in the overlay — invalid TOML, a wrong-shaped
table, a lint-failing regex, an unresolvable or reason-less
`[[override]]`/`[[relax]]`, a malformed declarative git-conditional
entry — rejects the **whole** overlay, not just the broken part. The
embedded baseline stays fully active, and the rejection is a loud
warning: in the audit log (`kind: "policy-warning"`, see
`docs/reference/audit-log.md`), in `bouncer rules lint`'s exit code, and
in `bouncer doctor`'s `policy` check. Never partial application, never a
silent fallback.

## Merge order

Two different orders, by table shape:

- **The five regex tables, `rm_rf.dangerous_targets`,
  `privilege_escalation.commands`** — baseline first, overlay entries
  appended after. An overlay addition can only ever add, never shadow a
  baseline entry by position.
- **`ask_flags` / `safe_first_arg` / `safe_grammar`** — overlay entries
  come first. Every consumer looks a `sub` up by `Array.find()`, so an
  overlay entry for an already-governed `sub` wins over the baseline
  one — this asymmetry is what makes such an entry a substitution
  (§ `[[relax]]` above), not a plain addition.

---
Source: src/policy/schema.ts, src/policy/load.ts, src/policy/lint.ts, src/policy/baseline.ts, policy/baseline.toml, src/adapter/policy.ts, src/adapter/log-path.ts
