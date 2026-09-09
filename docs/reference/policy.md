# Policy format reference

The policy is TOML, in three layers.

## Baseline vs. overlay

**Baseline** — twelve files in this repository, one per rule family plus
one per baseline harness declaration, compiled into the binary at build
time (`bun build --compile`): `policy/command.toml`, `policy/secret.toml`,
`policy/mcp-write.toml`, `policy/write-secret.toml`,
`policy/protected-write.toml`, `policy/prompt.toml`, and
`policy/harness/claude-code.toml`, `codex.toml`, `opencode.toml`,
`pi-agent.toml`, `gemini-cli.toml`, `cursor.toml` (ADR-0006 § 2 — one file
per assistant, the file name IS the id). Each rule file's top-level TOML
header (`[[rules.command.bash]]`, `[rules.secret...]`, ...) scopes it to
its family; `[[harness]]` is top-level in its own file. The rule families
merge shallowly, then harness declarations derive protected-write rows.
Always present, never edited at runtime. The vetted starting point.

**Overlay** — two named layers on top of the baseline (ADR-0001), each a
SET of files with the same shape, read from disk on every `bouncer
run`/`check`/`rules`/`doctor`/`audit` invocation (no caching, no restart
needed after an edit):

1. **common** — `~/.agents/bouncer/`, a harness-neutral product
   convention: no file anywhere names this root, and every harness's
   pipeline reads the same one.
2. **profile** — `<configDir>/bouncer/`, resolved by the TARGET
   harness's own declaration (ADR-0006 § 8: the first of its `env`
   names that's actually set, falling back to its `witness`) — for
   Claude Code (the default): `<configDir>` is `~/.claude` unless the
   `CLAUDE_CONFIG_DIR` environment variable is set, in which case it's
   that value (`~` expanded, trailing slash normalized). `--harness
   codex` resolves against `CODEX_HOME`/`~/.codex` instead, its OWN
   separate profile layer.

Both layers have the identical internal shape:

1. `<root>/policy.toml` — the single overlay file, if present.
2. `<root>/policy.d/*.toml` — every `.toml` file in that directory, in
   lexicographic FILENAME order (not write time), merged after
   `policy.toml`. A conf.d-style split for personal rules by theme
   (`10-npm.toml`, `20-client-x.toml`, ...).
3. `<root>/harness.d/*.toml` (ADR-0006 § 2) — every `.toml` file in that
   directory, same lexicographic order, each holding one `[[harness]]`
   block that declares a NEW harness or extends an existing one (§
   `[[harness]]` below). Discovery only — resolving a NEW harness's OWN
   profile root needs its declaration first, so a brand-new harness must
   be introduced through the COMMON layer (harness-neutral, no
   chicken-and-egg); the profile layer can still extend it afterward.

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

Every entry in the six regex tables below shares this shape:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique across every effective row in ALL SIX tables combined (ids resolve globally, not per-table). Lint rejects a duplicate from the same file, different files, either overlay layer, derived harness rows, or the embedded baseline. Use `[[override]]` (§ below) to change a baseline row instead of adding a same-id row. |
| `regex` | string | yes | Must compile and stay inside the RE2-like dialect (§ below). |
| `reason` | string | yes | Shown in `bouncer check`/`rules list` output and in the degraded Claude Code verdict text. |
| `flags` | string | no | Regex flags — `i`, `m`, `s` only (§ below). |
| `except` | string | no | A second regex; if it ALSO matches, the rule does not fire (e.g. `.env.example`/`.env.test` excepted from the `.env` block). |
| `special` | string | no | An engine-recognized structural matcher. A matcher receives the effective row: `git_remote_url` owns its read/write predicate; `docker_destructive` applies the row's `regex`, `flags`, and `except` to executable Docker candidates. The row's configured verdict and every override remain authoritative. |
| `verdict` | `"block"` \| `"confirm"` \| `"observe"` | no | A per-row static override of the family's default verdict (e.g. every `secret.path` row defaults to `"block"`; `transcript-backup` sets `verdict = "confirm"`). Lint-validated against the same three kinds `[[override]]`'s `action = "relax"` can name. A live `[[override]]` relax still wins over this field when both apply — this is the row's own static default, not the loudest word on the subject. |

## The six regex tables

| Table | Family | Guards |
|---|---|---|
| `rules.command.bash` | command | destructive/exfiltration/escalation shell patterns; proxy execution through file finders, pipeline executors, and preprocessors |
| `rules.secret.path` | secret | file paths that read as secret-bearing |
| `rules.secret.bash` | secret | shell commands that reveal plaintext (sops/age decryption, git config, embedded URL credentials); see [Override a baseline rule](../how-to/override-a-baseline-rule.md) to relax a baseline row |
| `rules.write_secret` | write-secret | text about to be written that matches a known secret token shape |
| `rules.protected_write` | protected-write | paths whose mutation changes harness behavior, persistence, or shell startup |
| `rules.prompt` | prompt | submitted prompts matching a prompt-injection signature |

The command baseline also confirms outbound `publish` actions (package registries, Docker image pushes including Compose, and `gh`/`glab` release creation, upload, or withdrawal) and `forge-api-write` actions (a mutating HTTP verb or body-field flag on `gh api`/`glab api`). `forge-api-write` deliberately confirms `gh api graphql -f query=...` reads: flag-only matching cannot distinguish their query body from a mutation. `base64-decode-exec` blocks Base64, `xxd -r`, or `openssl enc -d` output piped directly into a shell or interpreter.

The secret baseline names `keychain-dump` for macOS Security commands that
print passwords or private keys; its enumerated `find-generic-password`
metadata-only form stays allow only as a standalone command. Chained, piped,
or redirected forms fall back to the block, and `find-internet-password`
remains blocked. `credential-printer`, `shell-history`, and
`session-transcripts` confirm before exposing a live credential, a shell history
file (including Fish's XDG `fish_history`), or a live Claude Code transcript; the
`dotenv` row also covers direnv's `.envrc`.
`session-transcripts` targets only
`.claude[-profile]/projects/<slug>/<session>.jsonl` and immediate extension
copies such as `.jsonl.bak`, leaving memory notes available. A copy moved
outside `projects/` is intentionally outside the row: the directory is its
only reliable anchor. A transcript observer is a workstation-specific workflow,
so it can relax that row in its profile overlay with a reason; no such override
is part of the baseline.

`direnv-trust` confirms before trusting a project `.envrc` to run on later
directory changes. `persistence-scheduler` confirms before `crontab`, `at` or
`batch`, `launchctl` activation, or systemd activation or reload can start work
beyond the session.
When `direnv allow` names a guarded path such as `.envrc`, the secret family
judges that path first; its block verdict wins over `direnv-trust`'s confirm.


### Infrastructure mutation rows

The command table's `terraform-mutating`, `kubectl-mutating`, `helm-mutating`,
`docker-destructive`, and `sql-destructive-inline` rows return `confirm` before
infrastructure, cluster, release, Docker volume, or inline SQL mutations. They
do not infer whether a target is local or remote.

`kubectl-mutating` (`apply`/`create`), `helm-mutating` (`install`),
`docker-destructive`, and `sql-destructive-inline` are **Debatable (ticket
33)**. A profile can relax a row with `[[override]]`, `action = "relax"`,
`verdict = "observe"`, and a non-empty `reason = "local automation is reviewed
elsewhere"` without removing the baseline guard.


### Known limits

- A sops command hidden behind a package script or launched by direnv is not
  seen; production-decryption scripts remain human-run.
- Plaintext inherited from the agent's launch environment is outside this
  guard's scope.
- A non-default `SOPS_AGE_KEY_FILE` is a human choice and needs a personal
  overlay row.
- A command hidden inside a finder or pipeline executor's `sh -c` argument is
  not inspected; the guard does not parse shell command strings.
- `docker-destructive` recognizes literal Docker commands at command position,
  after shell control keywords, in `sh -c`/`eval`, nested active command
  substitutions, here-strings, remote and interpreter command strings, and a
  `cmux send` payload (including global cmux options and executable paths).
  A `cmux` payload has no reliable prose/code distinction, so the complete
  visible `cmux` source range is conservatively checked; malformed or
  fragmented payload tokens cannot discard a literal Docker operation.
  Variable-built commands and aliases remain outside literal recognition.
- `echo` and `printf` discard quoted Docker text only as an isolated display
  command: one shell segment and no unquoted operator, redirection, pipeline,
  heredoc, or compound command. Operators are recorded by the lexer while
  quote state is known, so a quoted redirection target is still active whereas
  a literal `>` inside display data is not. Every non-isolated input retains
  the complete original command as a conservative candidate; normalized
  executable candidates are additive.
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
- protected-write: a redirect embedded in a heredoc body is source text, not
  an executable write segment.
- protected-write: `sed -f` can name a script that writes a protected path,
  but the script's contents are not parsed.
- Harness declarations do not expand truncated globs (`~/.cla*` or
  `~/.claude/set*`), same-line assignments (`D=~/.claude; rm -rf
  $D/hooks`), nested braces, or brace ranges. A single pure comma-brace
  token such as `~/.{claude,codex}` is expanded; `~/.claude/*` confirms
  because its empty-name glob reading is the declared configuration
  directory.

Example row (from the baseline):

```toml
[[rules.command.bash]]
id = "dd-device-write"
regex = "\\bdd\\s+[^|;&\\n]*\\bof=\\/dev\\/"
reason = "dd writing to a block device (/dev/...) — likely disk wipe"
```

An overlay addition to any of these six tables is pure hardening: it
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

A token containing `*` or `?` is checked with every metacharacter read as `x`,
then with every metacharacter empty. The stricter matching path verdict wins.
Tokens without either metacharacter keep the literal scan unchanged.

The parser shares the command guard's structural tokenizer and wrapper-prefix
handling; see the header of `src/command-rules.ts`. Pattern files and
file-targeting values (`-f`/`--file`, `-g`/`--glob`/`--iglob`, `--pre`) remain
scanned. An unknown tool, option, argument form, unterminated heredoc, or
unterminated quote retains the full scan.


### Protected-write paths and Bash target extraction

`rules.protected_write` defaults to `confirm` and applies only to native
`Write`, `Edit`, `MultiEdit`, and `NotebookEdit` calls. `Read`, `Grep`, and
`Glob` stay silent even when their path matches. Every native or Bash target is
checked as both its raw spelling and its canonicalized path after symlink
resolution. The stricter verdict wins, so an innocent symlink name cannot hide
a protected destination and a protected raw mount path remains guarded when its
target has an unrelated name.

For Bash, the engine extracts known mutation targets structurally before it
falls back to path-like tokens under an unrecognized command head:

- redirects (`>`, `>>`, `>|`, `&>`, `&>>`, and numbered forms), every
  non-option `tee` argument, the final non-option operand of
  `cp`/`install`/`rsync`/`ln`, and every non-option operand of
  `mv`/`rm`/`unlink`/`shred`/`truncate`/`touch`/`chmod`/`chown`/`chattr`/`patch`;
- writer-specific option arguments, including `-t`/`--target-directory` for
  `cp`/`install`/`ln`/`mv`, in-place `sed` and `perl` operands, and `dd`
  operands written as `of=...`;
- positional destinations of `cp`/`install`/`ln`/`mv`/`rsync` are checked as
  both the literal destination and `<destination>/<basename(source)>` for each
  source, without a trailing-slash heuristic. This conservatively treats
  `cp ~/.zshrc /tmp/` as a write to `/tmp/.zshrc`.
- `sed` expressions that name a path, even without `-i`; `sed -f` remains a
  documented limit because its script contents are not available.

A target token carrying `*` or `?` uses the same two glob readings as the
secret scan before raw and canonical path checks: `rm ~/.claude/settings*.json`
confirms, while `rm ~/.claude/settings.json.bak` does not.

The fallback is deliberately not a shell evaluator. Exact read-only heads
(`cat`, `less`, `more`, `head`, `tail`, `grep`, `rg`, `ag`, `diff`, `cmp`,
`jq`, `stat`, `wc`, `file`, `bat`, checksum tools, `ls`, `find`, `fd`,
`tree`, `cd`, `pushd`, `test`, `[`, `source`, `.`, `echo`, `printf`, and
`bouncer`) stay free. Git subcommands that do not write their named path
arguments (`diff`, `show`, `log`, `blame`, `status`, `ls-files`, `cat-file`,
`grep`, `commit`, `add`, `push`, `fetch`, `rev-parse`, `branch`, `tag`, and
`remote`) also stay free. `checkout` and `restore` still confirm.

Search-pattern masking is opt-in only for `grep`/`egrep`/`fgrep`, `rg`, `ag`,
and `ack`; a head that can write through its pattern argument is never opted
in. Path-bearing quoted strings and shell command strings under an unknown
head therefore reach the conservative fallback. See [Known limits](#known-limits)
for heredoc and `sed -f` boundaries.

## `[[harness]]`: assistant configuration declarations

`[[harness]]` is a top-level table, outside `[rules]`, ONE PER FILE
(ADR-0006 § 2 — `policy/harness/<id>.toml`; the file name is the id).
It records the configuration-directory convention of one assistant; the
loader derives the protected-write regex rows from that record before it
appends the hand-written `rules.protected_write` rows. It may also carry
a `[harness.protocol]` sub-table (§ below) — the pipeline a generic
adapter reads to speak that assistant's own hook protocol.

```toml
[[harness]]
id = "claude-code"
dir = ["(^|/)\\.claude"]
witness = "~/.claude"
env = ["CLAUDE_CONFIG_DIR"]
reason = "Claude Code configuration directory"

[[harness.persistent]]
id = "harness-hooks"
path = "hooks(/|$)"
reason = "Claude Code hooks can alter future tool-call enforcement"
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Stable declaration id, matching the baseline file's own name. It produces `<id>-config-dir`. |
| `dir` | string[] | yes for a baseline or new overlay declaration | RE2-like regex fragments for configuration directories, with no trailing slash. |
| `witness` | string | no | Concrete path for `dir[0]`. Lint requires it to match `dir[0]`; if omitted, a narrow derived fallback must also match or lint instructs the author to declare it. |
| `parents` | string[] | no | Directories whose deletion removes a configuration directory. They derive only the directory row. |
| `env` | string[] | yes for a baseline or new declaration; `[]` is valid | Upper-case environment names that represent the first `dir`. Also what routes the profile overlay layer and the audit log (ADR-0006 § 8) — the first name actually set in the environment, falling back to `witness`. |
| `reason` | string | yes for a baseline or new declaration | Explanation shown for the derived directory row. |
| `persistent` | `[[harness.persistent]]` | no | Persistent paths below every `dir`. Each entry has unique `id`, `path`, and consequence-oriented `reason`. |
| `protocol` | `[harness.protocol]` | no | The pipeline a generic adapter reads to speak this harness's own hook protocol (§ below). Absent means `--harness <id>` fails closed (exit 2) — declared-but-unusable, same as undeclared. |

The effective declaration creates one `<id>-config-dir` row matching every
`dir` and `parents` fragment with `/?$`, then one row per `persistent`
entry matching every `dir` plus its `path`. The row ids are part of the
normal protected-write namespace. `bouncer rules list` marks each derived
row with `[harness:<id>]`; `doctor` includes them in the effective rule
count.

In Bash, `$NAME` and `${NAME}` expand only when `NAME` is declared in
some effective `env` array and the token is unquoted or double-quoted.
Single-quoted and escaped environment syntax stays literal. The token is
replaced with that declaration's validated `witness`, then normal target
extraction and matching continue. An undeclared `$CONFIG/hooks` remains
literal. The tokenizer also expands one non-nested comma brace expression
only when unquoted and unescaped, so `~/.{claude,codex}` yields both path
candidates. It expands at most 64 alternatives per token; a larger
expression does not touch the filesystem and returns a conservative
confirmation with `brace expansion exceeds the cap`.

An overlay block with an existing `id` appends `dir`, `parents`, and `env`
to the baseline declaration and inherits its `reason` and persistent
entries, and MAY replace its `protocol` wholesale (§ below — never
merged field by field). It must not declare `persistent`; that prevents
a profile from silently dropping or changing a baseline persistence
boundary. A new `id` supplies `dir`, `env`, and `reason` itself (or, for
a protocol-only extension of an existing id, `protocol` alone satisfies
the "must append something" check) and may add persistent entries and a
full `protocol`. Invalid fragments, an unverified witness, lower-case
environment names, repeated declaration ids in one layer, or any
duplicate effective rule id reject the containing layer, so the baseline
remains active.

Directory rows protect only the directory token. They deliberately do not
protect children such as `agents/`, `agent/`, `commands/`, `skills/`,
`projects/**/memory/`, logs, caches, or sessions: those locations are
written regularly and are not session-start persistence. pi-agent's
`extensions/` is explicit persistent state because it loads at boot.

### `[harness.protocol]`: the pipeline a generic adapter reads (ADR-0006)

Since ticket 15a, `src/adapter/` names no harness, tool, or field —
`policy/harness/claude-code.toml` is the first (and, in this ticket, only)
declaration carrying one, and it reproduces the pre-15a hardcoded Claude
Code adapter byte for byte (`fixtures/protocol/claude-code.json`,
`tests/fixtures-protocol.test.ts`). A harness declared WITHOUT a
`protocol` behaves exactly as before ADR-0006 (its `[[harness]]` block
still protects its directory); `--harness <id>` naming it fails closed
(exit 2, `docs/reference/cli.md`'s `run`).

```toml
[harness.protocol]
transport = "stdin-json"
wiring = "hook-file"

[harness.protocol.input]
event = "hook_event_name"
tool = "tool_name"
input = "tool_input"
session = "session_id"
prompt = "prompt"
cwd = "cwd"

[harness.protocol.events]
pre_tool = "PreToolUse"
prompt = "UserPromptSubmit"
session_start = "SessionStart"

[harness.protocol.tools]
Bash = { role = "command", command = "command" }
Read = { role = "read", path = "file_path" }
"mcp__*" = { role = "mcp" }

[harness.protocol.output]
block = "deny"
confirm = "ask"
observe = "silent"
flag = "context"
on_malformed = "allow"
ask_probe = "2026-08-16, workstation THREAT_MODEL §1: ..."

[harness.protocol.output.deny]
stdout = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":${reason}}}'
```

**`transport`** — the codec that reads the envelope. `"stdin-json"` (the
only one this ticket declares): one JSON object on stdin, no framing.

**`wiring`** — the codec `doctor` uses to prove the hook is actually
installed. `"hook-file"` (generic): reads `<configDir>/settings.json`,
checks each of `events.pre_tool`/`prompt`/`session_start` names a command
whose executable basename is `bouncer`, whose args contain `run` and —
for any harness other than `claude-code` — also `--harness <id>` (a bare
`bouncer run` under a non-default harness would silently judge against
claude-code's table instead). `"codex-hooks"` (ticket 15b): the same
checks, applied to Codex's own two additive sources plus a hash-trust
ledger. `"shim-file"` (ticket 15c, ADR-0006 § 7): an IN-PROCESS harness
(pi-agent, omp) has no settings file and no per-event matcher at all —
checks that `<configDir>/extensions/bouncer.ts` exists and is
byte-identical to what `bouncer harness shim <id>` prints today
(`wiring:shim`) and that the shim's own baked `BOUNCER` path resolves to
an executable (`wiring:binary`); no canary concept (the shim already
fails closed on its own liveness). Optional: a harness declared without
one gets `wiring: not checkable (declared harness)` in `doctor`, visible
rather than silently green.

**`[harness.protocol.input]`** — where things a hook invocation needs
live in the raw envelope object, as top-level dotted keys: `event` (the
field naming which hook event this is), `tool` (the tool name), `input`
(the tool's own input bag), `session` (session id, logging only),
`prompt` (UserPromptSubmit's text — OPTIONAL, required iff
`events.prompt` is declared, § below), `cwd` (the session's working
directory — used to resolve a RELATIVE `path` selector below; Claude
Code sends absolute paths and no `cwd`, so this is a no-op for it —
ALWAYS required, relative-path resolution needs it regardless of which
events a harness declares), `permission` (review round 1 P-4 — OPTIONAL,
no coherence rule gates it: when declared, its value is attached to
every logged verdict entry for that call, `docs/reference/audit-log.md`'s
own `permission` field; logging only, never read for a decision anywhere
in this codebase — codex.toml declares `permission = "permission_mode"`,
claude-code.toml declares none).

**`[harness.protocol.events]`** — the literal event-name strings `event`
takes for each event this pipeline understands. `pre_tool` is always
required. `prompt` and `session_start` are OPTIONAL (review round 2
R2-1) — a harness that never judges a submitted prompt (or has no
doctor-facing SessionStart surface, ADR-0006 § 7's pi-agent by design)
declares neither, rather than being forced to name an event field it has
no real envelope shape for. See "Optional surfaces" below for the
coherence rules gating each.

**`[harness.protocol.tools]`** — name → `{role, ...selectors}`. A name is
an exact tool name or a trailing-`*` glob (`"mcp__*"`); exact rows win
over glob rows regardless of table order. A name matching no row is not
judged (same as before this ticket). `role` is the engine's whole
vocabulary of a tool call:

| Role | Families it reaches | Selectors it reads |
|---|---|---|
| `command` | command, secret (as a Bash-shaped string), protected-write (`checkBashWrites`, shell-syntax aware) | `command` (a string, or `field[].subfield` for a batch of them) |
| `read` | secret only | `path` (canonicalised after resolving against `cwd`), `pattern` (matched LITERALLY, never canonicalised — Glob's own field) |
| `write` | secret AND protected-write on `path`; write-secret on `text` | `path`, `text` (a string, or `field[].subfield` joined with `\n`) |
| `fetch` | secret (URL-shaped) | `url` (single), `urls` (`field[].subfield`, appended after `url`) |
| `mcp` | mcp-write, judged on the tool's own name | none — the row itself carries no selector |

A selector is a dotted path into the input bag; `field[].subfield` maps
over an array at `field`, reading `subfield` off each object element (a
STRING element is taken as the value directly, skipping `subfield` —
`ctx_batch_execute`'s `commands[].command` mixes both shapes in one
call). A selector resolving to a non-string value logs `expected string
for tool_input.<selector>, got <type> — allowing` on stderr and yields no
value for that call — the exact diagnostic the pre-15a hardcoded readers
used, now general to any selector string. `path` is resolved against
`cwd` (when the harness's envelope sends one) BEFORE canonicalisation, so
a relative reference (Codex's own `apply_patch` paths, relative to the
session directory) still names a real file.

**Role `read`'s `path` selector is judged as a CANDIDATE SET, not the raw
value alone (ticket 15c review round 1 L-1)** — `src/adapter/neutral-
call.ts`'s `expandPathCandidates`, harness-neutral (every `role="read"`
row, on every harness, not a pi-agent-only rule): the raw value; each
`;`-split segment, trimmed; and, for the raw value and every segment,
every progressive strip of a trailing `:<segment>` (`a:b:c` → `a:b`,
then `a`) — deduplicated, ALL judged, cwd-joined identically to a plain
single value. `db.sqlite:table` (`tests/adapter-neutral-call.test.ts`'s
own literal row selector convention) yields the bare `db.sqlite` too,
harmless; `archive.zip:inner/.env` yields the bare `archive.zip`. A
superset of candidates can only ADD verdicts across the family checkers
that already loop `paths` — fail-closed by construction, no new selector
grammar needed. Found live: a trailing `:N-M` selector suffix or a
`;`-joined list, both riding unstripped inside the raw `path` string,
defeated every `$`-anchored path rule (`~/.zsh_history:1-5`,
`proj/secrets.pem:1-2`, `proj/.envrc; proj/README.md` all read `allow`
before this fix) — because Claude Code's own `Read`/`Grep` rows are also
`role="read"`, this is a Claude Code behavior CHANGE, not a pi-agent-only
fix (ADR-0006's own Consequences and History document it, ticket 15c
review round 2 C-3): two selector-suffixed/`;`-joined cases now judge in
`fixtures/protocol/claude-code.json`, captured from source since the
installed binary predates the fix; every other vector stays byte-
identical to the installed binary.

**`codec` (ADR-0006 § 6, tickets 15b/15c)** — a tool row may name a
`codec` INSTEAD of selectors: the row's role still applies, but the named
codec parses the raw input bag itself and returns the same `{paths,
text}` (role `write`) shape selectors would have produced, cwd-joined
identically. `rules lint` rejects a row combining `codec` with any
selector key (naming the collision) and an unknown `codec` name. Two
codecs today: `apply-patch` (`src/adapter/codecs/input/apply-patch.ts`):
parses Codex's `*** Begin Patch` … `*** End Patch` grammar (`*** Add
File:`, `*** Update File:` with an optional `*** Move to:`, `*** Delete
File:`) into every path it writes (a move writes BOTH ends — the row's
`paths` is genuinely plural for exactly this reason, unlike a
selector-derived row's single entry) and `text` = every `+` hunk line of
an Add/Update section, joined by `\n`. A patch missing its FRAME (`***
Begin Patch`/`*** End Patch`) yields no paths and no text (not judged at
all — nothing to partially trust when the grammar's own envelope was
never established); a patch WITH a valid frame whose BODY hits a line
matching no recognized directive/hunk shape (review round 1 S-9) keeps
every path and `+` text line already parsed before that line — judged on
what was seen, not discarded over one bad trailing line. `hashline`
(`src/adapter/codecs/input/hashline.ts`, ticket 15c): pi-agent/omp's
`edit` tool takes one patch string with `[PATH#TAG]` section headers and
`+` body rows (never `-`/context/`CUT` rows — hashline's own grammar has
no such thing) instead of discrete `path`/`text` fields; every header's
path is written (plural, same reasoning as a move), `text` = every `+`
row across every section joined by `\n`. A payload with no recognized
`[PATH#TAG]` header anywhere is not judged at all. Either codec logs one
stderr line naming a failure, the same "no value" contract a non-string
selector field already has.

**`[harness.protocol.output]`** — the abstract verdict → action table.
Every action is one of `deny`, `ask`, `context`, `silent`. `rules lint`
rejects the containing block AS A UNIT on any of:

1. `block` mapped to anything but `"deny"`.
2. `confirm` mapped to anything but `"deny"` or `"ask"`.
3. `observe` mapped to anything but `"silent"`.
4. `flag` mapped to anything but `"context"` or `"silent"`.
5. `ask_probe` missing or empty when `confirm = "ask"` — lint cannot
   verify a harness actually honours `ask`, so it forces the author to
   write down, in the same spirit as a rule's own `reason`, the measured
   evidence they believe it does.
6. An overlay relaxing an EXISTING BASELINE harness's `confirm` from
   `"deny"` to `"ask"` — a baseline `"deny"` is a measured fact (Codex's
   own, ADR-0006 § 4 rule 6, fact 3 — `permissionDecision: "ask"` is
   fail-open there, so relaxing back to `ask` would let every `confirm`
   verdict through unjudged), never a default an overlay gets to loosen.
   An overlay-declared harness (not itself baseline) carries no such
   fact and may freely replace its own protocol.
7. An unknown `transport` or `wiring`, or a tool row's `role` — plus, for
   a tool row, any field lint does not recognize at all, an unknown
   `codec` name, or a `codec` combined with any selector key (named:
   which selector collided).

`on_malformed` (`"allow"` or `"deny"`) governs exactly one case: stdin
`run()` could not read or parse at all — empty, or not valid JSON.
A WELL-FORMED envelope naming an event this binary does not judge
(`PostToolUse`, a missing `hook_event_name`) is a SEPARATE case and
always stays silent regardless of `on_malformed` — it is not malformed,
it is simply not ours to act on. `"allow"` is Claude Code's own fail-
open-on-bad-envelope contract, kept explicit per harness — Claude Code's
stays `"allow"`, silent, nothing logged. `"deny"` renders that harness's
OWN `deny` template — the same template a real blocked tool call would
get — with `${reason}` = `envelope-malformed: unreadable or malformed
hook envelope — failing closed` (`${rule}` = `envelope-malformed`), exit
0, and writes a `policy-warning` entry to the audit log (this harness
always has a resolvable log path by the time this case is reached — the
ADR-0006 § 6 exit-2 check for an unusable harness runs first). Every
other baseline harness decides which value it wants in its own test
phase.

**Optional surfaces: `prompt` and `session_start` (review round 2 R2-1)**
— `input.prompt`/`events.prompt` and `events.session_start`/
`output.session_start` are pairs that must agree; `output.ask`/`confirm`
and `output.context`/`flag` likewise. `rules lint` rejects the block AS A
UNIT on any of:

8. `events.prompt` declared without `input.prompt` — nothing would ever
   read the prompt text.
9. `events.prompt` NOT declared while `output.flag` is anything but
   `"silent"` — this harness never judges a prompt, so `flag` cannot
   degrade to a `"context"` it can never build.
10. `output.ask` present in the raw table while `confirm` is not
    `"ask"` — a dead template, never rendered.
11. `output.context` present while `flag` is not `"context"` — a dead
    template, never rendered.
12. `events.session_start` declared without a matching
    `[harness.protocol.output.session_start]` table.
13. `output.session_start` present while `events.session_start` is NOT
    declared — a dead template: `doctor`'s SessionStart announcement for
    this harness has no event to reach it through.

A minimal declaration — `pre_tool` + `deny` only, no `prompt`/
`session_start` at all — is a complete, lint-clean, usable protocol
(the how-to page's `harness.d/acme.toml` example is exactly this shape).
`input.cwd` and `output.deny` are the two fields with no optional path:
every declared harness needs both, unconditionally.

**`[harness.protocol.output.<action>]`** — one template table per action
the output table actually maps a verdict to (never `silent`, which
renders nothing), plus `session_start` when `events.session_start` is
declared (SessionStart's own doctor announcement, rendered through this
same mechanism but never reached via the verdict table). Each sets
`stdout` (a string), `exit` (an integer process exit code), or both —
Claude Code's four templates only ever set `stdout`. Placeholders are
JSON-encoded ON SUBSTITUTION (so an arbitrary reason/context string with
quotes or newlines never breaks the surrounding JSON literal) — write
them BARE, `${reason}` never `"${reason}"`: the value already carries
its own quotes once substituted, so a hand-written quote around the
placeholder doubles up and produces invalid JSON. `rules lint` rejects a
`stdout` where a placeholder directly touches a `"`, and separately
renders every template once with a worst-case probe value and requires
the result to still parse as JSON when `stdout` looks like a JSON object
or array literal — both belts reject the containing action's block as a
unit, the same as any other rule 1–13 failure.

**Placeholders — a fixed, PER-TEMPLATE set (review round 2 C-1)**: `run.ts`
fills exactly these names and no others, so lint rejects any placeholder
outside a template's own allowed set (naming the unknown placeholder and
listing what IS allowed there) — a name lint let through but the renderer
never fills would render as a literal, unsubstituted `${…}` string
forever, silently invalid JSON:

| Template | Allowed placeholders |
|---|---|
| `deny` | `${reason}` (`<ruleId>: <reason>`), `${rule}` (the bare ruleId), `${verdict}` (`block`/`confirm` — the abstract verdict before degradation) |
| `ask` | same three as `deny` |
| `context` | `${context}` only (the assembled UserPromptSubmit hit-list prose) |
| `session_start` | `${context}` only (the assembled doctor announcement text) |

### Codecs: the code a declaration names by string

A declaration's `transport`/`wiring` strings, and a tool row's `codec`,
name modules in `src/adapter/codecs/` — the ONLY code that knows a
harness by name. Today: `stdin-json` (transport, `src/adapter/codecs/
stdin-json.ts`); `hook-file` (wiring, `src/adapter/codecs/wiring/hook-file.ts`,
ADR-0006 § 6, a JSON hook file whose events name a command containing
`bouncer run --harness <id>`), `codex-hooks` (wiring, `src/adapter/
codecs/wiring/codex-hooks.ts`, ticket 15b — the same generic checks,
applied to Codex's OWN two additive sources, `hooks.json` and
`config.toml`'s `[hooks]` table, plus its hash-trust ledger,
`config.toml`'s `[hooks.state]`), and `shim-file` (wiring, `src/adapter/
codecs/wiring/shim-file.ts`, ticket 15c — an in-process harness's own
printed extension, `wiring:shim` + `wiring:binary`, no settings shape and
no canary); `apply-patch` (input codec on a tool row, `src/adapter/
codecs/input/apply-patch.ts`, ticket 15b — Codex's `apply_patch` patch
grammar) and `hashline` (input codec, `src/adapter/codecs/input/
hashline.ts`, ticket 15c — pi-agent/omp's `edit` tool's own `[PATH#TAG]`
patch grammar). A new parser or a new wiring check is a codec pull
request; a new assistant that fits the existing codecs is a file.

### Known limits (ADR-0006 § Consequences)

- A declaration cannot express a parser — that is what a codec is for;
  pretending a field map can parse `apply_patch` text or a hashline diff
  would put a parser in TOML.
- `rules lint` proves the SHAPE of an output table (every verdict maps to
  a legal action, `ask` carries a probe) — it never proves the harness
  actually HONOURS `ask`, `deny`, or any of it; that is what `ask_probe`
  and a real test phase are for.
- A shim installed by copy (in-process harnesses — pi-agent built in
  ticket 15c, opencode not yet scheduled) is a file the user maintains
  themselves (`bouncer doctor --harness <id>` reminds them to reprint it
  after every binary upgrade); `doctor` for one can only report what the
  shim itself relays back — a shim that never runs at all (the extension
  failed to load, the harness never called it) looks identical to a
  perfectly healthy, silent tool call from `doctor`'s own vantage point.
- The `codex-hooks` trust check (ticket 15b) proves PRESENCE of a
  `[hooks.state]` record for every bouncer-pointing handler, never that
  its `trusted_hash` is CURRENT — the exact hashing rule Codex uses is
  undocumented and, as of this ticket, unconfirmed (see the 15b report);
  a stale hash that still happens to have SOME record reads as trusted
  here even though Codex itself would treat it as modified and skip it.
- pi-agent's own `confirm` mapping was `"deny"` pending a live probe of
  `ctx.ui.confirm` under both `pi` and `omp` (ticket 15c); confirmed live
  on both binaries 2026-09-08 (real dialog, decline blocks, accept runs)
  and flipped to `"ask"` — see `pi-agent.toml`'s own `ask_probe` field
  and the 15c report's probe table for both runs' evidence, including a
  first `omp` attempt that turned out to be a stale, reused session and
  was retracted before the flip.

## `mcp_write.allowed_tools`

Exact, case-sensitive MCP tool names that pass without confirmation. The
baseline list is empty. Each entry includes the server and operation,
for example `mcp__chrome-devtools__click`; it does not authorize
`mcp__other__click` or `mcp__chrome-devtools__click_extra`.

An overlay adds entries only through `[[relax]]`, with a mandatory reason:

```toml
[[relax]]
list = "mcp_write.allowed_tools"
value = "mcp__chrome-devtools__click"
reason = "Human-approved Chrome clicks, including application writes"
```

Values require nonempty server and operation components. Whitespace and
glob syntax are rejected; there is no prefix, wildcard, or regex matching.
A direct overlay addition to `[rules.mcp_write].allowed_tools` rejects
the containing layer.

Exact permissions are checked before `read_prefixes`. They authorize all
arguments of the named tool, including mutating operations, not just reads.
Put them in a profile overlay to keep the permission out of other profiles.
Unlisted tools retain the existing read-prefix/default-ask behavior.
`bouncer audit --suggest` uses this list for MCP candidates.

## `mcp_write.read_prefixes`

A plain string list, shared across MCP servers. Unless an exact
`allowed_tools` permission applies, a call passes silently when its operation
name (everything after the tool name's second `__`) starts with one of
these prefixes; anything else asks for confirmation. This is the
baseline table (`[rules.mcp_write]` directly) — an overlay can only
ADD to it through `[[relax]]` (§ below), never by writing this table
itself:

```toml
[rules.mcp_write]
read_prefixes = ["get", "list", "search", "fetch", "read", "query", "lookup", "describe", "view"]
allowed_tools = []
```

## `[[override]]`: disable, replace, or relax a regex-table rule

```toml
[[override]]
rule = "curl-file-upload"   # must resolve to an id in one of the six regex tables
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
`command.git.config_read_modes`, `mcp_write.read_prefixes`, or
`mcp_write.allowed_tools`. A direct addition to any of these lists via
the table itself is rejected outright.

```toml
[[relax]]
list = "command.git.safe_subcommands"   # one of the four lists above
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
- **The six regex tables, `rm_rf.dangerous_targets`,
  `privilege_escalation.commands`** — baseline first, then every overlay
  file's additions across both layers, in merge order (common's files,
  then profile's). An overlay addition can only ever add, never shadow a
  baseline entry by position — UNLESS a later layer's row shares the
  earlier layer's row's `id` (§ Precedence), in which case the earlier
  layer's row is dropped rather than both surviving side by side.
- **`[[harness]]` declarations** — baseline declarations start the set.
  Matching overlay ids append `dir`, `parents`, and `env`; new ids append
  whole declarations. Derived protected-write rows are rebuilt from that
  effective set before the handwritten protected-write rows.
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

- A regex-table row `id` (any of the six families).
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
- Two regex-table rows (any of the six families) sharing the same `id`
  anywhere in one effective policy — whether they came from one file,
  several files, the baseline, or derived harness rows. Ids resolve
  GLOBALLY, not per-family; the only same-id mechanism is
  `[[override]] action = "replace"` against its existing row.
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

Every effective regex-table id is unique. Repeating an id inside one file
is rejected just like a cross-file collision, before `[[override]]`
application. Sequential override chaining remains valid because several
`[[override]]` rows can target the one effective rule; two override
entries targeting the same rule in different files of one layer remain a
conflict as listed above. A baseline-id addition is likewise rejected
before merge; use `[[override]] action = "replace"` instead.

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

A baseline-derived row carries `[harness:<id>]` instead of a filename.
Other `baseline`-provenance lines have no suffix because the embedded
baseline has no file on disk to name.

---
Source: src/policy/schema.ts, src/policy/load.ts, src/policy/lint.ts, src/policy/baseline.ts, src/policy/harness.ts, src/protected-write-rules.ts, policy/command.toml, policy/secret.toml, policy/mcp-write.toml, policy/write-secret.toml, policy/protected-write.toml, policy/prompt.toml, policy/harness/claude-code.toml, policy/harness/codex.toml, policy/harness/opencode.toml, policy/harness/pi-agent.toml, policy/harness/pi-agent.shim.ts, policy/harness/gemini-cli.toml, policy/harness/cursor.toml, src/adapter/policy.ts, src/adapter/log-path.ts, src/adapter/shim.ts, src/adapter/codecs/stdin-json.ts, src/adapter/codecs/wiring/hook-file.ts, src/adapter/codecs/input/apply-patch.ts, src/adapter/codecs/input/hashline.ts, src/adapter/codecs/wiring/codex-hooks.ts, src/adapter/codecs/wiring/shim-file.ts, src/adapter/codecs/wiring/registry.ts, src/adapter/neutral-call.ts, src/adapter/degrade.ts, src/adapter/render.ts
