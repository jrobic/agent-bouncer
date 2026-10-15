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
| `special` | string | no | An engine-recognized structural matcher. A matcher receives the effective row: `git_remote_url` owns its read/write predicate; `docker_destructive` applies the row's `regex`, `flags`, and `except` to executable Docker candidates; `env_value` (the `env-value` row of `rules.write_secret`) looks the text up against the hook process's environment and applies the row's `regex` and `except` as a gate on which texts it looks at (see [The env-value row](#the-env-value-row)). The row's configured verdict and every override remain authoritative. |
| `verdict` | `"block"` \| `"confirm"` \| `"observe"` | no | A per-row static override of the family's default verdict (e.g. every `secret.path` row defaults to `"block"`; `transcript-backup` sets `verdict = "confirm"`). Lint-validated against the same three kinds `[[override]]`'s `action = "relax"` can name. A live `[[override]]` relax still wins over this field when both apply — this is the row's own static default, not the loudest word on the subject. |

## The six regex tables

| Table | Family | Guards |
|---|---|---|
| `rules.command.bash` | command | destructive/exfiltration/escalation shell patterns; proxy execution through file finders, pipeline executors, and preprocessors |
| `rules.secret.path` | secret | file paths that read as secret-bearing |
| `rules.secret.bash` | secret | shell commands that reveal plaintext (sops/age decryption, git config, embedded URL credentials, credential printers) or print or reference the process environment (the [environment rows](#the-environment-rows)); see [Override a baseline rule](../how-to/override-a-baseline-rule.md) to relax a baseline row |
| `rules.write_secret` | write-secret | text about to be written that matches a known secret token shape, or that carries the value of a protected environment variable ([the env-value row](#the-env-value-row)) |
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

### The environment rows

The agent's own environment holds what its launcher exported (direnv, a
profile, a CI runner), so a command that prints it, or names one of its
secrets, puts the value in the transcript. Baseline rows in
`rules.secret.bash` (and one in `rules.secret.path`) refuse the three ways an
agent reads its environment. They are a **net, not a barrier**: Bouncer
judges command text and cannot remove a variable, and a test or a script the
agent launches inherits that environment and uses it on purpose. The
structural fix is the launcher's — keep the secrets out of the agent's
environment, behind an injection wrapper the agent cannot reach. Where that
exists these rows still catch the accidental read; where it does not they
are an incomplete guard (see [Known limits](#known-limits)).

**1. Dumps of the whole environment — `block`.**

| Row | Refuses |
|---|---|
| `env-dump` | at command position (also after `&&`, `;`, `\|` or a newline, inside `$(…)`, backticks and `sh -c`): `env` with nothing to run (`env`, `env -i`, `env -u NAME`, `env -0`, `env --`, `env FOO=1`); `printenv` with no name; `export` and `export -p`; `declare` / `typeset` with only `-x` / `-p` flags, or none; `set` alone; `compgen -e` and `compgen -A export`; `${!PREFIX@}` and `${!PREFIX*}` (the names of the matching variables) |
| `env-dump-ps` | `ps` at command position with the BSD `e` as its first operand (`ps e`, `ps eww`, `ps auxe`) or macOS `-E`; `docker compose ps postgres` and prose that says "ps output" are not `ps` |
| `env-dump-launchctl` | `launchctl getenv` (at command position) |
| `env-dump-jq` | jq's `env` and `$ENV` builtins (jq at command position) |
| `env-dump-docker` | `docker exec … env` or `printenv` with nothing after it; `docker compose config` as the compose subcommand — not with `-q` / `--quiet`, `--services`, `--volumes`, `--profiles`, `--images` or `--hash`, which print no environment (a positive list of printing flags: the dialect has no lookaround). `docker` at command position |
| `proc-environ` (`rules.secret.path`) | `/proc/<pid>/environ` — `self`, `thread-self`, a pid, `task/<tid>/environ`. The Read tool is covered, and Bash through the path scan (`bash-proc-environ`) |

"Command position" is one lead-in shared by `env-dump`, `env-dump-ps`,
`env-dump-launchctl`, `env-dump-jq` and `env-dump-docker`
(`{{command-position}}`, `src/policy/fragments.ts`): the start of the text;
after `;`, `&`, a newline, `{`, a backtick, `$(`, `<(` or `>(`; after a pipe
preceded by whitespace (`curl … | jq -n env` is a dump, `a|env|b` in a search
pattern is not a pipeline); after `then`, `do` and the like; inside `sh -c`;
behind the wrappers `VAR=value`, `rtk`, `command`, `exec`, `nice`, `time`,
`builtin`, `proxy` and `eval`. `ps`, `jq`, `docker` and `launchctl` may carry
a path (`/usr/bin/jq`). A search or a sentence that merely spells the command
— `grep 'launchctl getenv' docs`, a commit message that says `jq -n env`, a
trailing `# see docker exec c env` — is not the command.

Not matched: an `env` that runs a command (`env FOO=1 make test`),
`set -euo pipefail`, `set -x`, `export FOO=bar`, `declare -x FOO=bar`,
`printenv HOME`, `ps -ef`, `ps -e` and `ps aux` (they print no environment),
`git remote set-url`, `npm config set`, a jq `.env` field accessor, a
`{env: …}` object key and `env.NAME`. `docker inspect`
(`env-dump-docker-inspect`) is a **`confirm`**: it prints `Config.Env`, but
inspecting a container is everyday work.

**2. References to a protected variable name.** A name is protected when it
is uppercase and equals, or ends in `_` plus, one of `TOKEN`, `PASSWORD`,
`PASSWD`, `SECRET`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `ACCESS_KEY`,
`CREDENTIALS`. The suffix ends the name: `GITHUB_TOKEN`, `DB_PASSWORD`,
`STRIPE_API_KEY`, `AWS_SECRET_ACCESS_KEY` and `ANTHROPIC_API_KEY` match;
`NODE_ENV`, `HOME`, `PATH`, `TOKENIZER_PATH`, `MY_TOKEN_FILE`, `SECRET_KEY`,
`DB_PASS` and any lowercase name do not. There is no client-specific list and
no per-layer list: the definition is baseline, public and universal.

The definition is written once, in `src/protected-names.ts`
(`PROTECTED_NAME_SOURCE`, and `isProtectedName()` for code that holds a name
as a string). A baseline row that needs it writes `{{protected-name}}` in its
regex and the loader fills it in at load time, once — as it fills the git
`config_read_modes` list — so `bouncer rules list` shows the effective regex.
The long alternations the environment rows share are fragments of the same
kind (`src/policy/fragments.ts`): the reference forms (`{{env-reference}}`,
built from `{{env-object}}` and `{{env-call}}`), the command-position lead-in
(`{{command-position}}`, `{{shell-c}}`) and jq's builtin (`{{jq-lead}}`,
`{{jq-env}}`). A `{{name}}` that no fragment defines, or that survives the
fill, makes the baseline refuse to load (a typo would silently disable its
rule). An overlay row writes its own whole regex — layers add rows, never
data into a row — and lint rejects any `{{…}}` in an overlay (escape the
braces, `\{\{`, to match them literally). Anything else that has to recognise
a protected name imports the definition from there; a second copy would
drift.

The forms recognised: `$NAME` and `${NAME}` (shell); `process.env.NAME`,
`process.env["NAME"]`, `Bun.env.NAME`, `Deno.env.get("NAME")`;
`os.environ["NAME"]`, `os.environ.get("NAME")`, `os.getenv("NAME")`;
`ENV["NAME"]`, `ENV.fetch("NAME")`; awk's `ENVIRON["NAME"]`; `getenv("NAME")`,
`os.Getenv`, `env::var` (C family, PHP, Go, Rust); and, by the nature of the
command, `printenv … NAME`, `declare -p … NAME` and jq's `env.NAME` /
`$ENV.NAME`.

| Row | Verdict | When |
|---|---|---|
| `env-ref-display` | `block` | the reference feeds a display: `echo`, `printf`, `print`, `println`, `puts`, `pp`, `console.log` (also `info`, `warn`, `error`, `debug`) or `node` / `bun -p` earlier in the same statement (no `;`, `&`, `\|` or newline between; a `\`-newline continuation does not end the statement, and the scan reaches at most 400 characters ahead), or the form prints by nature (`printenv NAME`, …). `echo $NAME \| cmd` is a display too: the regex cannot follow the pipe |
| `env-ref-whole` | `block` | the environment object used as a whole — `process.env`, `Bun.env`, `Deno.env.toObject()`, `os.environ`, awk's `ENVIRON`, Ruby's `ENV` printed or enumerated (`p ENV`, `ENV.to_h`) — dumped, iterated, or spread into a child's environment |
| `env-ref-computed` | `block` | a name computed at runtime: `os.environ.get(<expr>)`, `process.env[<expr>]`, `ENV[<expr>]`, `getenv(<expr>)`, shell `${!name}`, `printenv $name`. A literal name is a closed string right after the bracket or parenthesis; anything else (a call, a variable, `'GITHUB_' + 'TOKEN'`) is computed, because a name rebuilt from pieces would slip past every name rule |
| `env-ref` | `confirm` | any other reference — `curl -H "Authorization: Bearer $GITHUB_TOKEN" …`, `export GH_TOKEN=$GITHUB_TOKEN`, a heredoc or a commit message that spells a protected name (prose is command text) |

A reference to a non-protected name stays allowed: `echo $HOME`,
`process.env.NODE_ENV`, `os.environ["HOME"]`. A **search pattern** is not an
access: `env-ref-whole` carries an `except` that lets `rg 'process.env' src`
and `grep -rn os.environ .` through, provided the whole command is a sequence
of searches (`rg`, `grep`, `git grep` / `log` / `diff` / `show`, …) and
harmless readers, `cd` and a literal `echo`, with no command substitution —
`rg 'process.env' src && node -p process.env` is still blocked. A fetched URL
that names `process.env` or `os.environ`, or ends in an `env` word, is not an
access either.

**3. `credential-printer` completed.** The one existing row (`confirm`) also
covers `gh` / `glab auth status -t`, `glab config get token`,
`git credential fill`, `docker-credential-* get`,
`npm` / `pnpm config get …_auth[Token]`, `aws configure get` of a secret key
or a session token, and `aws configure export-credentials`. It keeps its id:
an overlay that relaxed it keeps working.

**Order is behaviour.** The first matching row of a table wins, so every
block row sits before the confirm rows (`env-dump-docker-inspect`, `env-ref`,
`credential-printer`): a confirm placed first would hide a block later in the
same command. **Relaxing:** each row has its own id for `[[override]]`
([Override a baseline rule](../how-to/override-a-baseline-rule.md)), so a
workflow that inspects containers all day relaxes `env-dump-docker-inspect`
alone, and one that really needs `docker compose config` relaxes
`env-dump-docker`.

The operator-side steps are in
[Keep environment secrets away from agents](../how-to/keep-env-secrets-away-from-agents.md);
the reasons for a net rather than a barrier are in
[ADR-0007](../adr/0007-environment-secrets-baseline-net.md).

### The env-value row

The environment rows refuse the commands that print or name a protected
variable; they cannot see a script that prints one, an output that already
contains one, or a value the agent then writes into a file. The `env-value`
row of `rules.write_secret` closes that last half: **a `Write` / `Edit` whose
text carries the value of a protected environment variable is blocked**. It is
`write_secret` with the exact value instead of a regex, and it is a net, not a
barrier, like the rows above.

- **Where the value comes from.** The environment of the hook process: what
  the agent was launched with (Claude Code hands a hook its own environment;
  the pi-agent shim spawns Bouncer with no `env` option, so it inherits omp's).
  `bouncer run` takes its own process environment once per invocation and
  hands it to the dispatcher: the overlay-aware dispatcher and the baseline
  retry both read that record. No `.env`, `.envrc` or secret store is read.
- **Which variables.** Those whose name is protected — the same definition as
  the environment rows (`src/protected-names.ts`): an uppercase name equal to,
  or ending in `_` plus, `TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `API_KEY`,
  `APIKEY`, `PRIVATE_KEY`, `ACCESS_KEY` or `CREDENTIALS` — and whose value is
  **at least 8 characters** long. `HOME`, `NODE_ENV`, a lowercase name and a
  7-character value are not looked at.
- **Which text.** The text that `write_secret` already scans: `Write.content`,
  `Edit.new_string`, each `MultiEdit` `edits[].new_string`, the pi-agent
  `write` content and the added (`+`) rows of its `edit` (both the hashline
  string and pi's `edits[].newText`), and a Codex patch's added lines. Never
  `old_string` / `oldText`, never `NotebookEdit` (no text selector), never a
  command (Bash, `ctx_execute`), an MCP payload or a prompt.
- **Which forms.** The value is looked for as plain text, as base64 and as
  hex, by string search — never compiled into a regular expression. Exactly:
  - *plain*: the value itself;
  - *base64*: the value's UTF-8 bytes in the standard (`+/`) **and** URL-safe
    (`-_`) alphabets, padded or unpadded, at **any of the three alignments**
    the value can take inside a longer base64 stream (`base64(value)` alone
    would only match a value starting on a 3-byte boundary). The match leaves
    out the characters that share a 3-byte group with the neighbouring bytes,
    which is also why `=` padding does not matter;
  - *hex*: the value's UTF-8 bytes, all lowercase or all uppercase, contiguous.
- **Verdict, reason, audit log.** `block` (`env-value`, family `write-secret`).
  The reason shown to the model names the variable(s) and says to reference
  them by name instead; the audit-log entry carries the names in `env_vars`
  ([Audit log reference](audit-log.md#verdict-entry)). **On this verdict the
  value, in clear, base64 or hex, appears in neither** — nor in the log's `target` (a path
  that itself carries the value is logged as `(path withheld: …)`) — nor in
  the retry's `policy-warning`, whose error text is withheld when it carries a
  value. A shared dev password that also sits in a docker-compose file or a
  test fixture blocks that file: that is the guard working, and the reason
  tells the agent to reference the variable instead.
- **Tool output too (ADR-0008, ticket 59).** The same row, the same names,
  floor and spellings, redact every tool's **output** before the model sees
  it: under a harness that declares a post-tool event (Claude Code's
  `PostToolUse`, pi-agent's `tool_result`), each occurrence becomes
  `[redacted: NAME]` inside the output's own text, its shape kept (keys,
  numbers, booleans; image data is left alone). Two variables whose values
  overlap are named together in one marker (`[redacted: A, B]`); a value
  contained in a longer one is named by the longer; one value under two
  names is named by the one that sorts first. A base64 spelling goes with
  exactly the characters that carry a bit of the value, and its `=` padding
  when it ends the stream; a neighbour from the base64 alphabet (`/`, `_`,
  `-`, a letter) stays. The audit log records a `redact`
  verdict with the names ([Audit log reference](audit-log.md#verdict-entry)).
  Limits of its own (a failed tool under Claude Code, on-disk copies of the
  output): see the [Claude Code](../how-to/wire-into-claude-code.md#tool-output-redaction)
  and [pi-agent](../how-to/wire-into-pi-agent.md) how-tos.
- **Opting out.** The row is a regular baseline row, listed by `rules list`
  and reachable by `[[override]]` ([Override a baseline rule](../how-to/override-a-baseline-rule.md)):
  `disable` switches the guard off; `relax` softens it to `confirm` or
  `observe` (the variable is still named); `replace` swaps the row's regex,
  which here only decides **which written texts** the guard looks at (the
  baseline's `[\s\S]` accepts every non-empty text) — it sees the text, never
  the path, so it cannot exempt a file. **One switch for both uses** (ADR-0008
  § 5): `disable` or `relax` turns the tool-output redaction off as well.
  `replace` does not: it governs writes only, and the redaction ignores the
  row's `regex` and `except` and always scans the whole output, so an override
  written for the write guard never narrows what is hidden from the model
  (decision H6). The recognition itself (`special = "env_value"`) is the
  engine's and is not replaceable.

**Limits.** The guard sees only what its own environment holds, and only these
spellings:

- Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` strips credentials from
  subprocess environments, hooks included: the hook then sees **no values**
  and the guard is inert for the stripped variables.
- A value the agent splits, concatenates, reverses, ROT13s, hashes or
  re-encodes (percent-, JSON- or HTML-escaping, base64 of UTF-16 or broken
  across lines, hex with separators or in mixed case) before writing evades. A
  multi-line value (a PEM key) of which only some lines are written evades the
  plain match, and a value is matched exactly as the environment holds it, so
  one with a trailing newline does not match the same text without it.
- A variable exported later inside the Bash tool's own shell, or defined only
  by a shell profile the hook never loads, is not in the hook's environment.
- It is a net for what the agent copies. Since ticket 59 a value printed by a
  tool reaches the model redacted, within the post-tool limits above.
- It does not redact other families' logs. Every rule other than `env-value`
  logs its `target` verbatim, so a Bash command that carries a literal value
  and is blocked by another rule is written to the audit log as typed.

`bouncer audit` leaves an `env-value` entry `(as logged)`, like every
`write-secret` entry: the written text was never logged, so there is nothing
to re-judge.

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
- Plaintext inherited from the agent's launch environment cannot be removed
  by any row. The [environment rows](#the-environment-rows) only refuse the
  commands that print or reference it, and [the env-value row](#the-env-value-row)
  only blocks a write that carries its value — a net, not a barrier: a test or
  a script the agent launches inherits the environment and may print it, and a
  value that already reached the agent's context stays there. The structural
  fix is the launcher's (secrets kept out of the agent's environment).
- The audit log records every verdict's `target` as the rule saw it, except
  the `env-value` verdict's, which withholds a path that carries a protected
  value. A command that carries a literal value and is blocked by another
  rule is therefore logged in clear.
- The environment rows read command text. Not covered: a variable name or a
  command built at run time (`eval`, a base64-decoded command, a pid in
  `/proc/$$/environ`); Perl `%ENV`, PHP `$_ENV` and Python's bare `environ`
  after `from os import environ`; `docker run … env`, `podman`,
  `kubectl exec … -- env`, `yq` `env()`; `readonly -p` and `compgen -v`;
  `ps` options ahead of the BSD operand (`ps -p 1 eww`); `ps`, `jq`,
  `docker` or `launchctl` behind something the command-position lead-in does
  not know — a wrapper (`timeout 5 docker exec c env`, `watch`, `xargs`,
  `env VAR=value docker …`; `sudo` is blocked outright by the command
  family), a bare `( … )` subshell, a pipe with no space before it
  (`a|jq -n env`), `docker exec c ps eww`; a `docker compose config` flag the
  printing-flag list does not know.
- Prose is command text: a commit message or a heredoc that spells
  `process.env` or a protected variable fires the whole-environment (block)
  or the reference (confirm) row, and a line that holds only `set`, `env` or
  `export` in a heredoc (SQL, YAML) fires `env-dump`, as does the JavaScript
  object shorthand `{ env }` (a brace opens a command position; `node -e
  "spawn(cmd, { env })"`). `echo $TOKEN | docker login --password-stdin` is
  blocked because `echo` is a display; a jq program that holds `env` in a
  string literal or as a variable name (`test("a|env b")`, `--arg env prod`)
  matches `env-dump-jq`: jq is the command there, so command position does
  not help; a search is excepted only when
  the whole command is searches and harmless readers (`awk` and the
  interpreters are not).
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
- `kill-init` requires a literal signal spelling and target; a signal or PID
  reached through a shell variable or command substitution (`kill -$SIG 1`,
  `kill -9 $PID`) is not resolved before scanning.
- `kill-init` recognizes only the enumerated signal spellings and `--`; a
  `killall`-specific flag ahead of the signal (`-q`, `-u`, `-t`, `-c`, …)
  is not skipped, so `killall -q -TERM init` evades the row — a deliberate
  scope boundary, not an oversight (the ticket's own decision names "any
  signal spelling…and a `--` separator", not "any flag").
- `kill-init` blocks `kill -0 -1`: signal `0` is a pure existence probe (it
  kills nothing) but the row's numeric signal alternative does not
  special-case it. Accepted over-blocking, not a gap.
- `kill-init`'s numeric signal spelling (`-<number>`) is syntactically
  identical to the `-1` target: `kill -1 12345` and `killall -1 node`
  (sending SIGHUP to a harmless pid or name) block, not because `-1` names
  the target here but because the row cannot tell a signal number from the
  target it precedes. Accepted over-blocking, pre-existing.
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

## `rules.command.git`: the four declarative conditional forms

Below `rules.command.git`, two plain lists (`safe_subcommands`,
`config_read_modes`) and four declarative tables cover git subcommands
whose safety depends on their arguments — everything else falls through
to `git-protected` (always confirm). `checkout` and `restore` are the
two subcommands these four forms can't express (pathspec detection,
index-only form — `--staged` plus one or more pathspecs) — they stay
engine code under their own names. Three more lists, `allowed_global_options`,
`allowed_config` and `allowed_env`, judge what is written around `git`
instead of the subcommand (§ [`git-config-exec`](#git-config-exec-what-may-stand-before-git) below).

A subcommand is judged by the first form that governs it, in this order:
`safe_subcommands` (always safe), `ask_flags`, `safe_first_arg`,
`safe_grammar`, `safe_flags`, then the `checkout` and `restore` engine
exceptions. A subcommand an earlier form governs never reaches a later
one, so an overlay `ask_flags` entry for `init` takes over from the
baseline's `safe_flags` entry for it.

**`ask_flags`** — safe unless one of `flags` is present, or (with
`max_positionals`) too many non-flag arguments are given. This is
baseline's own `branch` row verbatim, so pasting it into an overlay as-is
is a SUBSTITUTION of an already-governed subcommand (§ [[relax]] below)
— `reason` is what makes it valid as a real overlay entry, not just a
baseline-shape illustration:

```toml
[[rules.command.git.ask_flags]]
sub = "branch"
flags = ["-d", "-D", "--delete", "-m", "-M", "-C", "--move", "-f", "--force"]
reason = "example only — this duplicates the baseline row verbatim"
```

In the baseline, `branch -C` force-copies a branch and may replace the
destination, while `branch -c` refuses an existing destination and remains
unlisted. The `tag` row also lists `-f` and `--force`: moving an existing tag
can discard its previous target. Other tag forms such as `-a`, `-l`, `-n`,
`--format` and `--sort` remain safe.

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `flags` | string[] | yes |
| `max_positionals` | number | no |
| `reason` | string | conditional — see § [[relax]] below |

`flags` lists the options that ask; it never lists the safe ones. Each
argument after the subcommand is compared with the listed flags the way
git itself reads options (gitcli(7)), so the exact spelling is only one of
four ways to hit a flag, and each of them asks:

| Written as | Matches when | Example |
|---|---|---|
| the listed spelling | identical | `git branch -D foo` |
| `--name=value` | `--name` is listed (the value is ignored) | `git switch --force-create=x main`, `git branch --force=x` |
| an abbreviation | a `--x` that is a strict prefix of a listed long option, however short | `git branch --delet foo`, `git tag --del v1`, `git switch --discard` |
| a group of short options | a single-dash token that is not a number, in which any letter before a `=`, at any position, is a listed short option | `git branch -qD foo`, `git branch -dv foo`, `git tag -fd v1`, `git switch -C=x main` |

The `=value` and abbreviation forms compose: `git switch --force-c=x main`
asks, as git itself reads it as `--force-create=x`. In a group of short
options, a `=` starts the value: only the letters before it are read, so
`git switch -fc=y HEAD~1` asks (`-f`) and `git switch -c=x` does not. A
listed spelling asks even where git refuses it (`git branch --force=x`, an
ambiguous abbreviation): the list is a confirmation net, not a model of
git's errors. `--` (end of options) and a bare `-` are matched only when
listed themselves. An entry that is neither `-x` nor `--name` (a bare word,
`-ff`) matches its exact spelling only. `max_positionals` counts the
arguments that are not options and does not change.

The rule is the same for every `ask_flags` entry, the baseline's and an
overlay's, so an existing overlay entry becomes stricter without being
rewritten.

**Known limit.** The options that take a value are unknown to `ask_flags`
(no field names them), so a value can be read as options. A value glued to
a short option reads as more letters (`git switch -cfix`,
`git tag -mfix v1`): the `f` in the tag message matches listed `-f`;
`git tag -mdone` asks because the `d` in its message matches listed `-d`.
A value in the next token that starts with `-`
(`git branch --sort -committerdate`) can also contain a listed option and
cause one unnecessary confirmation. The error is on the safe side.
A separated value that does not start with `-`
(`git switch -c fix`) does not ask; for one that does, write
`--opt=value` (`git branch --sort=-committerdate` does not ask).
`fixtures/command.json` pins the glued and separated limits
(`known-limit-git-switch-glued-value-letter`,
`known-limit-git-tag-glued-force-letter`,
`known-limit-git-branch-separated-dash-value`).

**`checkout` engine exception.** Its destructive options use the same
`ask_flags` matcher as the declarative rows: exact spellings, grouped short
options, `--name=value` and strict long-option prefixes (including a prefix
with `=value`) ask. That covers `-f`, `-B`, `--ours`, `--theirs`, `-p` and
`--patch`, including grouped or abbreviated spellings. `--`, pathspecs and
the two-positional `checkout <ref> <path>` form also ask for confirmation;
ordinary branch switches and branch creation remain safe.
As with every `ask_flags` row, a value glued to a short option can be
read as flags: `git checkout -bfix` asks because its `f` matches `-f`;
`git checkout -b fix` remains safe. The known limit is pinned by
`known-limit-git-checkout-glued-value-letter`.

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
sequence. A string slot is literal except `"*"`, which matches any single
non-flag token. A typed `{ kind = "sha" }` slot matches one SHA-shaped
token without granting the wildcard's broader revision-name surface.
Written on its own line, `sequences = [ ["--check"] ]` needs a space
after the first `[` — Bun's TOML parser misreads a bare leading `[[` as
an array-of-tables header even mid-value (see `policy/command.toml`'s
own `apply` entry, which avoids it by putting the outer bracket on its
own line — same for `pull`/`merge` in `examples/personal-overlay.toml`,
ticket 13's tracked example of a `safe_grammar` entry living in a
personal overlay instead of the baseline). Baseline's own `apply` row;
same substitution note as `ask_flags` above:

```toml
[[rules.command.git.safe_grammar]]
sub = "apply"
sequences = [ ["--check"], ["--check", "*"] ]
reason = "example only — this duplicates the baseline row verbatim"
```

An overlay can declare a plain single-SHA cherry-pick form:

```toml
[[rules.command.git.safe_grammar]]
sub = "cherry-pick"
sequences = [
  [ { kind = "sha" } ],
]
```

The SHA constraint is lexical: exactly 7–64 ASCII hexadecimal characters
(`0-9`, `a-f`, or `A-F`), case-insensitive. It does not read the repository
or call Git, and does not verify the identifier exists, names a commit, or
uniquely identifies an object. A hexadecimal-looking branch or other ref is
indistinguishable from a SHA-shaped token.

Matching uses Git arguments after recognized shell redirections have been
removed: `2>&1` is not an extra argument, but an option following it still
is. Quoted or escaped redirection text remains an argument. Redirection
destinations are still inspected by the path protections; an allowed Git
form cannot authorize an otherwise protected write. Ambiguous redirection
syntax requires confirmation instead of silently dropping arguments.

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `sequences` | `Array<Array<string \| { kind = "sha" }>>` | yes |
| `reason` | string | conditional — see § [[relax]] below |

**`safe_flags`** — safe only if every argument is an allowed option, the
value of one, or one of at most `max_positionals` positional arguments.
It is the inverse of `ask_flags`: the entry lists what is allowed, so an
option it does not list asks. Baseline's own `init` row; same
substitution note as `ask_flags` above:

```toml
[[rules.command.git.safe_flags]]
sub = "init"
flags = ["-q", "--quiet"]
value_flags = ["-b", "--initial-branch"]
max_positionals = 1
reason = "example only — this duplicates the baseline row verbatim"
```

| Field | Type | Required |
|---|---|---|
| `sub` | string | yes |
| `flags` | string[] — options accepted on their own, each starting with `-` | yes |
| `value_flags` | string[] — options that take a value, each starting with `-` | yes |
| `max_positionals` | integer ≥ 0 | yes |
| `reason` | string | conditional — see § [[relax]] below |

Any other key rejects the layer: a misspelled `value_flag` would
otherwise be dropped in silence, and an allow-list that lost a field is
read in the permissive direction.

The arguments after the subcommand — once recognized shell redirections
are removed, as for `safe_grammar` — are read one by one. The command is
safe only if every one is:

1. an option of `flags`, written exactly;
2. an option of `value_flags`, written exactly, followed by a value that
   does not start with `-` (the value is consumed: it is not a
   positional);
3. `--name=value`, where `--name` is a long option of `value_flags` and
   `value` is not empty (a short option has no `=` form);
4. a positional argument — one that does not start with `-` — within the
   `max_positionals` count.

Anything else asks with `git-protected`. The rule judges the text only:
it does not call git and does not read the file system. Abbreviated long
options, grouped short options, glued short values and `--` match none of
the four cases, so they ask by construction — which is why the form is an
allow-list rather than a deny-list.

The same allow-list reasoning covers what is written before the
subcommand. Global options such as `--bare`, `--git-dir`, `--work-tree`,
`-c` or `--no-pager` act on the command as if they followed it
(`git --bare init` is `git init --bare`), so for a subcommand decided by
`safe_flags` the only global option tolerated is `-C <dir>`, alone or
repeated; any other asks with `git-protected`. The other three forms,
and `safe_subcommands`, ignore global options when they decide the
subcommand. The global options and the environment prefixes
(`GIT_TEMPLATE_DIR=… git init`) of every subcommand are judged
separately, by `git-config-exec` (§ below).

Against the baseline `init` row:

| Accepted | Why |
|---|---|
| `git init`, `git init -q` | no argument, or a `flags` option |
| `git init --quiet /tmp/x`, `git init -q .` | one positional |
| `git init -q -b develop .` | `-b` consumes `develop`; `.` is the positional |
| `git init --initial-branch=main` | `--name=value` of a long `value_flags` option |
| `git -C /tmp/x init -q` | `-C <dir>` is the one global option `safe_flags` tolerates before the subcommand |
| `git init -q 2>/dev/null` | a redirection is not an argument |

| Refused (`git-protected`) | Why |
|---|---|
| `git init --bare`, `--shared`, `--template=<d>`, `--separate-git-dir <d>`, `--object-format=sha256`, `--ref-format=reftable` | option not listed |
| `git init --separate=<d>` | an abbreviation is an unknown token |
| `git init -qb main` | grouped short options are one unknown token |
| `git init -bmain` | a glued short value is an unknown token |
| `git init -b`, `git init -b -q`, `git init --initial-branch=` | no value, a value starting with `-`, an empty value |
| `git init --` | the end-of-options marker is an unknown token |
| `git init /tmp/a /tmp/b` | more positionals than `max_positionals` |
| `git --bare init`, `git --git-dir=/tmp/x/.git init`, `git --work-tree=/tmp/x init`, `git -c init.templateDir=/tmp/t init -q` | a global option other than `-C <dir>` |
| `git -C /tmp/x --bare init -q` | `-C` combined with another global option |

## `git-config-exec`: what may stand before `git`

A git subcommand the section above allows still runs any program git is
told to run. `git -c core.fsmonitor=<shell> status` executes the shell
command, `git -c core.hooksPath=/tmp/h commit` the `pre-commit` hook found
there, `GIT_EXTERNAL_DIFF=<program> git diff` the program, and
`git --exec-path=/tmp/x status` a `git-*` helper planted in `/tmp/x`.
`git-config-exec` reads what is written around `git` and answers `confirm`
unless every item is on an allow-list. Like the rest of the git policy it
judges the text only: it does not call git and does not read the file
system.

**What is judged**, in every git segment:

| Written | Judged by |
|---|---|
| `-c <key>=<value>` | `allowed_config`: key and value |
| `--config-env=<key>=<VAR>`, or `--config-env <key>=<VAR>` | `allowed_config`: key only, because git reads the value from `VAR` when it runs, so only an entry without a value allows it |
| any other global option before the subcommand (`--exec-path`, `--namespace`, `-C <dir>`, `--no-pager`…) | `allowed_global_options`: by name; for `--name=value` the name is looked up and the value is not |
| `VAR=<value> git …`, `VAR+=<value> git …`, `env VAR=<value> git …`, and through the prefixes and wrappers of § [What counts as the start of a command](#what-counts-as-the-start-of-a-command) (`rtk`, `command`, `timeout`, `xargs`…: `LC_ALL=C timeout 5 git …`) | `allowed_env`: name and value; the name of `VAR+=<value>` keeps its `+`, so it matches no entry and asks |

**Entry grammar** (`allowed_config` and `allowed_env`). An entry is either a
name, which allows it at any value (`user.name`; a trailing `*` makes it a
prefix, `user.*`), or `name=value`, which allows it at that one value
(`core.pager=cat`). It is split at its first `=`, so a value may hold one.
A config key is compared without regard to case, as git does
(`tag.gpgSign` matches `tag.gpgsign`); a value and a variable name are
compared exactly. A `*` means something only at the end of an entry that
has no value. A list that is empty allows nothing.

**Baseline content** (`policy/command.toml`):

| List | Entries |
|---|---|
| `allowed_global_options` | `-C`, `--no-pager`, `-P`, `-p`, `--paginate`, `--no-replace-objects`, `--literal-pathspecs`, `--glob-pathspecs`, `--noglob-pathspecs`, `--icase-pathspecs`, `--no-optional-locks`, `--no-advice`, `--git-dir`, `--work-tree`, `--bare` |
| `allowed_config`, any value | `user.*`, `color.*`, `advice.*`, `init.defaultBranch`, `commit.gpgsign`, `tag.gpgsign`, `tag.forceSignAnnotated`, `push.followTags`, `gc.auto`, `core.quotepath` |
| `allowed_config`, one value | `core.hooksPath=/dev/null`, `core.pager=cat`, `core.fsmonitor=false`, `core.editor=true`, `core.editor=:`, `sequence.editor=true`, `sequence.editor=:` |
| `allowed_env`, any value | `GIT_AUTHOR_*`, `GIT_COMMITTER_*`, `GIT_TERMINAL_PROMPT`, `GIT_INDEX_FILE`, `LC_ALL`, `LANG`, `TZ`, `NO_COLOR`, `CI`, `GIT_DIR`, `GIT_WORK_TREE` |
| `allowed_env`, one value | `GIT_EDITOR=true`, `GIT_EDITOR=:`, `GIT_SEQUENCE_EDITOR=true`, `GIT_SEQUENCE_EDITOR=:`, `GIT_PAGER=cat`, `PAGER=cat`, `GIT_TRACE=0`, `GIT_TRACE=1`, `GIT_TRACE=2`, `GIT_TRACE=true`, `GIT_TRACE=false` |

The keys and variables listed with one value are the ones that run a
program at any other value (`core.pager=less`, `GIT_EDITOR='cp /tmp/m'`) and
are harmless at the listed one. `GIT_TRACE` is listed the same way for
another reason: at any value but the five that switch tracing on or off it
is a file git appends its trace to, a write no write rule looks at
(`GIT_TRACE=/tmp/x git status` asks). The other `GIT_TRACE*` variables
(`GIT_TRACE2`, `GIT_TRACE_PACKET`, `GIT_TRACE_PERFORMANCE`…) are not listed
and ask; a `[[relax]]` widens them. `--git-dir`, `--work-tree`, `--bare`,
`GIT_DIR` and `GIT_WORK_TREE` run nothing themselves and are listed so
that they pass; the subcommand's own verdict still applies.

**Order.** The subcommand's own verdict comes first, and `git-config-exec`
only turns an allow into a confirm. A line with several git segments
answers for the first segment that asks, whichever rule asks. So
`git -c core.pager=x push` answers `git-protected`, as does
`GIT_EDITOR=true git rebase --continue` (push and rebase ask on their own),
and so does `git -c user.name=x init -q`: `init` is decided by
`safe_flags`, which tolerates no global option but `-C <dir>`, whatever the
`-c` key. The audit log tells the two ids apart.

Asking (`confirm [git-config-exec]`), with the first offender in the reason:

| Command | Offender |
|---|---|
| `git -c core.fsmonitor='echo x' status`, `git -c core.hooksPath=/tmp/h commit -m x`, `git -c diff.external=/x diff`, `git -c include.path=/tmp/c status` | a key that runs a program or loads a file, at a value not listed |
| `git -c core.pager=less diff`, `git -c core.hooksPath= commit` | a listed key at another value |
| `git --config-env=core.pager=CAT diff`, `git --config-env core.pager=X diff` | a key listed with a value only: the value is unknown |
| `git --exec-path=/tmp/x status`, `git --namespace=x status` | a global option that is not listed |
| `GIT_EXTERNAL_DIFF=/x git diff`, `env GIT_SSH_COMMAND=/x git ls-remote ssh://h/r`, `HOME=/tmp/h git status`, `GIT_CONFIG_GLOBAL=/tmp/c git status`, `PATH=/tmp/bin:$PATH git status` | a variable that is not listed |
| `GIT_EDITOR='cp /tmp/m' git commit` | a listed variable at another value |

Passing, as long as the subcommand itself passes:

| Command | Why |
|---|---|
| `git -c user.email=t@t -c user.name=t commit -qm i`, `git -c commit.gpgsign=false commit -q -F -`, `git -c tag.gpgSign=false tag v1` | keys listed at any value |
| `git -c core.hooksPath=/dev/null commit -qm i`, `git -c core.pager=cat diff` | keys listed at that value |
| `git --no-pager diff`, `git -C /tmp/x status`, `git --git-dir=/tmp/x/.git log` | global options listed |
| `GIT_EDITOR=true git commit`, `GIT_SEQUENCE_EDITOR=: git log`, `LC_ALL=C git ls-remote https://h/r`, `GIT_TERMINAL_PROMPT=0 git fetch https://h/r`, `rtk git status` | variables listed; a wrapper alone |

**Widening.** The three lists are policy data like `config_read_modes`: an
overlay extends them through [`[[relax]]`](#relax-widen-a-pure-allowlist)
only, reason mandatory, and `bouncer doctor` and `bouncer rules list`
show each entry as an active relaxation. A `value` follows the entry grammar
above, so `GIT_SSH_COMMAND='ssh -o BatchMode=yes' git ls-remote ssh://h/r`
passes after:

```toml
[[relax]]
list = "command.git.allowed_env"
value = "GIT_SSH_COMMAND=ssh -o BatchMode=yes"   # that one value; "GIT_SSH_COMMAND" allows any
reason = "CI probes reach hosts over ssh and must not prompt"
```

Prefer a `name=value` entry for a key or variable that runs a program: the
bare name allows every value, `-c core.sshCommand=/tmp/evil` included.
`[[override]]` cannot target `git-config-exec` (it is produced by an engine
algorithm, not by a row of the six regex tables).

**Known limits.**

- An `export GIT_EXTERNAL_DIFF=… && git diff` in the same line, or in an
  earlier call, sets the variable outside the prefix of the git command,
  which is all the rule reads (`known-limit-git-config-exec-exported-variable`
  in `fixtures/command.json`).
- A value is read as literal text: `GIT_EDITOR=$EDITOR git commit` asks
  (the text is not `true`), while `GIT_AUTHOR_NAME=$(…) git commit` passes
  the rule, a variable listed at any value.
- `GIT_INDEX_FILE` is listed at any value because it runs nothing, but git
  writes its index to the path it names. With a subcommand the baseline
  allows, that creates a new file at most, and `read-tree`, which can
  overwrite one, asks on its own; the rule does not look at that path.
- `--git-dir`, `--work-tree`, `GIT_DIR` and `GIT_WORK_TREE` are listed, but git
  reads the config of the repository they name: a config file planted
  there, like a `.gitconfig` or a `.git/config` written by another tool, is
  not seen.
- A binary named `git` started by a path (`/tmp/x/git status`) is judged as
  git, whatever it is. A `PATH=… git …` prefix asks, as `PATH` is not listed.

## What counts as the start of a command

`git-protected`, `git-config-exec`, `sudo` (privilege escalation) and
`rm-rf-dangerous` judge a command by its name, so they first find where each
command of a line starts. This list is the one definition they share.
`tests/command-start-forms.ts` writes it once as forms around a command `X`
and replays them on `git push`, `sudo ls`, `rm -rf /` and `git status`; the
result is the `command-start-*` cases of `fixtures/command.json`. The env rows
of `rules.secret.bash` find a command with their own pattern, the
command-position lead-in described with them above.

A command starts:

1. **After a separator**: at the start of the line, after `;`, `&&`, `||`,
   `|`, `&` or a newline.
2. **Inside a grouping**: after `(` or `{`, including a `(` glued to the first
   word (`(git push)`). A `)` or `}` that ends the last word, glued or separate,
   is taken off, with any redirection after it. The body of a function
   definition counts: `f() { git push; }`, `function f { git push; }`.
3. **After a shell keyword**: `!`, `if`, `then`, `elif`, `else`, `while`,
   `until`, `do`.
4. **Inside a substitution**: `$( … )`, backticks, `<( … )` and `>( … )`. An
   assignment `X=$( … )` is not a variable written in front of the command
   inside the substitution: `STRAY=$(rtk git status --short | wc -l)` passes.
5. **In the argument of a shell that reads a command line**: `bash`, `sh`,
   `zsh` and `dash`, also started by a path (`/bin/bash`), with `-c`, also in
   a group (`-lc`, `-ec`, `-euc`), and `eval`. The argument is read again as a
   command line with these same rules, only when the shell itself starts a
   command (after items 1 to 4, the prefixes and the wrappers). An argument
   holding `$var`, `$( … )` or backticks is read too; those are opaque words
   in it. An assignment written before the shell reaches every command of the
   line read again, its substitutions included, as it reaches the shell's
   environment: `GIT_SSH_COMMAND=x bash -c 'git fetch'` asks like
   `GIT_SSH_COMMAND=x git fetch`. The same holds for `watch` and `env -S`
   (item 7).
6. **After a prefix**: an assignment `VAR=x` or `VAR+=x`, `rtk` (and
   `rtk proxy`), `command`, `exec`, `nice` (`-n N`), `time` (`-p`) and
   `builtin`.
7. **After a wrapper**, read with the shape of its arguments:

| Wrapper | Options passed before the command |
|---|---|
| `timeout` | `-k`/`--kill-after` D, `-s`/`--signal` S, `--foreground`, `--preserve-status`, then the duration |
| `xargs` | `-0`/`--null`, `-r`/`--no-run-if-empty`, `-t`/`--verbose`, `-n`/`--max-args` N, `-I` R, `-P`/`--max-procs` N, `-L` N, `-d`/`--delimiter` C, `-E` S, `-s`/`--max-chars` N, `--replace[=R]`, `--max-lines[=N]`, `--eof[=S]` |
| `env` | `-i`, `-u` NAME, `VAR=x`, and `-S` STRING, whose words are read as the start of a command line |
| `nohup` | none |
| `watch` | `-n`/`--interval` S, `-d`/`--differences[=permanent]`, `-t`/`--no-title`, `-x`/`--exec`, `-c`/`--color`, `-g`/`--chgexit`, `-e`/`--errexit`, `-p`/`--precise`; without `-x`, watch runs its words with `sh -c`, so they are read as a command line (item 5) |

Prefixes and wrappers are recognised by name, also when started by a path
(`/usr/bin/env git push`, `/usr/bin/timeout 5 git push`). Options are read
the way getopt reads them: grouped (`-0r`), with a glued
value (`-n1`, `-I{}`, `-sKILL`) or as `--name=value`; `--` ends them. An option
that is not listed for a prefix or a wrapper makes the start uncertain: each
rule then looks for its command name among the words that follow
(`timeout --verbose 5 git push` asks).

**Depth.** A command line read again (item 5, `env -S`, `watch`) and the body
of a backtick or a process substitution are read down to three levels below
the line: `bash -c "eval 'eval git push'"` asks; a fourth level is not read.
`$( … )` is read at any depth.

**The reading before this list stays.** Each rule first reads every segment
of the line the way it did before, from its first word past the prefixes of
item 6, then every command this list finds. A command that asked before
therefore asks with the same rule and reason, and no verdict loosens:
`(cd /tmp && git status)` still asks, as that reading takes `status)` for the
subcommand. `rm-rf-dangerous` also still reads every `rm` word of the line
wherever it stands (`echo rm -rf /` is blocked). The path scans
(protected-write targets, the secret path scan, `docker-destructive`) keep
their own reading.

**Not the start of a command** (known limits):

- the command after a `case` pattern (`case x in a) git push;; esac`);
- a function called by name: its body is judged where it is defined;
- the argument of `bash -c "$cmd"`: the command a variable names is known
  only when the shell runs;
- the words `xargs` reads on its standard input: `echo -D | xargs git branch x`
  is judged as `git branch x`;
- a command run on another machine, in a virtual machine or in a container:
  `ssh host '…'`, `limactl shell vm -- bash -c '…'`, `docker exec c sh -c '…'`;
- `parallel`, `script -c`, and the wrappers not listed (`stdbuf`, `flock`,
  `caffeinate`…);
- a variable exported earlier (`export GIT_EXTERNAL_DIFF=…`, see
  § [`git-config-exec`](#git-config-exec-what-may-stand-before-git));
- a heredoc body, which is the input of a command, not a command line: its
  lines keep the reading before this list (their first word only), and a
  backtick bash runs in an unquoted heredoc (`cat <<EOF` … `` `git push` ``)
  is not read;
- a command line nested more than three levels down.

## The two algorithm-driven tables

`rm-rf-dangerous`, `sudo` (privilege escalation), `git-protected` and
`git-config-exec` are produced by engine algorithms, not by a `{id, regex, reason}` row —
`[[override]]` can't target them (§ below). Each is governed by its own
named table instead, additive only (new entries widen what's caught,
never narrow it):

```toml
[rules.command.rm_rf]
dangerous_targets = ["^\\/$", "^~\\/?$", "..."]  # regexes the rm target must NOT match

[rules.command.privilege_escalation]
commands = ["sudo", "doas", "pkexec", "runas", "please"]
```

`git-protected` is governed by `safe_subcommands` and the four
declarative forms above; `git-config-exec` by `allowed_global_options`,
`allowed_config` and `allowed_env` (§ above).

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

Active `$()` command substitutions are scanned separately from the enclosing
command, including inside double quotes and nested substitutions.
`CURSOR=$(jq -r .cursor roster.json)` remains a read; writes inside the
substitution and targets after it are still checked. Single-quoted or escaped
`$()` text stays literal. Search-pattern and prose masking excludes only the
literal portions of an argument, not the commands it executes. Substitution
output is never evaluated.

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
response = "tool_response"

[harness.protocol.events]
pre_tool = "PreToolUse"
prompt = "UserPromptSubmit"
session_start = "SessionStart"
post_tool = "PostToolUse"

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
ask_probe = "2026-08-16, Claude Code (version unrecorded): an unanswerable ask under --dangerously-skip-permissions is enforced as deny"

[harness.protocol.output.deny]
stdout = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":${reason}}}'

[harness.protocol.output.redact]
stdout = '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":${response}}}'
```

**`transport`** — the codec that reads the envelope. `"stdin-json"` (the
only one this ticket declares): one JSON object on stdin, no framing.

**`wiring`** — the codec `doctor` uses to prove the hook is actually
installed. `"hook-file"` (generic): reads `<configDir>/settings.json`,
checks each of `events.pre_tool`/`prompt`/`session_start`/`post_tool` names a command
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
an executable that is not a versioned Homebrew Cellar path
(`<prefix>/Cellar/<formula>/<version>/bin/<exe>`, which `brew upgrade`
removes) (`wiring:binary`); and (ticket 56), when `witness` is an
`agent` directory (`~/.omp/agent`), the same byte-for-byte check for every
omp profile beside it, each `<witness's parent>/profiles/*/agent`
(`wiring:shim (profile <name>)` — omp loads none of the default
directory's extensions in a profile; a folder whose name omp refuses is no
profile and is skipped; no field to declare); no canary
concept (the shim already fails closed on its own liveness). Optional: a
harness declared without one gets `wiring: not checkable (declared
harness)` in `doctor`, visible rather than silently green.

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
claude-code.toml declares none), `response` (ADR-0008 — OPTIONAL, required
iff `events.post_tool` is declared: the tool's own result in a post-tool
envelope, walked and rewritten in its own shape — `tool_response` for
Claude Code, the shim's `content` for pi-agent).

**`[harness.protocol.events]`** — the literal event-name strings `event`
takes for each event this pipeline understands. `pre_tool` is always
required. `prompt` and `session_start` are OPTIONAL (review round 2
R2-1) — a harness that never judges a submitted prompt (or has no
doctor-facing SessionStart surface, ADR-0006 § 7's pi-agent by design)
declares neither, rather than being forced to name an event field it has
no real envelope shape for. `post_tool` (ADR-0008) is OPTIONAL too: the
event fired after a tool ran, whose response bouncer rewrites to redact
protected environment values ([the env-value row](#the-env-value-row));
a harness that cannot replace a tool result (Codex today) declares none and
is never reached. See "Optional surfaces" below for the coherence rules
gating each.

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
A WELL-FORMED envelope naming an event this binary does not judge (one
the declaration does not name, a missing `hook_event_name`) is a SEPARATE case and
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

**Optional surface: `post_tool` (ADR-0008 § 3)** — fail-closed by lint,
the block rejected AS A UNIT on any of:

14. `events.post_tool` declared without `input.response`, or
    `input.response` declared without `events.post_tool` (a dead selector).
15. `events.post_tool` declared without a
    `[harness.protocol.output.redact]` table, or that table present without
    `events.post_tool` (a dead template).
16. A `redact` template whose `stdout` does not carry `${response}`, or
    that sets `exit` — an answer that drops the rewritten response, or exits
    instead of answering, would show the original output.
17. `events.post_tool` equal to another declared event name — `run` routes
    the post-tool event first, so a shared name would never be judged as a
    tool call.

**`[harness.protocol.output.<action>]`** — one template table per action
the output table actually maps a verdict to (never `silent`, which
renders nothing), plus `session_start` when `events.session_start` is
declared (SessionStart's own doctor announcement, rendered through this
same mechanism but never reached via the verdict table) and `redact` when
`events.post_tool` is declared (the rewritten tool response, ADR-0008). Each sets
`stdout` (a string), `exit` (an integer process exit code), or both —
Claude Code's five templates only ever set `stdout`. Placeholders are
JSON-encoded ON SUBSTITUTION (so an arbitrary reason/context string with
quotes or newlines never breaks the surrounding JSON literal) — write
them BARE, `${reason}` never `"${reason}"`: the value already carries
its own quotes once substituted, so a hand-written quote around the
placeholder doubles up and produces invalid JSON. `rules lint` rejects a
`stdout` where a placeholder directly touches a `"`, and separately
renders every template once with a worst-case probe value and requires
the result to still parse as JSON when `stdout` looks like a JSON object
or array literal — both belts reject the containing action's block as a
unit, the same as any other rule 1–17 failure.

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
| `redact` | `${response}` only — the rewritten tool response, JSON-encoded as the VALUE it is (an object, an array), not as a string: one rule for every placeholder, `JSON.stringify(value)` (ADR-0008 § 2) |

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
printed extension, `wiring:shim` + `wiring:binary` and, ticket 56, one
`wiring:shim (profile <name>)` per omp profile; no settings shape and
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
  the shim's ask dialog under both `pi` and `omp` (ticket 15c, then a
  Yes/No `ctx.ui.confirm`); confirmed live on both binaries 2026-09-08
  (real dialog, decline blocks, accept runs) and flipped to `"ask"` — see
  `pi-agent.toml`'s own `ask_probe` field and the 15c report's probe
  table for both runs' evidence, including a first `omp` attempt that
  turned out to be a stale, reused session and was retracted before the
  flip. Ticket 55 (2026-10-11, re-run 2026-10-12) turned the dialog into a
  numbered one-key `ctx.ui.select` (`1. Allow` / `2. Block`; only the
  exact `1. Allow` allows) and re-ran the probe on both binaries: accept
  runs, decline, Esc and Ctrl+C block, headless blocks without a dialog —
  but the digit keys and the default highlight are measured per binary,
  not iso (omp 18.9.1: digits select instantly and Block is highlighted,
  so a stray Enter blocks; pi 0.84.1: digits do nothing and Allow is
  highlighted, so a stray Enter allows, as it did with the former Yes/No
  dialog).
- Around the ask dialog, when a UI exists, the pi-agent shim emits omp's
  `herdr:blocked` event on the extension bus (ticket 55) so that Herdr's
  omp integration, which listens for it, is expected to report the agent
  `blocked` while the dialog is up (pending the operator's live Herdr
  run) — an observability signal, never policy: it changes no verdict,
  and a `pi` with no event bus or an `emit` that throws is swallowed. The
  release (`{ active: false }`) runs whenever the dialog settles — an
  answer, Esc, Ctrl+C, a failing select — and, with the dialog open and
  the process sent SIGINT, SIGTERM or SIGHUP, under omp (its shutdown
  settles the dialog) but not under pi 0.84.1, which exits with the dialog
  still pending (measured 2026-10-12; the signal dies with the process).
  Known limit: vibe-island listens to omp's `tool_approval_*` events, not
  to `herdr:blocked`, so it stays blind to a Bouncer ask (omp's native
  approval is not reachable from an extension's `tool_call` result, which
  only carries `block`, `reason`, `additionalContext` and `input`).

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
`command.git.config_read_modes`, `command.git.allowed_global_options`,
`command.git.allowed_config`, `command.git.allowed_env`,
`mcp_write.read_prefixes`, or `mcp_write.allowed_tools`. A direct addition
to any of these lists via the table itself is rejected outright.

```toml
[[relax]]
list = "command.git.safe_subcommands"   # one of the seven lists above
value = "push"
reason = "..."   # mandatory, non-empty — this can only relax security
```

For `allowed_global_options`, `allowed_config` and `allowed_env`, `value`
is an entry as described in § `git-config-exec`: a name for any value, or
`name=value` for one value. `rules lint` rejects the layer for a value that
names nothing: on `allowed_config` and `allowed_env` an empty name
(`=true`) or a bare `*` (`*`, `*=true`), which would allow every key or
variable; on `allowed_global_options` a value holding `=`, since the value of
`--name=value` is not part of an entry and such an entry would never match,
and `-c` or `--config-env`, which `allowed_config` judges before this list is
read.

A `safe_first_arg`/`ask_flags`/`safe_grammar`/`safe_flags` overlay entry
whose `sub` is already governed by the baseline (`init` is, through
`safe_flags`) is a SUBSTITUTION, not a fresh addition, and needs the same
mandatory `reason` (see the field tables above) — the overlay entry wins
over the baseline one for that subcommand.

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
- **`ask_flags` / `safe_first_arg` / `safe_grammar` / `safe_flags`** —
  overlay entries come first. Every consumer looks a `sub` up by
  `Array.find()`, so an overlay entry for an already-governed `sub` wins
  over the baseline one — this asymmetry is what makes such an entry a
  substitution (§ `[[relax]]` above), not a plain addition.

## Precedence: the profile wins on a shared target (ADR-0001)

The common and profile layers are not merged as two more files in one
set — the SAME target contributed by both is not a cross-file conflict,
it is the profile layer replacing the common layer's entry outright. The
targets this applies to (the four case ADR-0001 names):

- A regex-table row `id` (any of the six families).
- An `[[override]]`'s `rule`.
- An `[[relax]]`'s `list` + `value`.
- An `ask_flags` / `safe_first_arg` / `safe_grammar` / `safe_flags`
  entry's `sub` (within its own table — `ask_flags` and `safe_first_arg`
  sharing a `sub` name is not itself a shared target).

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
- Two `ask_flags`/`safe_first_arg`/`safe_grammar`/`safe_flags` entries for
  the same `sub`, in two different files of the same layer.
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
Source: src/policy/schema.ts, src/policy/load.ts, src/policy/lint.ts, src/policy/baseline.ts, src/policy/fragments.ts, src/policy/harness.ts, src/protected-write-rules.ts, src/protected-names.ts, src/env-value-rules.ts, policy/command.toml, policy/secret.toml, policy/mcp-write.toml, policy/write-secret.toml, policy/protected-write.toml, policy/prompt.toml, policy/harness/claude-code.toml, policy/harness/codex.toml, policy/harness/opencode.toml, policy/harness/pi-agent.toml, policy/harness/pi-agent.shim.ts, policy/harness/gemini-cli.toml, policy/harness/cursor.toml, src/adapter/policy.ts, src/adapter/log-path.ts, src/adapter/shim.ts, src/adapter/codecs/stdin-json.ts, src/adapter/codecs/wiring/hook-file.ts, src/adapter/codecs/input/apply-patch.ts, src/adapter/codecs/input/hashline.ts, src/adapter/codecs/wiring/codex-hooks.ts, src/adapter/codecs/wiring/shim-file.ts, src/adapter/codecs/wiring/registry.ts, src/adapter/neutral-call.ts, src/adapter/degrade.ts, src/adapter/render.ts
