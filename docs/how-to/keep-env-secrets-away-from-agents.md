# Keep environment secrets away from agents

Goal: stop an agent from reading the secrets its launcher exported into its
environment (a direnv `.envrc`, a shell profile, a CI runner), see what
Bouncer already refuses without configuration, quiet the confirmations you
do not want, and close the part Bouncer cannot close.

## Prerequisites

- Bouncer 1.8.0 or later, wired into your harness
  ([Claude Code](wire-into-claude-code.md), [Codex](wire-into-codex.md),
  [pi-agent and omp](wire-into-pi-agent.md)). `bouncer --version` prints the
  version.
- Secrets that live in the environment of the shell that starts the agent.
  Secrets kept only in a file are the `dotenv` row's job, not this page's.

## What the baseline already does

Since 1.8.0 the baseline judges the common ways an agent reads its own
environment, with no configuration:

- a dump of the whole environment (`env`, `printenv`, `export`,
  `ps eww`, `docker exec <container> env`, `docker compose config`) is
  blocked;
- a protected variable fed to a display (`echo $GITHUB_TOKEN`) is blocked;
- any other use of a protected variable (a token in an `Authorization`
  header) asks for confirmation;
- the environment object used as a whole (`process.env` spread or printed,
  `os.environ` dumped) and a variable name computed at run time are
  blocked;
- `/proc/<pid>/environ` is blocked, for the Read tool as well as Bash;
- `docker inspect` asks for confirmation, because it prints a container's
  `Config.Env`.

A protected name is an uppercase name that ends in a credential word, such
as `GITHUB_TOKEN`, `DB_PASSWORD` or `STRIPE_API_KEY`. The exact definition,
every row id and the forms each row recognises are in
[The environment rows](../reference/policy.md#the-environment-rows). The
rows read command text, so they are a net and not a barrier: step 3 covers
what they miss.

## Steps

1. Check the verdicts on your own machine. `bouncer check` judges a command
   string and runs nothing ([CLI reference](../reference/cli.md#check)).
   Put the command in single quotes: in double quotes your shell expands
   `$GITHUB_TOKEN` first, so Bouncer judges the value or an empty string
   instead of the reference and answers `allow`.

   ```sh
   bouncer check 'echo $GITHUB_TOKEN'
   ```

   ```console
   block [env-ref-display] prints the value of a protected variable (a name ending in TOKEN, PASSWORD, SECRET, API_KEY, …) into the transcript — use it without printing it, or ask the operator → deny (claude-code)
   ```

   Expect these verdicts:

   | Command | Verdict | Row |
   |---|---|---|
   | `env` | block | `env-dump` |
   | `echo $GITHUB_TOKEN` | block | `env-ref-display` |
   | `python -c 'import os; print(os.environ["DB_PASSWORD"])'` | block | `env-ref-display` |
   | `cat /proc/self/environ` | block | `bash-proc-environ` |
   | `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user` | confirm | `env-ref` |
   | `docker inspect app-db` | confirm | `env-dump-docker-inspect` |
   | `env FOO=1 make test` | allow | |
   | `echo $HOME` | allow | |

   For another harness add `--harness <id>`. Codex turns every `confirm`
   into a deny, so its two confirm lines end in `deny (codex)`.

2. Reduce the noise. `docker inspect` is the confirmation most operators
   meet daily. Relax that row by its id, with a reason, in
   `<configDir>/bouncer/policy.toml` to affect one profile, or in
   `~/.agents/bouncer/policy.d/<file>.toml` to affect every harness. Edit it
   in your own editor: a write to the policy file from the agent is itself
   confirmed (`bouncer-policy`).

   ```toml
   [[override]]
   rule = "env-dump-docker-inspect"
   action = "relax"
   verdict = "observe"
   reason = "we inspect local containers all day; the databases hold throwaway credentials"
   ```

   `action`, `verdict` and the other forms are described in
   [Override a baseline rule](override-a-baseline-rule.md). The same block
   with `rule = "env-ref"` silences the confirmation on every other use of a
   protected variable. Do it only if that use is routine for you: the
   confirmation is the only check on where the value goes. Leave the block
   rows (`env-dump`, `env-ref-display`, `env-ref-whole`, `env-ref-computed`)
   alone unless a specific workflow forces you to relax one.

   Lint and re-check:

   ```sh
   bouncer rules lint
   bouncer check 'docker inspect app-db'
   bouncer doctor
   ```

   ```console
   observe [env-dump-docker-inspect] docker inspect prints a container's configuration, its environment variables included — confirm before reading it → silent (claude-code)
   ```

   `doctor` lists the override under `overrides:`. After upgrading to 1.8.0,
   run `bouncer rules lint` even if you add nothing: an overlay row that
   reuses one of the new ids is rejected.

3. Close the part Bouncer cannot close. Bouncer judges command text and the
   content of writes. It cannot remove a variable from the environment, and
   a test or a script the agent launches inherits that environment and can
   print it, while Bouncer sees only the command that launched it. The rows
   are a net for the accidental read, not a barrier
   ([why](../adr/0007-environment-secrets-baseline-net.md)). The gap closes
   at the launcher, with one of these:

   - Keep the secrets out of the agent's environment and inject them only
     into the commands that need them, through a wrapper that runs a fixed
     command and that the agent cannot edit. `sops exec-env <file>
     '<command>'` run in your own terminal is the pattern
     [ADR-0002](../adr/0002-sops-age-decryption-is-a-human-act.md)
     describes. Start the agent from a shell that has not loaded the
     secrets: no exports in the profile, and `direnv allow` withheld for the
     directory the agent starts in.
   - In a CI runner, scope each secret to the step that needs it instead of
     the whole job, so the step that runs the agent never receives it.
   - In Claude Code, set `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` in the
     environment that launches `claude`. It strips credential-looking
     variables from Bash commands, hooks and stdio MCP servers
     ([what it removes](https://code.claude.com/docs/en/env-vars#what-the-subprocess-environment-scrub-removes)).
     Three consequences. All three facts come from that page; the effect on
     Bouncer in the third is inferred, not measured:
     - it removes every variable whose name or value looks like a
       credential, so a test that needs `DB_PASSWORD` or `NPM_TOKEN` runs
       without it;
     - it leaves `GITHUB_TOKEN`, `GH_TOKEN` and the proxy variables in
       place, so Bouncer's rows remain the only guard for those (a
       [`sandbox.credentials`](https://code.claude.com/docs/en/sandboxing#protect-credentials)
       deny entry removes a GitHub token from sandboxed commands);
     - it also removes `CLAUDE_CONFIG_DIR`. Bouncer's hook is one of the
       scrubbed subprocesses, and `policy/harness/claude-code.toml` names
       that variable as the way it finds the profile directory, so under
       the scrub a profile selected with `CLAUDE_CONFIG_DIR` would be read
       from `~/.claude` instead. A session that uses the default
       `~/.claude` is not affected.
   - pi-agent and omp have no equivalent switch: use the first two options.

## Verify

- `bouncer rules lint` exits 0.
- Every command of step 1 returns the verdict in the table, except the rows
  you relaxed in step 2.
- `bouncer doctor` lists each override you wrote, with its reason.
- Launcher side, from a terminal started the way you start the agent and
  outside the agent: this prints names only, never values.

  ```sh
  env | cut -d= -f1 | grep -E '^([A-Z0-9_]*_)?(TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS)$'
  ```

  The output lists every protected name the agent would inherit. Empty
  means nothing is exported; a name you left on purpose is a name the
  agent can read. The pattern mirrors `PROTECTED_NAME_SOURCE` in
  `src/protected-names.ts` and must follow that definition if it changes.
- Under `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`, with `NPM_TOKEN` exported in
  the launcher, ask the agent in a Claude Code session to run
  `test -n "$NPM_TOKEN" && echo set || echo unset`. Bouncer asks for
  confirmation (`env-ref`); approve it. The command prints `set` or
  `unset`, never the value, and `unset` shows the scrub removed the
  variable.

---
Source: policy/secret.toml, src/protected-names.ts, src/cli-commands.ts, policy/harness/claude-code.toml
