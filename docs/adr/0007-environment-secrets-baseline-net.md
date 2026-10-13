# ADR-0007: Environment secrets: baseline rows as a net, not a barrier

**Date**: 2026-10-13
**Status**: Accepted
**Deciders**: Jonathan Robic

## Context

### Current situation

An agent's environment holds whatever its launcher exported: a direnv
`.envrc` loaded before `claude` started, a shell profile, a CI runner's
job variables. A process inherits that environment and every child it
starts inherits it again, so a command the agent writes (`env`, `echo
$GITHUB_TOKEN`, `docker exec app-db env`) can print a secret straight into
the transcript, where the model, the logs and any later reader see it.

Before 1.8.0 nearly every way of reading the environment was allowed.
Measured on 2026-10-11 with `bouncer check` on the installed 1.5.0 binary,
a probe of 23 commands that read the environment returned `allow` for 22;
only `gh auth token` was caught, by `credential-printer`. The `dotenv` row
of `rules.secret.path` protects the *file* that exports the variables. It
says nothing about the variables once a shell has loaded them.

[ADR-0002](0002-sops-age-decryption-is-a-human-act.md) option 3 had already
looked at an environment tripwire and declined it for the production-secret
case: with the `sops exec-env` doctrine the agent's environment carries no
production value, and the 25 `env`/`printenv` dumps in three months of
transcripts were all token-presence checks. That argument covers production
plaintext. It does not cover the tokens an operator exports on purpose
(`GITHUB_TOKEN`, `NPM_TOKEN`, a database password for local tests), which
are the ones an agent can print by accident.

### Problem

Where does Bouncer draw the line between a command that reads the
environment legitimately and one that leaks it, given that it sees only
command text?

### Constraints

- Bouncer judges text. A command string or the content of a write is
  all it receives; it cannot remove a variable from a process, and it cannot
  see what a script the agent launches does with the environment it inherits.
- Tests legitimately inherit the environment: a suite that connects to
  `app-db` needs `DB_PASSWORD`.
- Universality bar (ticket 13): a baseline row has to be inert for a
  consumer who has none of these variables, and a client-specific name does
  not belong in a public baseline.
- A consumer who disagrees needs a one-row escape hatch (`[[override]]`).

## Decision

Four decisions, each with the alternative it rules out. The rows and their
forms are specified in
[policy.md § The environment rows](../reference/policy.md#the-environment-rows);
this page keeps the reasons.

### 1. A net, not a barrier, shipped now

The baseline refuses the accidental read of the agent's own environment, and
the documentation says in plain terms that it does not remove the secret. The
structural fix belongs to the launcher: keep secrets out of the agent's
environment and inject them only into the commands that need them. The
[how-to](../how-to/keep-env-secrets-away-from-agents.md) describes that
side.

Rules out:

- **Waiting for the launcher-side fix.** It is the right fix and it is
  outside Bouncer's reach, and it varies by harness (Claude Code has an
  environment scrub, pi-agent and omp have none). Until each operator
  applies it, the accidental read stays uncovered, while the rows can ship
  today.
- **Claiming a barrier.** A row that blocks `echo $GITHUB_TOKEN` stops
  nothing when the agent runs `make test` and the test prints the variable.
  Calling the rows a barrier would tell an operator the launcher work is done
  when it is not.

### 2. The verdict follows the use

- **Block** a dump of the whole environment, and a protected variable fed to
  a display (`echo`, `printf`, `console.log`, `node -p`, …). Both put the
  value in the transcript by their nature.
- **Confirm** any other use of a protected variable. A token in an
  `Authorization` header is what the variable is for, and the human decides
  whether this command is the one that should carry it. `docker inspect`
  is a confirm for the same reason: it prints `Config.Env`, and inspecting
  a container is everyday work.
- **Block** whole-environment access (`process.env` spread or iterated,
  `os.environ` dumped) and a name computed at run time (`os.environ.get(<expr>)`,
  `${!name}`, `'GITHUB_' + 'TOKEN'`). A name rebuilt from pieces passes
  every name rule, so the only rule that holds is to refuse the computation.

Rules out:

- **Block every reference.** It breaks the legitimate uses that `confirm`
  keeps, so operators would relax or disable the rule wholesale and lose
  the protection it gave.
- **Confirm everything.** A printed secret is already in the transcript by
  the time the human answers, and a prompt that fires on every `env` trains
  the answer "yes". The cases where the output is the leak need a verdict
  that does not depend on that answer.

### 3. Protected names by an uppercase suffix, written once, in the baseline

A name is protected when it is uppercase and equals, or ends in `_` plus,
`TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`,
`ACCESS_KEY` or `CREDENTIALS`. The definition lives in one module,
`src/protected-names.ts`. A baseline row writes `{{protected-name}}` in its
regex and the loader substitutes the definition once at load time; the long
alternations the environment rows share (reference forms, command-position
lead-in, jq's builtin) are fragments filled the same way. The baseline
refuses to load when a placeholder is undefined or survives the fill, so a
typo cannot silently disable a row.

Rules out:

- **A per-client explicit list in a profile layer.** It does not reach every
  harness: an omp session in the same tree does not read the Claude Code
  profile layer, so the same variable would be protected in one assistant and
  not in the other. It would also be redundant, because every name on the
  list already matched the suffixes.
- **An engine feature that lets a layer append names to a row.** It would add
  merge semantics (today layers add rows, never data inside a row) for a
  single use.
- **Three hand-copied alternations.** The reference rows, the display rows
  and `isProtectedName()` would drift apart with no failing test to say so.

### 4. No rule on protected names in code the agent writes

An earlier proposal confirmed a `Write` or `Edit` that cites a protected
name outside a configuration file. It is not built: ordinary application code
reads `process.env.DB_PASSWORD` all the time, and the rule would confirm most
edits to code that handles configuration.

The planned follow-up detects the *value* instead of the name: ticket 58
blocks a `Write` or `Edit` whose content contains a protected value, and
ticket 59 redacts a value from tool output. ADR-0008 will record that
decision; it is not written yet.

Rules out:

- **A name-based rule on writes.** Noise on legitimate code, for a signal
  that a value-based check carries more precisely.

## Consequences

### Positive

- The accidental read is covered on every harness, with no configuration and
  with no client-specific name in the baseline.
- Each row has its own id, so a workflow that inspects containers all day
  relaxes `env-dump-docker-inspect` alone and keeps the rest
  ([how-to](../how-to/keep-env-secrets-away-from-agents.md)).
- The definition of a protected name exists once; code that needs it imports
  it.

### Negative

- **Friction, measured.** On 2026-10-13, 7,571 distinct Bash commands from
  omp sessions were replayed through the full dispatch against the new
  baseline (ticket 57). The verdict changed for 52 of them (0.69 %). Two
  were true false positives, and both are documented known limits in
  [policy.md § Known limits](../reference/policy.md#known-limits). The
  `docker inspect` confirmations are the main source of friction; they are
  relaxable by id.
- **Text only.** A variable name built at run time by `eval` or a decoded
  command, a language or tool outside the recognised forms, and a script that
  prints its inherited environment all pass. The list is in policy.md § Known
  limits. Value-based detection (tickets 58 and 59) is planned to narrow it.
- **New ids.** An overlay row that reuses one of the new baseline ids is
  rejected at load.

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| An operator reads the rows as a guarantee and skips the launcher work | Medium | High | policy.md and the how-to state "net, not a barrier" and name the launcher fix; this ADR records why |
| A regex row backtracks catastrophically on a hostile command | Low | High | every environment row ran in under 100 ms on pathological inputs on the development machine; the test asserts a 1 s ceiling so a shared CI runner does not flake |
| A protected-looking name is missed (`DB_PASS`, `SECRET_KEY`) | Medium | Medium | suffix list is public and universal; a consumer adds an overlay row for a name of their own |

## References

- `policy/secret.toml` (the environment rows), `src/protected-names.ts`,
  `src/policy/fragments.ts`.
- [policy.md § The environment rows](../reference/policy.md#the-environment-rows)
  and § Known limits.
- [How-to: keep environment secrets away from agents](../how-to/keep-env-secrets-away-from-agents.md).
- [ADR-0002](0002-sops-age-decryption-is-a-human-act.md) (the production
  secret case and the `exec-env` doctrine).
- Ticket 57 (this decision, PR #19); tickets 58 and 59 (planned).

---

## History

| Date | Action | By |
|---|---|---|
| 2026-10-13 | Created, Accepted. Shipped in 1.8.0 (ticket 57, PR #19). | Jonathan Robic |
