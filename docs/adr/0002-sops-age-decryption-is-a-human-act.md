# ADR-0002: sops/age decryption is a human act — the baseline blocks it for the agent

**Date**: 2026-09-04
**Status**: Accepted
**Deciders**: Jonathan Robic (design session, 2026-09-04)

## Context

### Current situation

The agent works on the local environment only. Production overrides live
sops-encrypted in the repository (`prod.enc.env`, `prod.enc.yaml`) and are
decrypted by the human, in the human's own terminal, through
`sops exec-env <file> '<command>'`: the plaintext exists only in that child
process, never on disk. The age identity that decrypts them sits at sops's
default location (`~/Library/Application Support/sops/age/keys.txt` on
macOS, `$XDG_CONFIG_HOME/sops/age/keys.txt` elsewhere), or wherever
`SOPS_AGE_KEY_FILE` points. Three months of transcripts (67 524 Bash
commands) hold 278 `sops` invocations, `SOPS_AGE_KEY_FILE` among them.

Measured on the installed binary on 2026-09-04 (`bouncer check`): every one
of `sops -d prod.enc.env`, `sops exec-env prod.enc.env pnpm start`,
`sops prod.enc.yaml` (implicit edit), `age -d -i keys.txt file.age`,
`cat ~/Library/Application\ Support/sops/age/keys.txt` and
`cat ~/.aws/sso/cache/abc.json` was **allow**. The agent runs with the
human's identity: sops as deployed protected against accidental reads and
commits of plaintext, not against the agent deciding to decrypt.

### Problem

Nothing distinguished "the human decrypts in their terminal" from "the
agent decrypts in its Bash tool". The doctrine existed as a habit, not as an
enforced boundary, and the `.aws` home directory was only half covered
(`credentials` and `config`; the `sso/cache` and `cli/cache` token files
were not).

### Constraints

- Universality bar (ticket 13): a baseline row must be inert for a consumer
  who has no sops, no age, no `.aws` — never a false positive on an
  ordinary workstation.
- `--dangerously-skip-permissions` turns every `confirm` into an effective
  deny (probe of 2026-08-16): a verdict chosen for the interactive case must
  still make sense under that flag.
- The Bash matcher is a literal-string defense, not a shell parser
  (`src/secret-rules.ts` header): a rule that needs shell semantics to be
  right is out of reach.
- A consumer who disagrees must have a one-row escape hatch
  (`[[override]]`, `docs/reference/policy.md`).

## Options considered

### Option 1: `confirm` on decryption

Ask the human every time the agent runs `sops -d` or `age -d`.

**Pros**: the softest form; nothing is refused outright.

**Cons**: reintroduces exactly the prompt the doctrine removes — the agent
never has a legitimate reason to decrypt a production value, so every prompt
is a "no" the human has to type. Under `--dangerously-skip-permissions` it
is already a deny; `confirm` only changes the interactive case, where the
point is to not be asked.

**Effort**: low.

### Option 2: `block` on decryption, `relax` as the escape hatch (chosen)

Four baseline rows in the `secret` family, default verdict `block`:
`sops-decrypt`, `age-decrypt`, `age-identity` (path), and `aws-creds`
widened in place to the whole `.aws` directory. A consumer wanting the
softer form writes `[[override]] rule = "sops-decrypt" action = "relax"
verdict = "confirm"` with its reason.

**Pros**: the verdict matches the doctrine ("not the agent's act"); no
prompt; the escape hatch is per row and carries a reason.

**Cons**: `age` is general-purpose — a consumer who uses `age` for
non-secret files pays a block until they relax it. Marked `debatable` in
the TOML for that reason.

**Effort**: low (policy rows + fixtures); the implicit-edit form of `sops`
cost three review rounds (below).

### Option 3: Also guard the environment — `env`/`printenv` dumps and `process.env`

**Pros**: would catch plaintext already loaded into the agent's shell.

**Cons**: measured over the same three months: 25 `env`/`printenv` dumps,
all legitimate token-presence checks; 24 `process.env` hits, nearly all
heredoc file contents. With the `exec-env` doctrine the agent's environment
carries no production value; the tripwire would cost ~2 confirms a week for
nothing. Plaintext inherited from a shell where direnv loaded production
before `claude` started is a launch-discipline case, out of scope by
construction.

**Effort**: low to build, permanent friction. Not built.

### Option 4: Recognise `sops` through the structural tokenizer

Parse the command like the git guard does and decide on argv.

**Pros**: exact command-position detection, no false positive on prose
(`brew install sops age`, `rg sops docs/`).

**Cons**: a new engine mechanism for one tool; the ticket said "the
fixtures decide, not the mechanism". A regex anchored at command head —
start of string or `;&|(`, then optional `VAR=value` assignments and the
engine's benign wrappers (`rtk`, `command`, `exec`, `env`, `nice`, `time`,
`builtin`, `proxy`), then `sops` and exactly one non-flag token — passed
every fixture, including the three false positives above as allows.

**Effort**: medium. Deferred; the regex is the decision.

## Decision

**Option 2.** The rows, as shipped in `policy/secret.toml` (commit
`7b86e18`, ticket 24):

- `sops-decrypt` (bash): the explicit forms `-d`, `--decrypt`, `decrypt`,
  `exec-env`, `exec-file`, `edit` anywhere after a `sops` word, plus the
  implicit edit form `sops <file>` at command head as described in option 4.
  Not matched: `-e`/`encrypt`, `set`, `unset`, `rotate`, `updatekeys`,
  `publish`, `filestatus`, `groups`, `--version`, `--help`, and prose
  (`echo sops`, `which sops`, `brew install sops age`, `rg sops docs/`).
- `age-decrypt` (bash): `age`/`rage` with `-d`/`--decrypt`. `Debatable
  (ticket 24)`.
- `age-identity` (path): `(^|/)sops/age/[^/]+$|(^|/)age/keys\.txt$` —
  every default identity location plus the bare `age/keys.txt` convention;
  `crypto-key` already covers `*.agekey`.
- `aws-creds` (path): `(^|/)\.aws(/|$)` — id kept, so no existing override
  breaks; `~/.aws-sam/` and `/opt/aws/bin` (no leading dot) stay allowed.

Through the Bash path-token scan, the two path rows also fire on commands
naming those paths (`bash-age-identity`, `bash-aws-creds`); strictest wins.

### Justification

Block, not confirm, because the interactive prompt is the cost the doctrine
exists to remove, and because the flag that most agentic sessions run under
already makes the two verdicts equivalent. The escape hatch is the
documented `relax` form rather than a softer default: the row states the
doctrine, the override states the exception and its reason.

## Consequences

### Positive

- Decryption, the identity file and the whole `.aws` directory are refused
  to the agent by default; a `sops exec-env` no longer depends on the file
  being named `.env*` to be caught (`prod.enc.env` is sops's native naming
  and was not a `dotenv` match).
- The rows are inert without sops/age/aws on the machine.
- One override row restores the soft form per rule, with a reason.

### Negative

- Literal matching does not see `sops` hidden behind a package script
  (`pnpm start:prod` wrapping `sops exec-env`) or run by direnv from an
  `.envrc`. Operating convention, not a rule: decrypting scripts stay
  operator-run, never repository scripts the agent can invoke.
- `sops --config cfg.yaml prod.enc.yaml` (a flag plus a file) falls outside
  "exactly one non-flag token" and is allowed — recorded as a `knownLimit`
  fixture.
- A non-default `SOPS_AGE_KEY_FILE` is the human's own choice; a personal
  overlay row names it. `SOPS_AGE_KEY` inline in the environment is the
  launch-discipline case above.

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Prose or install commands blocked by the implicit-edit form | Low | Low | anchored at command head; `brew install sops age`, `rg sops docs/`, quoted commit messages pinned as allow fixtures (review rounds 1–2b of ticket 24) |
| A consumer who uses `age` for non-secret files is blocked | Medium | Low | `Debatable (ticket 24)` annotation; `[[override]] action = "relax"` |
| Plaintext already in the agent's environment at launch | Low | High | out of scope by construction; launch discipline (start `claude` from a shell that has not loaded production) |
| Decryption reached through a wrapper the regex does not list | Low | Medium | the explicit forms use `\bsops` (any prefix); only the implicit edit form is anchored — extend the wrapper list if a real one appears |

## Implementation plan

- [x] Ticket 24 — four rows, fixtures both directions, digest lock, TOML
      comments (doctrine, known limits, `debatable`), `docs/reference/policy.md`
      (`rules.secret.bash` row, known limits), ticket-13 triage table
      (universal ×3, debatable ×1). Commit `7b86e18`.
- [x] Shipped in the grouped reinstall of 2026-09-04 (`903b052`).

## Success metrics

- On the installed binary: `sops -d f`, `sops exec-env f cmd`,
  `sops prod.enc.yaml`, `SOPS_AGE_KEY_FILE=k sops prod.enc.yaml`,
  `rtk sops prod.enc.yaml`, `age -d f.age`, reads of `sops/age/keys.txt`
  and of `~/.aws/sso/cache/*.json` → `block`; `sops -e f`, `sops --version`,
  `age -r x -o f.age f`, `brew install sops age`, `rg sops docs/` → `allow`.
  Verified on the source build before install (39 probes) and on the
  installed binary after.
- Zero `sops-decrypt`/`age-decrypt` denials on a legitimate command in the
  audit log over the following weeks; a hit means either the doctrine was
  bypassed or a wrapper form is missing.

## References

- `policy/secret.toml` (rows and comments), `fixtures/secret.json`
  (`sops-*`, `age-*`, `aws-creds-*` cases, `knownLimit` on `--config`).
- `docs/reference/policy.md` § The five regex tables, § Known limits,
  `docs/how-to/override-a-baseline-rule.md` (the `relax` form).
- Ticket 13 (baseline universality bar).

---

## History

| Date | Action | By |
|---|---|---|
| 2026-09-04 | Created, Accepted — design session decision, shipped the same day | Jonathan Robic |
