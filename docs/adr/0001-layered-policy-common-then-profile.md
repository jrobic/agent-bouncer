# ADR-0001: Layered policy — a harness-neutral common layer read natively, the profile layer wins

**Date**: 2026-09-03
**Status**: Accepted
**Deciders**: Jonathan Robic (grilling session, rounds 1–2, 2026-09-03)

## Context

### Current situation

`bouncer` loads its overlay from one root per invocation:
`<configDir>/bouncer/policy.toml` (optional) then `<configDir>/bouncer/policy.d/*.toml`
in lexicographic filename order (`src/adapter/policy.ts`). `<configDir>` is the
Claude Code account directory (`CLAUDE_CONFIG_DIR`, default `~/.claude`). The
engine (`src/policy/load.ts`) receives one flat list of files and has no
notion of where they come from.

Two profiles run the binary on this workstation. Since 2026-09-03 they share
their rules through a directory symlink, `<configDir>/bouncer/policy.d` →
`~/.agents/bouncer/policy.d` (dotfiles ADR-0004, an explicitly interim
mount). The loader does not know the link exists. Three properties of the
current loader shape that mount:

- Two overlay files targeting the same thing (a git `sub`, a `[[relax]]`
  list + value, an `[[override]]` rule, a regex `id`) reject the whole set —
  never "last file wins" (`docs/reference/policy.md` § Cross-file conflicts).
  A profile therefore cannot specialise anything the shared files already
  touch; it can only add what they leave alone.
- Any broken file rejects the whole set and falls back to the embedded
  baseline (§ Fail-closed behavior). The shared files carry pure hardening
  too (`hook-log`), which falls with them.
- A broken *directory* symlink reads as "no overlay": `lint: OK`, doctor
  `[pass] baseline only`. Silent (ADR-0004, probe B).

### Problem

Sharing rules between profiles requires a per-profile mount gesture, gives
no way for one profile to diverge from the shared rules, and leaves
provenance blind (`[policy.d/100-personal.toml]` says nothing about which
root the file lives under). The user's stated goal: the loader reads the
common layer itself, and the per-profile symlinks disappear.

### Constraints

- Only the *policy* is shared. Audit logs stay per profile
  (`src/adapter/log-path.ts` is untouched): the per-account config dir
  exists so a client seat's trail never interleaves with the personal one.
- Universality bar (ticket 13): a workstation without a common layer is a
  normal deployment, never a warning.
- Multi-harness (ticket 15): the common layer must live somewhere no
  harness owns; the profile layer is whatever the calling harness's adapter
  resolves. `bouncer` never enumerates profiles — one invocation, one
  harness, one profile.
- Fail-closed stays: nothing a broken file does may loosen the effective
  policy.
- The engine stays I/O-free and path-agnostic.
- No per-project layer in this change. A policy read from a repository is
  supplied by the repository — attack surface, separate decision
  (`.scratch/backlog.md`, cascade entry).

## Options considered

### Option 1: Pointer — `include_dir` declared in the profile's `policy.toml`

The target ADR-0004 § 7 sketched: each profile's `policy.toml` names the
common directory; the loader follows the pointer.

**Pros**: explicit and visible in `rules lint`; loud when the target is
missing; no path convention baked into the product.

**Cons**: keeps one file per profile — the very per-profile gesture this
change removes, just a pointer instead of a link. ADR-0004 chose the pointer
against an environment variable (shells of other harnesses do not inherit
the launcher's environment), not against a convention; and the fact that
made a convention impossible then — "bouncer ignores `~/.agents`" — is what
this change ends.

**Effort**: medium (two-phase read: parse the profile file before knowing
the file set).

### Option 2: Convention — `~/.agents/bouncer/` read natively (chosen)

The adapter resolves a second root, `~/.agents/bouncer/`, with the same
shape as the profile root (`policy.toml` optional, then `policy.d/*.toml`),
through one harness-neutral helper every adapter calls. No file in any
profile says where the common layer is.

**Pros**: zero per-profile configuration; one root for every harness, which
is what makes the layer "common" rather than "Claude's"; `~/.agents/` is
the multi-harness root already in use for everything else shared.

**Cons**: an absent directory is an empty layer, silently — the same
silence ADR-0004 § 8 paid for with the interim link. Mitigation: every
output names the layer's state (`common: 4 files` / `common: absent`), and
the workstation's own doctor (dotfiles, `rules lint | grep -q overlay:`)
keeps failing loudly when the common files are not loaded. `~/.agents/`
becomes a product convention, documented as such.

**Effort**: low for discovery; the real work is the layering (shared by
every option).

### Option 3: Hybrid — convention by default, `include_dir` to override

**Pros**: covers a deployment that wants the common layer elsewhere.

**Cons**: two mechanisms, two test surfaces, for a need nobody has
measured. YAGNI.

### Option 4: Keep the symlink mount

**Pros**: nothing to build.

**Cons**: every property under *Current situation* stays: per-profile
gesture, no divergence, silent broken link, blind provenance.

## Decision

**Option 2**, with the layering semantics below. Every item was put to the
user and settled (grilling rounds 1–2, 2026-09-03); the recommended answer
was taken each time.

### Layers and discovery

- Merge order: embedded baseline → **common** (`~/.agents/bouncer/`) →
  **profile** (`<configDir>/bouncer/`, resolved by the calling harness's
  adapter). Within a layer: `policy.toml` first, then `policy.d/*.toml` in
  lexicographic order — unchanged.
- Both layers have the same shape, read by one function over two roots.
- The engine receives **named layers** (`[{name: 'common', files},
  {name: 'profile', files}]`) and owns precedence, rejection and
  provenance. The adapter only resolves roots and reads files.
- `bouncer` does not enforce the `NNN-` filename prefix ranges of ADR-0004
  § 2. Layer order is the order of layers, not of names; the prefix is one
  deployment's convention.

### Precedence — the profile wins

- The same target in the common layer and the profile layer — a git `sub`
  in `ask_flags`/`safe_first_arg`/`safe_grammar`, a `[[relax]]`
  list + value, an `[[override]]` rule, a regex `id` — is not a conflict:
  the profile entry replaces the common one. The shadowed common regex row
  is dropped; the profile row stays at its own position (after every
  common row — overlay rows are hardening additions after the baseline,
  their mutual order rarely matters, and this shape has no special case).
- Two files of the **same** layer targeting the same thing stay a
  lint error, exactly as today.
- The cascade is additive: a profile can add or shadow, never *revoke* a
  common `[[relax]]`. A relaxation not wanted on every profile does not
  belong in the common layer. A `[[revoke]]` form is a backlog idea for
  open-source users with a shared common layer and a stricter profile.
- New lint rule, any layer: a regex row whose `id` is a **baseline** id is
  an error ("use `[[override]] action = "replace"`"). Today such a row is
  silently appended and dead (the baseline row matches first), and an
  `[[override]]` on that id would hit both rows.

### Rejection — per layer, still fail-closed

- A broken file rejects **its layer**, not the set. Common broken → common
  dropped, profile kept — unless a profile `[[override]]` no longer resolves
  (its target was in the dropped common layer): then the profile layer is
  rejected too, and the baseline runs alone. Profile broken → profile
  dropped, common kept.
- One `policy-warning` audit-log entry per rejected layer, naming the file;
  `rules lint` and `doctor` fail as they do today.
- Absent common directory: a pass, with `common: absent` in every output.
  Never a failure — a fresh install has no `~/.agents`.
- Migration guard: when the profile's `policy.d` resolves (realpath) to
  the common root — the interim symlink still in place — the profile layer
  is skipped and a warning names the fix (`rm` the link). The warning fails
  `doctor`, so `SessionStart` repeats it until the link is gone. Without
  this, the same four files would load twice and the profile copy would
  "shadow" the common copy line by line: identical effect, lying
  provenance.

### Provenance

- `rules list`: `rule secret.path hook-log overlay
  [common:policy.d/100-personal.toml]`, `[profile:policy.toml]`; any entry
  that shadows one carries `shadows common:<file>`.
- `rules lint`: `lint: OK (overlay: common/policy.d/100-personal.toml, …,
  profile/policy.d/500-x.toml)` — the `overlay:` token stays, the
  dotfiles doctor greps it.
- `doctor`: `policy — overlay active (51 effective rules; common: 4 files,
  profile: 0 files)`.
- A readability pass on these formats is a backlog item; they are shaped
  to be exact, not pretty.

### Explicitly deferred

- **Sealed rules** (a common rule no lower layer may disable or relax).
  Both layers are files the user owns; an agent wanting to disarm a rule
  must edit one of them, and since ticket 19 that edit asks. A seal earns
  its place only with a layer the user does not own — the per-project
  layer, excluded here.
- **Per-project layer**, **`[[revoke]]`**, **provenance UX pass** —
  `.scratch/backlog.md`.

## Consequences

### Positive

- The per-profile symlinks and the manifest entry that installs them go
  away; a profile is "the common layer plus its own files", by construction.
- A profile can diverge (client seat stricter or looser on one target)
  without editing the common layer.
- A broken profile file no longer drops the common layer's hardening, and
  vice versa.
- Every rule names its layer and file; a shadowed entry says so.
- The same common root serves every future adapter (ticket 15) unchanged.

### Negative

- `~/.agents/bouncer/` is now a product convention. Documented in
  `docs/reference/policy.md`; a deployment that wants another root has no
  knob until someone needs one (option 3).
- An absent common layer is silent by design; on this workstation the
  dotfiles doctor, not `bouncer`, is what notices.
- "Same target in two layers" changes meaning from *error* to *the profile
  wins*. Provenance is what keeps that debuggable — it is not optional.

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Common root deleted or `~/.agents` link broken → relaxes and `hook-log` vanish silently | Medium | Medium | `common: absent` in every output; dotfiles doctor `grep -q overlay:`; ADR-0004 § 8 already accepts this trade for the interim, and the native read makes the failure rarer than a per-profile link |
| Precedence hides a common hardening behind a profile relax | Low | High | `shadows common:` provenance on every such entry; ticket 19's `bouncer-policy` asks on every edit of either layer; sealed rules when a non-owned layer exists |
| Double load during migration reads as "profile shadows everything" | High, transient | Low | realpath guard: profile layer skipped, doctor fails until the link is removed |
| Partial rejection leaves an inconsistent set (profile override of a dropped common rule) | Low | Medium | override resolution runs after the common layer is settled; unresolvable → profile layer rejected → baseline (fail-closed) |
| Baseline-id lint rule breaks an existing overlay | Low | Low | verified 2026-09-03: no common file reuses a baseline id (`hook-log` left the baseline at ticket 13) |

## Implementation plan

Tickets under `.scratch/bouncer/issues/` (split by the `to-tickets` pass).

### Phase 1 — engine: named layers
- [x] `loadPolicyFromLayers(layers)` next to `loadPolicyFromOverlayFiles`
      (which becomes the one-layer case); precedence per target; per-layer
      rejection; baseline-id lint; `LoadResult` carries per-layer state and
      layer-qualified `sourceFile`.
- [x] Tests, pure: every precedence target ×2 layers; rejection matrix
      (common broken / profile broken / both / override orphaned);
      baseline-id collision; intra-layer conflict unchanged.

### Phase 2 — adapter, outputs, docs
- [x] Shared helper for the common root (`~/.agents/bouncer/`, `HOME`-based
      so tests use a throwaway home); CC adapter reads two roots through
      one `readLayer(root)`; realpath migration guard.
- [x] `rules list` / `rules lint` / `doctor` formats above; audit-log
      `policy-warning` per layer.
- [x] `docs/reference/policy.md` (§ Baseline vs. overlay → three layers,
      § Merge order, § Cross-file conflicts → per layer, § Provenance),
      `docs/reference/cli.md` samples, `docs/how-to/wire-into-claude-code.md`.
- [x] End-to-end adapter tests: real dirs, throwaway `HOME` +
      `CLAUDE_CONFIG_DIR`, the symlinked-profile migration case.

### Phase 3 — ship (lead, announced step by step)
- [x] Rebuild grouped with ticket 16; reinstall `~/.local/bin/bouncer`
      (backup `bouncer.<sha>.bak`).
- [x] Both profiles: `rm` the `policy.d` link (an absent local `policy.d`
      is an empty layer); purge `policy.d.pre-mount.bak/` and
      `policy.toml.pre-19.bak`.
- [x] dotfiles, as a proposed patch for its lead: drop the `symlink`
      manifest entry (keep `binary` and the `command` lint check); amend
      ADR-0004 (option 4 delivered, § 3 and § 7).
- [x] Proof: `doctor` ×2 green with `common: 4 files, profile: 0 files`,
      51 effective rules, 5 relaxations, `rules list` provenance
      `[common:…]` on every overlay entry.

## Success metrics

- Both profiles: no symlink under `<configDir>/bouncer/`, doctor green,
  same counts as before the change (51 rules, 5 relaxations).
- A deliberately broken profile file leaves the common relaxations active
  (`rules list` still shows the five), and `doctor` names the profile file.
- `rules list` names a layer on every overlay-provenance line.

## References

- dotfiles `docs/adr/0004-bouncer-policy-overlays-partages.md` —
  interim mount, § 7 target constraints, § 8 broken-link verdict.
- `src/adapter/policy.ts`, `src/adapter/log-path.ts`, `src/policy/load.ts`.
- `docs/reference/policy.md` § Merge order, § Cross-file conflicts,
  § Provenance.
- Tickets 12 (policy file layout), 13 (baseline universality), 15
  (multi-harness adapters), 19 (policy self-protection).
- `.scratch/backlog.md` — cascade entry (per-project, sealed rules),
  `[[revoke]]`, provenance UX pass.

---

## History

| Date | Action | By |
|---|---|---|
| 2026-09-03 | Created, Accepted — decisions from the grilling session | Jonathan Robic |
