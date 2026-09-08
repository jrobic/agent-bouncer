# Tune rules with audit

Goal: use the audit log to find rules that fire often (allowlist
candidates) and conditional rules that never fire (dead weight), and turn
that into policy changes — reviewed by hand, never applied automatically.

## Steps

1. The day after a ship, read the report for session traffic only:

   ```sh
   bouncer audit --days 7 --sessions-only
   ```

   The flag removes direct CLI checks and `run < file` probes before
   aggregation, so post-ship friction reflects hook traffic. Omit it when
   those probes belong in the audit.

   The report has three sections, in order:
   - **Frequent friction** — deny/ask clusters, most-fired first. Each
     line names the rule id, a fire count, a normalized command/path
     shape, and up to three example targets.
   - **Conditional rules that fired** — a declarative git-conditional
     table entry (`docs/reference/policy.md`'s `ask_flags` /
     `safe_first_arg` / `safe_grammar`) that produced a silent allow at
     least once. Proof it's earning its keep.
   - **Dead conditional rules** — declared, never fired in the window. A
     candidate for removal, not for automatic action.

2. Generate candidate overlay snippets for the friction section:

   ```sh
   bouncer audit --days 7 --sessions-only --suggest
   ```

   Output is TOML, one `[[relax]]` or `[[override]]` block per frequent
   rule that has a known policy lever, each with an auto-filled `reason`
   citing the count/shape/window that produced it. A rule with no lever
   (e.g. `rm-rf-dangerous`, `sudo` — see
   `docs/how-to/override-a-baseline-rule.md`'s non-override-able list)
   gets a `#`-comment instead, telling you to review manually.

   A relaxation targeting `command.git.safe_subcommands` (from
   `git-protected` friction) ships **commented out**, unlike every other
   suggestion:

   ```toml
   # The block below is commented out: relaxing "command.git.safe_subcommands" for "push" disables ALL grammar checks for that subcommand, not only the audited shape.
   # [[relax]]
   # list = "command.git.safe_subcommands"
   # value = "push"
   # reason = "UNCOMMENT ONLY AFTER REVIEWING: allows EVERY git push form without confirmation, including --force — not just the audited shape. audit: rule \"git-protected\" fired 2x on shape git push <arg> <arg> in the last 30d — review before keeping"
   ```

   That list affects the whole Git subcommand, not just the audited
   shape. MCP suggestions instead use `mcp_write.allowed_tools` with
   the full audited name, leaving other servers and suffix neighbours
   unchanged. Regex-rule suggestions apply to the entire rule; inspect
   its scope before copying.

3. Read every suggestion before touching your overlay. `--suggest` never
   writes to `<configDir>/bouncer/policy.toml` or any other file — it
   only prints to stdout.

4. Copy the blocks you actually want into your overlay by hand. Uncomment
   a `command.git.safe_subcommands` block only after you've accepted the
   full-subcommand scope stated in its reason.

5. Re-lint:

   ```sh
   bouncer rules lint
   ```

## Verify

- `bouncer audit --days 7 --sessions-only --suggest`'s output, pasted as-is
  into a scratch overlay, passes `bouncer rules lint` with `lint: OK` — every
  emitted block (commented or not) is valid TOML.
- After copying a block into your real overlay: `bouncer rules list`
  shows it (`override ...` or `overlay-relax ...`), and a commented git
  block you did NOT uncomment shows nothing for that subcommand.
- No file under `<configDir>/bouncer/` changes as a result of running
  `audit` or `audit --suggest` alone.

---
Source: src/adapter/audit.ts, src/cli-commands.ts
