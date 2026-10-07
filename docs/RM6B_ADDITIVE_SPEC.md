# onyx — RM6 additive port onto v1.1.1 main (multi-target output & UX)

## Situation (verified)

The RM6 batch work was implemented against a **stale local base** (`9710f24`, v0.2.x) and is
preserved on the remote branch `rm6-batch-scanning` = `51c9a40`. Meanwhile `origin/main` is a
**different, far newer lineage** (v1.1.1, 124 commits, head `24153ec`) that already ships its own
multi-target design:

- `-T, --targets FILE` and `--jobs N`, `runMulti()` in `main.go`
- multi-target `--format` is restricted to `table`, `cli-no-colour`, `jsonl`, `csv` (json/sarif
  are rejected with a usage error), exit code = worst per-target code (via the `rank()` helper)
- concurrent mode prints an interleaved `=== [i/n] target ===` stderr header per target

So most of RM6 is **superseded**. Do not merge it wholesale and do not rebase it as-is.

## Your job

Port ONLY the capabilities main lacks, as an **additive** change on top of `origin/main`,
preserving every existing contract.

**Work in a separate clone** so you never collide with the worker fixing `main` in
`/home/boreas/projects/onyx` (they are repairing `dbcmd.go` + CI there — do not touch that clone):

```
git clone git@github.com:Boreas37/onyx.git /home/boreas/projects/onyx-rm6
cd /home/boreas/projects/onyx-rm6
git checkout -b rm6-additive origin/main
```
Toolchain: `export PATH="/usr/local/go/bin:$PATH"` → go 1.23.4 (the `go` in /usr/bin is 1.19, never use it). Pi 5, linux/arm64, ~15 GB free disk.

Copy this spec into the clone as `docs/RM6B_ADDITIVE_SPEC.md` and commit it with your work.

### Non-negotiable compatibility rules

- `-T/--targets` and `--jobs` stay the **canonical** flags. Add `--input FILE` only as a
  documented **alias** for `-T`.
- **Do not change the exit-code contract**: keep `runMulti`'s existing worst-code aggregation.
- Single-target behaviour must stay **byte-identical** (stdout/stderr/shapes) — prove it with a
  diff against the pre-change binary (build the base binary first and keep it).
- Stdlib only, no new dependencies. No changes to `internal/scanner` detection semantics.

### Features to add

1. **Aggregate output for multi-target** (today `--format json` / `sarif` are rejected for >1 target):
   - `--format json` with multiple targets → ONE document:
     `{"targets":[{"target","ok","error"?,"findings":[...],"stats":{...}}],"summary":{"targets","ok","failed","findings_by_severity","duration_s"}}`.
     Field names above are pinned; per-target `findings` keep the existing single-target finding shape.
   - `--format sarif` with multiple targets → ONE SARIF log, one `run` per host, host in the run name.
   - Single-target `json`/`sarif` output stays exactly as it is today.
2. **`--output-dir DIR`**: writes `<host>.json` per target (existing single-target JSON shape) plus
   `DIR/batch-summary.json` (the aggregate summary). Create the directory if missing; host names
   sanitised for the filesystem (ports/colons safe). `--output FILE` keeps working and, in
   multi-target mode, writes the aggregate document.
3. **Concurrent output hygiene** (the current interleaved `=== [i/n] ===` headers are unreadable
   when `--jobs > 1`):
   - One `\r`-updated progress line on stderr: `[####------] 40% 4/10 hosts 38s`, thread-safe,
     throttled (~12 redraws/s), TTY-only (prints nothing when piped), disabled by `--silent`.
   - One compact line per finished target on stderr:
     `[4/10] example.com  ok  7 findings (2 critical)  12.3s` (or `failed: <reason>`).
   - Keep the old section headers available behind `--verbose`.
   - No per-finding flood outside `--verbose` (user requirement).
4. **Verify the DB is loaded once per batch** (not per target) in `runMulti`, same for the PoC
   tracker index. If main already does this, say so in your report with the code reference;
   if not, fix it.
5. **Per-target isolation** in concurrent mode: one dead/unreachable target must not stop or
   corrupt the others (including their output attribution).

### Tests (real, executed)

- Unit: aggregate JSON shape, SARIF run count == target count, `--output-dir` file set,
  progress/piped-output silence, `--input` alias parsing, isolation with an unreachable target,
  and that the exit-code aggregation is unchanged.
- E2E with the real binary: 3 local `python3 -m http.server` targets (at least one serving a fake
  WordPress tree whose plugin slug+version exists in the local DB) + 1 dead port
  (`http://127.0.0.1:1`); run with `-T targets.txt --jobs 3 --format json` and prove correct
  attribution, `ok:3, failed:1`, and a sane exit code. Paste the real JSON summary.
- Regression: old binary vs new binary on one target — outputs identical (paste the diff).
- Gate: `go build ./... && go vet ./... && go test -race ./...`.
  NOTE: `TestRunDBSubcommands` (root package) fails on the current `main` base — that is a known
  unrelated bug being fixed in parallel by another worker. Do NOT fix it yourself; confirm it is
  the ONLY failure and say so explicitly. Everything else, including your new tests, must pass.
  (`internal/scanner` takes ~150 s without `-race`; be patient.)

### Docs & delivery

- Update `README.md` (new section for the aggregate output + `--output-dir`, flags table, the note
  that rate limits / request caps / timeouts are per target), `usage()`, and `CHANGELOG.md`.
- Commit as `Boreas37 <hamzacagrici@gmail.com>`; message
  `feat(cli): aggregate multi-target output, --output-dir, batch progress (RM6 additive)`.
- Push the branch and **open a PR** against `main` (`gh pr create --base main --head rm6-additive`)
  with a body stating: what was ported from `rm6-batch-scanning`, what was deliberately dropped as
  superseded, and that it is blocked on the `dbcmd`/CI fix for a fully green `-race` run.
  Do NOT merge the PR and do NOT push to `main`.

## Report back
Real commands with real output (gate, e2e run, regression diff), the branch name + PR URL, the
commit SHA, what you dropped as superseded, and the exact list of any test failures that are not yours.
