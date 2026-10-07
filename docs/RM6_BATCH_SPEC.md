# onyx RM6 — Batch / multi-target scanning

Repo: `/home/boreas/projects/onyx` — Go, module `github.com/Boreas37/onyx`, **stdlib only (no new dependencies)**.
Toolchain: `export PATH="/usr/local/go/bin:$PATH"` → go 1.23.4 (the `go` in /usr/bin is 1.19 and MUST NOT be used).
Platform: Raspberry Pi 5, linux/arm64.

Prerequisite: **every existing feature keeps working.** In single-target mode the
stdout/stderr output and the JSON/CSV/SARIF/table shapes must stay **byte-identical**
to the current build. Baseline binary for regression diffing: `./onyx` in the repo
root (the current 0.2.x build) — build the new one to a different path and `diff` outputs.

Implement ONLY the 5 features below. Do not refactor unrelated code, do not touch
`internal/db`, `internal/nuclei`, `internal/pocs` semantics, and do NOT modify
anything under `/home/boreas/projects/CVE-PoC-Tracker` (another worker owns it).

## 1. Target list input

- `onyx scan --input FILE`: FILE is a text file with one target per line.
  - `#` comment lines and blank lines ignored; CRLF tolerated; leading/trailing whitespace trimmed.
  - Bare hostnames get `https://` (e.g. `example.com` → `https://example.com`); explicit `http://` / `https://` respected.
  - Dedupe by normalized host (case-insensitive, trailing slash ignored) — keep first occurrence.
  - Hard cap 5000 targets → clear usage error above that.
- Multiple positional targets also work: `onyx scan a.com b.com c.com`.
- `--input` and positional targets may be combined; dedupe across both.
- Single positional target keeps today's behavior exactly (this is the regression-critical path).

## 2. Batch execution

- New flag `--host-concurrency N` (default **2**, min 1, max 16): how many hosts are
  scanned in parallel. Each host keeps its own `--threads`, `--rate-limit`,
  `--max-requests` and `--max-scan-duration` semantics — these are **per host**
  (document this in the README flags table).
- The vulnerability DB is loaded **once per batch**, not once per host. Same for the
  PoC tracker index (`--poc-tracker-dir`). Reloading a ~151 MB DB per host is a bug.
- Isolation: a host that fails (DNS, TLS, timeout, not-WordPress, connection refused)
  must not stop the batch. Record it as a failed target with the reason.
- Ctrl-C stops cleanly and still prints the summary of hosts already finished.

## 3. Batch output & progress

- Progress stays **one** `\r`-updated stderr line (TTY only, zero output when piped,
  `--silent` disables): `[####------] 40% 4/10 hosts 38s`.
- One compact line per finished host, to stderr: `[4/10] example.com  ok  7 findings (2 critical)  12.3s`.
  No per-finding flood — that stays behind `--verbose`.
- End-of-batch summary on stdout for table/cli-no-colour formats: total targets,
  ok/failed counts, findings by severity, and the 5 worst hosts (host, critical count, total).
- `--format json` in batch mode (>1 target): one document
  `{"targets":[{"target","ok","error"?,"findings":[...],"stats":{...}}],"summary":{"targets","ok","failed","findings_by_severity","duration_s"}}`.
  Single-target JSON output must remain exactly as it is today.
- `--format csv` in batch mode: prepend a `target` column (first column), one row per
  vulnerability across all hosts.
- `--format sarif` in batch mode: one SARIF log with one run per host (single-target SARIF unchanged).
- `--output-dir DIR`: per-host `<host>.json` files (single-target JSON shape) plus
  `DIR/batch-summary.json`. Create the directory if missing.
- `--output FILE` in batch mode writes the aggregate document to FILE.

## 4. Exit codes

- `0` — at least one target scanned successfully (findings do not change the code).
- `1` — every target failed.
- `2` — usage error (bad flags, empty target list).

## 5. Docs, usage, version

- New flags added to `usage()` keeping the existing alignment/format.
- README: new "Batch scanning" section with a copy-pasteable example, flags-table rows,
  and an explicit note that rate limits / request caps / timeouts are per host.
- Bump the version const to `0.3.0` and update README version mentions.

## Tests — real, executed, output pasted as evidence

Unit tests (new file(s), stdlib only):
- list parsing: comments, blanks, CRLF, dedupe, scheme defaulting, >5000 → error
- host concurrency bound respected (never more than N hosts in flight)
- isolation: one unreachable target does not prevent other targets from being scanned
- exit-code rules (all-failed → 1, mixed → 0, usage → 2)
- csv target column, batch JSON shape, SARIF run count == host count

End-to-end with the real binary (not `httptest` only):
- Start 3 local static servers (`python3 -m http.server` on 3 ports): at least one serving a
  fake WordPress tree (`wp-content/plugins/<slug>/` where `<slug>` exists in the local DB at
  `data/wordfence.json` with a version range that matches what you serve) and one serving
  plain HTML. Add a 4th target that is a dead port (`http://127.0.0.1:1`).
- Run `./onyx-new scan --input targets.txt --host-concurrency 3 --format json --silent`
  and prove: 3 ok + 1 failed, findings attributed to the correct host, exit code 0.
- Regression proof: run the OLD `./onyx` and the NEW binary on the same single target and
  `diff` the outputs — must be identical (paste both commands and the diff result).

Full gate (paste the real output):
```
export PATH="/usr/local/go/bin:$PATH"
cd /home/boreas/projects/onyx
go build ./... && go vet ./... && go test ./...
```

## Commit & push

- Author: `Boreas37 <hamzacagrici@gmail.com>` (real identity, never anonymous).
- Commit message: `feat: batch scanning — target lists, host concurrency, aggregate output (RM6)`
- Also commit the currently untracked roadmap specs in the same push:
  `docs/RM2_WAF_SPEC.md`, `docs/RM3_DATA_SPEC.md`, `docs/RM4_OUTPUT_SPEC.md`, `docs/RM5_PACKAGING_SPEC.md`
  (separate commit `docs: roadmap specs RM2–RM5` is fine).
- `git push origin main`, then **verify on the remote** (`git log --oneline origin/main -2`).
- Never commit the built binaries (`onyx` is gitignored — keep it that way).

## Report back

Return: the exact commands you ran with their real output (build/vet/test, the e2e batch run,
the regression diff), the commit SHA confirmed on the remote, the new flag list, and anything
you deliberately left out. Never claim something works that you did not actually run.
