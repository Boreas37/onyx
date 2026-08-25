# Contributing to onyx

## Development Setup

```bash
git clone https://github.com/Boreas37/onyx && cd onyx
go build ./...          # stdlib-only, Go 1.23+
go vet ./...
go test -race ./...
```

The vulnerability DB is not bundled. Fetch it:

```bash
go run . update          # writes data/wordfence.json (+ .idx sidecar)
```

Or point any scan at a custom feed:

```bash
go run . scan https://example.com --db /path/to/feed.json --no-intel
```

## Project Layout

- `main.go`, `dbcmd.go`, `diffcmd.go`, `cachecmd.go`, `completion.go` — CLI wiring
- `internal/scanner/` — HTTP engine (detection, enumeration, brute force, pacing, 429 handling)
- `internal/db/` — Wordfence feed loader + gob index sidecar (`*.idx`)
- `internal/dbupdate/` — delta pipeline + minisign verification (BLAKE2b, Ed25519)
- `internal/report/` — table/json/sarif/csv/cyclonedx/markdown/html/junit/gitlab-sast renderers
- `internal/watch/`, `internal/intel/`, `internal/nuclei/`, `internal/pocs/` — supplemental

All packages are stdlib-only. No `go get` outside the toolchain.

## Testing

```bash
go test ./...                              # fast
go test -race ./...                        # with race detector
go test -run TestGoldenReportFormats -update ./internal/report/  # regen goldens
go test -run '^$' -fuzz FuzzWriteReportSafety -fuzztime 10s ./internal/report/
scripts/e2e.sh /tmp/onyx data/wordfence.json        # hermetic e2e
scripts/e2e-realwp.sh /tmp/onyx data/wordfence.json http://localhost:8080/  # needs docker mysql+WP
```

CI runs `ci` (build+vet+race), `e2e`, `e2e-realwp` (nightly), `fuzz`, `lint`, `release` (on `v*` tags) and the Homebrew tap refresh.

## Commit Style

Conventional commits (`fix:`, `feat:`, `docs:`, `chore:`, `perf:`). Keep PRs small and focused; include tests for parser/renderer changes and update goldens with `-update`.

## Release

```bash
# bump onyxVersion in main.go, then:
git tag vX.Y.Z && git push origin vX.Y.Z   # triggers .github/workflows/release.yml
gh workflow run update-formula.yml --repo Boreas37/homebrew-onyx
```
