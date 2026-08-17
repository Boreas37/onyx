# onyx — Software Bill of Materials (SBOM)

## Go runtime dependencies

`onyx` is a **stdlib-only** Go project: the build has **zero external Go
dependencies**. `go.mod` declares the module itself and nothing else.

```
module github.com/Boreas37/onyx

go 1.23
```

Every `crypto/`, `net/`, `encoding/`, `compress/`, `runtime/`,
`flag/`, `time/`, `os/` package used at compile time comes from the Go
standard library shipped with the toolchain named in `go.mod`.

Toolchain for release builds: **Go 1.23** (`.github/workflows/release.yml`,
`actions/setup-go@v5`). Developer builds use whatever `go` is on PATH —
for reproducibility the Go version of the release binary can be read from
`onyx version --json` (`go_version` field).

## Runtime data (not code)

The scanner does not bundle a database. At runtime it reads a local copy of
the **Wordfence Intelligence Vulnerability Database**, downloaded from the
`Boreas37/onyx-db` mirror (`onyx update`). That data is Wordfence's, under
the Wordfence Intelligence terms — see the `onyx-db` README. It is
redistributable for free personal and commercial use, but it is not part of
this SBOM's code inventory.

## Build and distribution tooling

These are build-time/CI tools, not runtime dependencies:

| Tool | Use | Where |
|---|---|---|
| Go toolchain (stdlib only) | compile the single static binary | everywhere |
| Docker / docker buildx | container image (`ghcr.io/boreas37/onyx`) | `.github/workflows/build-image.yml` |
| DDEV | not used in this repo (nothing here depends on it) | — |

No `curl | sh`, no package installers, no vendored third-party code.

## Build metadata

Release binaries embed their provenance via `-ldflags`:

```
-X main.buildCommit=<git sha>
-X main.buildTime=<RFC3339 build timestamp>
```

`onyx version --json` reports both, plus the Go version and target OS/arch:

```
{"version": "0.2.0", "go_version": "go1.23.4", "os": "linux", "arch": "arm64", "commit": "abcdef", "build_time": "2026-08-17T00:00:00Z"}
```

Local builds report `"commit": "unknown"` and `"build_time": "unknown"`.

## Supply-chain notes

- No external modules → no transitive dependency graph to audit.
- Release archives are checksummed (`checksums.txt`, `sha256sum`) and
  attached to the GitHub release; the Homebrew formula pins its archive by
  `sha256`.
- Signed SBOMs (e.g. SPDX + cosign) are future work, not present today.