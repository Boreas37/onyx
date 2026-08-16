# onyx

A WordPress vulnerability scanner that runs entirely offline. It reads a local
copy of the Wordfence Intelligence database, checks your target's plugins and
themes, and tells you what's known-vulnerable. No API calls, no accounts, no
cloud service. The database is just a file on disk.

## Why

WPScan is the usual answer here, but it leans on a paid API for the database.
The Wordfence feed itself is free for commercial use, so there's no reason the
scanner can't ship with the data bundled. `onyx` treats the vulnerability
database like a dependency: download it once, update it when you feel like it,
scan as many sites as you want.

## Install

```bash
go install github.com/Boreas37/onyx@latest
```

That puts `onyx` in `$(go env GOPATH)/bin`. Make sure that's on your PATH.
No runtime deps, one binary.

## Usage

First, get the database:

```bash
onyx update
```

This downloads the latest compressed feed from the `onyx-db` repository and
unpacks it to `data/wordfence.json` (creating the directory if needed).

Then scan a site:

```bash
onyx scan https://example.com
```

### Flags

| Flag | What it does |
|---|---|
| `--db PATH` | Use a different database file (default `data/wordfence.json`) |
| `--threads N` | Concurrent requests (default 5) |
| `--timeout S` | Per-request timeout (default 10s) |
| `--json` | Machine-readable output |
| `--api` | Only query the REST API, skip brute-force enumeration |
| `--stealth` | One request per second, for noisy environments |

## How it works

1. Fetch the homepage, `/wp-login.php` and the REST API root. If nothing
   WordPress-ish comes back, it stops.
2. Walk the most vuln-heavy plugin and theme slugs from the database, fetch
   their `readme.txt` / `style.css`, and read the version out of it.
3. Compare each installed version against the affected ranges in the
   database, and report anything that matches.

Version detection is read-only — `onyx` never sends exploit payloads. If a
version can't be determined, it's reported as-is and skipped for matching,
so you don't get false positives from unknown installs.

## The database

The feed comes from the Wordfence Intelligence Vulnerability Database,
which is licensed free for personal and commercial use, including
redistribution. The mirror lives in the
[`onyx-db`](https://github.com/Boreas37/onyx-db) repository, updated daily.
See its README for the license terms.

## Roadmap

- `onyx update` currently needs wiring to the GitHub Releases API (the
  database is already mirrored; the download code is a stub).
- Per-plugin rate limiting and resume for interrupted scans.
- Output formats beyond table and JSON.

## License

MIT for the code. The vulnerability data is Wordfence's, under their
Intelligence terms — see the `onyx-db` README.
