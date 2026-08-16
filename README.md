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
| `--rate-limit N` | Max requests per second (overrides `--stealth`) |
| `--verbose` | Full one-line-per-finding output (default is a compact summary) |
| `--min-severity S` | Only show findings >= `critical`/`high`/`medium`/`low` |
| `--enumerate M` | What to probe: `p` plugins, `t` themes, `u` users — combine letters (default `pt`) |
| `--max-requests N` | Cap on brute-force enumeration requests (default 500); enumeration stops once exceeded |
| `--output FILE` | Also write JSON results to `FILE` (the table still prints to stdout) |
| `--silent` | Suppress all progress output; only the result is printed |

Run `onyx` with no arguments for the full flag reference.

## How it works

1. Fetch the homepage, `/wp-login.php` and the REST API root. If nothing
   WordPress-ish comes back, it stops.
2. Walk the most vuln-heavy plugin and theme slugs from the database, fetch
   their `readme.txt` / `style.css`, and read the version out of it.
3. Enumerate users (`--enumerate u`): read `/wp-json/wp/v2/users` when it is
   open, then follow up to 10 `/?author=N` redirect chains to `/author/<slug>/`.
4. Compare each installed version against the affected ranges in the
   database, and report anything that matches.

Version detection is read-only — `onyx` never sends exploit payloads. If a
version can't be determined, it's reported as-is and skipped for matching,
so you don't get false positives from unknown installs.

During a scan a live progress line is rendered on stderr when you're in a
terminal (`[12/200] plugin:elementor readme.txt (3.24.0) | 2 findings |
1m20s elapsed`). When the output is piped or logged, no control characters
are emitted — just `[INF]` log lines. `--silent` disables progress
entirely, and stdout always carries only the results.

## The database

The feed comes from the Wordfence Intelligence Vulnerability Database,
which is licensed free for personal and commercial use, including
redistribution. The mirror lives in the
[`onyx-db`](https://github.com/Boreas37/onyx-db) repository, updated daily.
See its README for the license terms.

## Roadmap

- [x] `onyx update` wired to the GitHub Releases API (auto-updates on a missing database)
- [x] User enumeration via `--enumerate u`
- [x] `--max-requests` cap on brute-force enumeration
- [x] JSON output to a file with `--output FILE`
- [x] Live progress on a TTY with `--silent` to turn it off

## License

MIT for the code. The vulnerability data is Wordfence's, under their
Intelligence terms — see the `onyx-db` README.
