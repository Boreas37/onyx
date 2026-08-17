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
No runtime deps, one binary. Docker image is also published:
`docker pull ghcr.io/boreas37/onyx:latest`.

## Usage

First, get the database:

```bash
onyx update
```

This downloads the latest compressed feed from the `onyx-db` repository and
unpacks it to `data/wordfence.json` (creating the directory if needed). If the
database is missing, `scan` fetches it automatically before starting.

Then scan a site:

```bash
onyx scan https://example.com
```

### Common flags

| Flag | What it does |
|---|---|
| `--db PATH` | Use a different database file (default `data/wordfence.json`) |
| `--threads N` | Concurrent requests (default 5) |
| `--enumerate M` | What to probe: `p` plugins, `t` themes, `u` users, `m` media — combine letters (default `pt`) |
| `--detection-mode M` | `passive`, `aggressive`, or `mixed` (default: mixed) |
| `--min-severity S` | Only show findings >= `critical`/`high`/`medium`/`low` |
| `--format F` | Output format: `table`, `json`, `jsonl`, `sarif` (default: table) |
| `--rate-limit N` | Max requests per second |
| `--stealth` | One request per second + random user agent |
| `--user-agent S` | Set a fixed User-Agent header |
| `--random-user-agent` | Rotate a random browser UA per request |
| `--proxy URL` | Route requests through an HTTP proxy |
| `--checks LIST` | Extra checks: `cb` config backups, `dbe` db exports, `timthumb` |
| `--max-requests N` | Cap on brute-force enumeration requests (default 500) |
| `--max-scan-duration D` | Stop after a duration (`30s`, `5m`) and report partial results |
| `--cache-ttl H` | Cache HTTP responses on disk for H hours |
| `--output FILE` | Also write JSON results to `FILE` (table still prints to stdout) |
| `--config FILE` | Load defaults from a JSON config file (CLI flags win) |
| `--silent` | Suppress progress output; only the result is printed |

Run `onyx` with no arguments for the full flag reference.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished, no vulnerable components found |
| `5` | Vulnerabilities found |
| `2` | Error (bad URL, unreachable target, missing DB) |

## How it works

1. Fetch the homepage, `/wp-login.php` and the REST API root. If the target
   can't be reached at all, it stops with an error (exit 2).
2. **Passive detection:** scan the homepage HTML for `wp-content/plugins/…`
   and `wp-content/themes/…` references — anything the page mentions gets
   checked, with no extra requests (same trick WPScan uses).
3. **Aggressive enumeration:** walk the most vuln-heavy plugin and theme
   slugs from the database (top 200 by default, raise with
   `--max-requests`), fetch their `readme.txt` / `style.css`, and read the
   version out of it. Supply your own lists with `--plugins-list FILE` /
   `--themes-list FILE`.
4. Enumerate users (`--enumerate u`): read `/wp-json/wp/v2/users` when it's
   parseable, then walk `/?author=N` redirect chains to `/author/<slug>/`,
   including subdirectory multisite installs (`/blog/author/<slug>/`).
5. Probe for interesting leftovers: `robots.txt`, `readme.html`, `debug.log`,
   `xmlrpc.php`, upload directory listing, `wp-config.php.bak`,
   `wp-includes/version.php`. Optional `--checks cb,dbe,timthumb` digs for
   config backups and database dumps.
6. Compare each installed version against the affected ranges in the
   database, and report anything that matches.

Version detection is read-only — `onyx` never sends exploit payloads. If a
version can't be determined, it's reported as-is and skipped for matching,
so you don't get false positives from unknown installs.

Rate limiting is handled in two layers: your own `--rate-limit` / `--stealth`
throttle, and automatic detection of HTTP 429 responses. When the target rate
limits you, onyx backs off exponentially (1s → 2s → … → 30s), counts the
hits, and reports them in the result as `rate_limit_hits` so you know the
scan may be incomplete.

During a scan a single live progress line renders on stderr in a terminal
(`[##########----------] 50% 252/500 12s`). When output is piped or logged,
no control characters are emitted — just `[INF]` log lines. `--silent`
disables progress entirely; stdout always carries only the results.

## The database

The feed comes from the Wordfence Intelligence Vulnerability Database,
which is licensed free for personal and commercial use, including
redistribution. The mirror lives in the
[`onyx-db`](https://github.com/Boreas37/onyx-db) repository, updated daily.
See its README for the license terms.

## Roadmap

- [x] `onyx update` wired to the GitHub Releases API (auto-updates on a missing database)
- [x] User enumeration via `--enumerate u` (incl. subdirectory multisite)
- [x] Passive + aggressive detection modes (`--detection-mode`)
- [x] JSON / JSONL / SARIF output (`--format`, `--stream`)
- [x] WAF evasion: custom / random user agents, proxy support
- [x] Rate limiting + automatic 429 backoff
- [x] Config backup / DB export / timthumb checks
- [x] HTTP response cache (`--cache-ttl`)
- [x] Scan time limit (`--max-scan-duration`)
- [x] Config file support (`--config`)
- [x] Machine-readable exit codes (0 / 5 / 2)

## License

MIT for the code. The vulnerability data is Wordfence's, under their
Intelligence terms — see the `onyx-db` README.
