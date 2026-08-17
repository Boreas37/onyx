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
| `--nuclei` | Verify findings against projectdiscovery templates (needs the nuclei binary) |
| `--output FILE` | Also write JSON results to `FILE` (table still prints to stdout) |
| `--config FILE` | Load defaults from a JSON config file (CLI flags win) |
| `--silent` | Suppress progress output; only the result is printed |

Run `onyx` with no arguments for the full flag reference.

### Nuclei verification pipeline

Like RustScan's `--nmap` flag, `--nuclei` chains a second tool onto the scan:

```bash
onyx scan https://example.com --nuclei
```

1. onyx runs its normal scan and collects the CVE IDs from its findings.
2. For each CVE it looks up the matching template in the local
   projectdiscovery templates clone (`~/nuclei-templates` or
   `$NUCLEI_TEMPLATES_DIR`, override with `--nuclei-template-dir`).
3. All found templates are fired at the target with the nuclei binary; every
   match is parsed and shown under a "Nuclei verification" section.
4. When a CVE gets confirmed by nuclei, onyx also pulls up to **5 most-starred
   PoC repositories** from the local [`CVE-PoC-Tracker`](https://github.com/Boreas37/CVE-PoC-Tracker)
   clone (`~/projects/cve-tracker` or `$POC_TRACKER_DIR`), plus a link to the
   tracker itself.

The whole chain degrades gracefully: missing nuclei binary, missing template,
or missing tracker clone only print a `[WARN]` and the scan still completes.

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

Continuous development — next up, in rough order:

- **Exploit-oriented checks**: wp-login brute force (`--passwords` /
  `--usernames`), XML-RPC multicall password attack, authenticated REST
  inventory via application passwords (`--wp-auth`).
- **WAF and evasion hardening**: SOCKS5 proxy support, TLS fingerprint
  rotation, per-host rate limiting, `--proxy-target-only` style scoping.
- **Data layer**: scanner-feed support (broader, noisier detections),
  incremental DB updates with checksum, `--no-update` and staleness prompts.
- **Output**: CSV and color-free `cli-no-colour` formats, scan summary
  statistics (request counts, duration, coverage).
- **Packaging**: GitHub Actions release workflow for binaries, Homebrew tap,
  `go install` version pinning, signed SBOM.
- **Community**: plugin/theme slug contribution workflow, template
  pre-registration, issue templates.

## License

MIT for the code. The vulnerability data is Wordfence's, under their
Intelligence terms — see the `onyx-db` README.
