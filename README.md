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

On macOS (or Linux) with Homebrew, from the onyx tap:

```bash
brew tap Boreas37/homebrew-onyx
brew install onyx
```

(The tap repo is pending — the formula template lives in `docs/homebrew/`.)

Release builds embed build metadata, visible via `onyx version --json`
(commit SHA, build time, Go version, target OS/arch). See
[`docs/SBOM.md`](docs/SBOM.md) for the supply-chain notes.

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
| `--passwords FILE` | Wordlist of passwords (one per line) — enables the wp-login brute force (needs `--usernames FILE` or `--enumerate u`) |
| `--usernames FILE` | Wordlist of usernames (one per line) for brute-force attacks |
| `--user USER` | Single username for the XML-RPC multicall attack (`--xmlrpc-brute`) |
| `--xmlrpc-brute FILE` | XML-RPC multicall password attack (`wp.getUsersBlogs`; needs `--usernames FILE` or `--user USER`) |
| `--multicall-max-passwords N` | Passwords per XML-RPC multicall request (default 3) |
| `--wp-auth USER:PASS` | Authenticated REST inventory over HTTP Basic auth — use a WordPress Application Password (create one in wp-admin → Users → Profile → Application Passwords) |
| `--no-brute` | Disable credential brute force (wp-login and XML-RPC) |
| `--input FILE` | Batch: scan every target in `FILE` (one per line; blank lines and `#` comments ignored) |
| `--host-concurrency N` | Batch: hosts scanned in parallel (default 2, max 16) — `--threads`, `--rate-limit`, `--max-requests` and `--max-scan-duration` are **per host** |
| `--output-dir DIR` | Batch: write a `<host>.json` per target plus `DIR/batch-summary.json` |
| `--silent` | Suppress progress output; only the result is printed |

Run `onyx` with no arguments for the full flag reference.

### Batch scanning

Scan many hosts in one run — from a file, from positional arguments, or both:

```bash
onyx scan --input targets.txt --host-concurrency 4 --format json
onyx scan https://a.example https://b.example --output-dir results/
```

`targets.txt` holds one target per line: blank lines and `#` comments are
ignored, CRLF is tolerated, bare hostnames get an `https://` scheme, and the
list is deduplicated by host (max 5000).

- The vulnerability database is loaded **once per batch**, not once per host
  (same for the PoC tracker index) — reloading the ~151 MB feed for every
  target would be a bug.
- `--host-concurrency N` (default **2**, range 1–16) sets how many hosts run at
  once. Every other budget flag — `--threads`, `--rate-limit`,
  `--per-host-rate-limit`, `--max-requests` and `--max-scan-duration` — is
  **applied per host**, so each target keeps its own request cap and pacing.
- A host that fails (DNS, TLS, timeout, connection refused, out of scope) is
  recorded as a failed target with its reason and the batch keeps going.
  Ctrl-C stops dispatching new hosts and still prints the summary of the hosts
  that already finished.
- Progress is a single `\r`-updated stderr line plus one compact
  line per finished host (`[4/10] example.com  ok  7 findings (2 critical)  12.3s`).
  Both are drawn **only in a terminal** and disabled by `--silent`; a piped run
  writes nothing to stderr. Per-finding output stays behind `--verbose`.
- Output: the table formats print an end-of-batch summary (totals, ok/failed,
  findings by severity, the 5 worst hosts); `--format json` emits one aggregate
  document `{"targets":[…],"summary":{…}}`; `--format csv` prepends a `target`
  column; `--format sarif` emits one run per host; `--output-dir DIR` writes a
  `<host>.json` per target plus `DIR/batch-summary.json`; `--output FILE`
  writes the aggregate document to `FILE`.
- In batch mode the exit code is `0` when at least one target was scanned, `1`
  when every target failed, and `2` for a usage error (bad flags, empty list).
  Single-target exit codes (`0`/`5`/`2`) are unchanged.

Two deliberate decisions from the RM6 spec: a reachable target that is **not**
WordPress is recorded as `ok:true` (it was scanned, just not WordPress) with
zero findings — only unreachable/unscannable targets are `failed`; and
deduplication keys on the lowercased host, so `example.com`, `EXAMPLE.com/` and
`https://example.com` collapse to the first occurrence. The version bump to
`0.3.0` changes only the version string in the table banner and the SARIF
`driver.version` — single-target JSON, CSV, JSONL and the table body are
byte-identical to `0.2.x`.

### Exploit-oriented checks

Beyond read-only version detection, `onyx` can actively verify credentials —
only against targets you own:

- **wp-login brute force** — `--passwords FILE` together with `--usernames
  FILE` (or the users found via `--enumerate u`) tries every pair against
  `/wp-login.php`. A 302 redirect to `wp-admin` marks a valid credential.
  Paced at 1 request/second unless `--rate-limit` is set; disable with
  `--no-brute`.
- **XML-RPC multicall attack** — `--xmlrpc-brute FILE` tries the password
  list against `xmlrpc.php` using `system.multicall` `wp.getUsersBlogs`
  calls, 3 passwords per request (`--multicall-max-passwords N`), which
  keeps the request count low. Needs `--usernames FILE` or a single
  `--user USER`, and only runs when the xmlrpc.php ping check succeeded.
- **Authenticated REST inventory** — `--wp-auth USER:PASS` lists the
  installed plugins and themes through `/wp-json/wp/v2/{plugins,themes}`
  over HTTP Basic auth and feeds them straight into the database matching.
  Passwords contain a colon, so use a WordPress Application Password
  (create one in wp-admin → Users → Profile → Application Passwords). Invalid
  credentials print a `[WARN]` and the scan continues.

Valid credentials show up under `login_brutes` in the JSON output and a
"Valid credentials:" section in the table.

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
| `5` | Vulnerabilities found (single-target) |
| `2` | Error (bad URL, unreachable target, missing DB, usage error) |
| `1` | Batch only: every target failed (batch success is `0`, and findings do not change the code) |

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
disables progress entirely; stdout always carries only the results. In batch
mode the progress bar and the per-host completion lines are drawn only in a
terminal, so a piped batch writes nothing to stderr at all — the aggregate
result on stdout is the whole story.

## The database

The feed comes from the Wordfence Intelligence Vulnerability Database,
which is licensed free for personal and commercial use, including
redistribution. The mirror lives in the
[`onyx-db`](https://github.com/Boreas37/onyx-db) repository, updated daily.
See its README for the license terms.

## Roadmap

Continuous development — next up, in rough order:

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
