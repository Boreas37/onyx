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

On macOS (or Linux) with Homebrew:

```bash
brew tap Boreas37/onyx https://github.com/Boreas37/homebrew-onyx
brew install Boreas37/onyx/onyx
```

The tap tracks the latest release; a daily job refreshes the formula.

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
| `--enumerate M` | What to probe: `p`/`vp`/`ap` plugins, `t`/`vt`/`at` themes, `u` users, `m` media — comma-separated (default `pt`; `vp`/`vt` probe vulnerable components without the popular-seed lists) |
| `--detection-mode M` | `passive`, `aggressive`, or `mixed` (default: mixed) |
| `--min-severity S` | Only show findings >= `critical`/`high`/`medium`/`low` |
| `--format F` | Output format: `table`, `json`, `jsonl`, `sarif`, `csv`, `cyclonedx`, `markdown`/`md`, `html`, `junit` (default: table) |
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
| `--config FILE` | Load defaults from a JSON config file (CLI flags win). Without `--config`, onyx auto-discovers `$XDG_CONFIG_HOME/onyx/scan.json`, `~/.config/onyx/scan.json` and `./onyx.json` (first match) |
| `--profile NAME` | Named preset: built-ins `stealth`, `aggressive`, `fast`, or a custom file in `~/.onyx/profiles/NAME.json`. Applied after `--config`; explicit CLI flags still win |
| `--passwords FILE` | Wordlist of passwords (one per line) — enables the wp-login brute force (needs `--usernames FILE` or `--enumerate u`) |
| `--usernames FILE` | Wordlist of usernames (one per line) for brute-force attacks |
| `--user USER` | Single username for the XML-RPC multicall attack (`--xmlrpc-brute`) |
| `--xmlrpc-brute FILE` | XML-RPC multicall password attack (`wp.getUsersBlogs`; needs `--usernames FILE` or `--user USER`) |
| `--multicall-max-passwords N` | Passwords per XML-RPC multicall request (default 3) |
| `--wp-auth USER:PASS` | Authenticated REST inventory over HTTP Basic auth — use a WordPress Application Password (create one in wp-admin → Users → Profile → Application Passwords) |
| `--no-brute` | Disable credential brute force (wp-login and XML-RPC) |
| `--strict-wp` | Exit `3` when the target does not look like WordPress (default: warn, exit `0`) |
| `--crawl-pages N` | Fetch N pages from the target's sitemap and mine them for plugin/theme references + `?ver=` versions (default 0 = off) |
| `-T FILE`, `--targets FILE` | Scan many sites sequentially (one URL per line, `#` comments). Extra URLs can also be passed positionally. Exit code aggregates: any hard failure → `2`, else any findings → `5`. Formats that cannot be concatenated (`json`, `sarif`, `cyclonedx`) require a single target |
| `--fail-on SEV` | Exit `5` only when a finding is `SEV` or worse (`critical`/`high`/`medium`/`low`); default: any finding. Nuclei-verified hits always exit `5` |
| `--no-intel` | Skip EPSS / CISA KEV enrichment (enabled by default; findings are annotated and sorted by exploitation priority) |
| `--fingerprint-db FILE` | JSON table of static-file MD5 hashes → WordPress versions, used as a core-version fallback when meta/RSS/OPML yield nothing |
| `--no-popular` | Do not append the built-in popular plugin/theme slug lists during aggressive enumeration |
| `--allow-foreign-redirect` | Follow HTTP redirects to hosts other than the scanned target (default: blocked — SSRF hardening) |
| `--retries N` | Retry transient network errors N times with exponential backoff + jitter (default 2, `0` disables) |
| `--jobs N` | Scan `-T`/extra targets with up to N concurrent scans (default 1 = sequential; output order may vary) |
| `--no-discover-404` | Do not probe a nonexistent path for plugin/theme references |
| `--fail-on-rate-limited` | Exit `4` when the target's 429 throttling cut the scan short (CI: incomplete != clean) |
| `--nuclei-min-severity S` | Only run nuclei templates of `S` or worse (`critical`/`high`/`medium`/`low`/`info`) |
| `--outputs LIST` | Write extra report copies (`json,sarif,html,...`) as `<output>.<format>` files |
| `--basic-auth USER:PASS` | HTTP Basic credentials for protected targets |
| `--cookie "k=v; ..."` | Session cookie header for login-walled pages |
| `--headers "Name: value, ..."` | Extra request headers (comma-separated) |
| `--vhost HOST` | Override the Host header (shared-hosting scans) |
| `--force` | Scan even when the target shows no WordPress fingerprints |
| `--exclude-vulns LIST` | Drop findings with these vulnerability IDs (comma-separated) |
| `--wp-version X.Y.Z` | Skip version detection and report this core version (e.g. when meta tags are stripped) |
| `--silent` | Suppress progress output; only the result is printed |

Run `onyx` with no arguments for the full flag reference.

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
| `0` | Scan finished, no qualifying vulnerable components found |
| `4` | Scan cut short by the target's rate limiting (only with `--fail-on-rate-limited`) |
| `5` | Vulnerabilities found (with `--fail-on SEV`: at least one at `SEV` or worse) |
| `3` | Target does not look like WordPress (only with `--strict-wp`) |
| `2` | Error (bad URL, unreachable target, missing DB) |

By default a non-WordPress target is reported ("does not look like
WordPress") and the scan exits `0`. Pass `--strict-wp` to make that case a
distinct failure (`3`) — useful in CI so a misconfigured URL doesn't read as
a clean pass.

## Inspecting the local database

    onyx db stats                     # record counts by type, freshness
    onyx db lookup contact-form-7     # all recorded vulns for one slug, most severe first
    onyx db top 20                    # most vulnerable slugs in the feed
    onyx db search "CVE-2025"         # grep titles/CVE ids (capped at 20)
    onyx db diff B.json               # compare two feed snapshots

All `db` subcommands are read-only and work fully offline; pass `--db PATH`
to inspect a file other than the default.

## Shell completions

```bash
onyx completion bash >> ~/.bashrc     # or ~/.zshrc
onyx completion fish >> ~/.config/fish/completions/onyx.fish
```

Completes subcommands, `db` subcommands and every scan flag.

## Watch mode

```bash
onyx watch https://example.com --interval 1h --webhook https://hooks.example/xyz
```

Every pass scans the target and diffs the findings against the previous
run's baseline (stored under the user cache dir, `--state-dir` to override):

```
[2026-08-22T14:47:23Z] 0 new, 0 resolved, 12 unchanged
```

New vulnerabilities print under "New vulnerabilities:", fixed ones under
"Resolved:". When anything changes and `--webhook` is set, onyx POSTs a JSON
report (`target`, `summary`, `new[]`, `resolved[]`); `--webhook-format slack`
wraps the same data as a Slack webhook `{"text": ...}` message. Without
`--interval`, watch runs a single compare-and-exit pass — handy for CI drift
checks.
Scan flags like `--db`, `--threads`, `--enumerate`, `--max-requests` are
honored.

## Access control & targeting

Protected targets are supported: `--basic-auth USER:PASS` (e.g. staging
sites), `--cookie "wordpress_logged_in=..."` for login-walled pages,
`--headers "X-API-Key: ..., ..."` for custom request headers and
`--vhost HOST` when several sites share one IP (Host-header override).
`--force` scans even when the target shows no WordPress fingerprints
(odd builds, hard-won WAFs), and `--exclude-vulns` drops noisy records
by vulnerability ID.

## Cache management

```bash
onyx cache stats                 # dir, entry count, total size
onyx cache purge                 # delete all cached responses
```

The HTTP response cache lives in `~/.cache/onyx/http` (or
`$ONYX_CACHE_DIR`), uses `0600`/`0700` permissions, and is only active
with `--cache-ttl`.

## Enumerate tokens

`--enumerate` accepts WPScan-style tokens: `p`/`ap` (plugins, including
the popular seed lists), `vp` (vulnerable plugins only), and the same
for themes (`t`/`at`/`vt`), plus `u` (users) and `m` (media). Legacy
bare-letter forms like `ptum` keep working. When the mirror publishes
`popular.json` with install counts, detected components report
`active_installs` in JSON and CycloneDX output. XML-RPC scans now also
report the advertised method list (`xmlrpc_methods`).

## Result diffing and config help

```bash
onyx diff a.json b.json          # compare two saved scan results (exit 1 on any difference)
onyx example-config              # print a commented JSON config template
```

`onyx diff` compares the vulnerability sets of two `--format json` outputs
and reports added / removed / changed entries — handy for drift checks
between scheduled scans. The config template matches every key
`applyConfig` understands.

## Exploitation intelligence

By default every finding is annotated with its EPSS score (probability of
exploitation in the wild) and CISA KEV membership, then findings are sorted
by that priority: KEV-confirmed first, highest EPSS next. The data lives in
the user cache dir and refreshes daily; offline scans fall back to the last
cached copy with a warning, and `--no-intel` skips enrichment entirely.

## CI-friendly report formats

Beyond machine formats (`json`, `jsonl`, `sarif`, `csv`, `cyclonedx`),
onyx renders human-readable and CI-gating outputs:

```bash
onyx scan https://example.com --format md      > report.md       # Markdown
onyx scan https://example.com --format html    > report.html     # standalone page
onyx scan https://example.com --format junit   > junit.xml       # CI test reports
```

JUnit marks one failing testcase per vulnerability, so GitLab/Jenkins test
widgets light up per finding; a clean scan emits a passing testcase so the
report is always structurally valid. `--output FILE` honors these formats.

## Component inventory output

`--format cyclonedx` emits the detected plugins/themes as a CycloneDX 1.5
SBOM (`components[]` with name/version), ready for dependency tracking
pipelines.

## How it works

1. Fetch the homepage, `/wp-login.php` and the REST API root. If the target
   can't be reached at all, it stops with an error (exit 2).
2. **Passive detection:** scan the homepage HTML for `wp-content/plugins/…`
   and `wp-content/themes/…` references — anything the page mentions gets
   checked, with no extra requests (same trick WPScan uses). `?ver=`
   parameters on plugin/theme assets are read as version hints, so many
   components get a version without any probing.
3. **Aggressive enumeration:** walk the most vuln-heavy plugin and theme
   slugs from the database (top 200 by default, raise with
   `--max-requests`), fetch their `readme.txt` / `style.css`, and read the
   version out of it. Supply your own lists with `--plugins-list FILE` /
   `--themes-list FILE`.
4. **Sitemap discovery** (`--crawl-pages N`): fetch pages from the
   target's sitemap (`/wp-sitemap.xml`, falling back to `/sitemap.xml`,
   one index level deep) and run passive detection over each — sites whose
   homepage is minimal often expose different plugins on inner pages.
5. **Core fingerprinting:** the WordPress version comes from whichever
   source answers first: the generator meta tag, the RSS feed generator,
   or `wp-links-opml.php`. The winning source is reported in JSON output
   under `core_evidence`.
4. Enumerate users (`--enumerate u`): read `/wp-json/wp/v2/users` when it's
   parseable, then walk `/?author=N` redirect chains to `/author/<slug>/`,
   including subdirectory multisite installs (`/blog/author/<slug>/`).
5. Probe for interesting leftovers: `robots.txt`, `readme.html`, `debug.log`,
   `xmlrpc.php`, upload directory listing, `wp-config.php.bak`,
   `wp-includes/version.php`. Optional `--checks cb,dbe,timthumb` digs for
   config backups and database dumps. Cache-layer headers (LiteSpeed,
   WP Super Cache, W3TC, Varnish, …) and an exposed `mu-plugins/` listing
   are reported as interesting finds too.
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

## Report enrichment

Findings carry the feed's display names and fix guidance: JSON output
includes `remediation` and `patched_versions` when the record provides
them, and every result is stamped with a `schema_version` field so CI
consumers can detect breaking output changes. Detected components report
`tested_up_to` / `requires_at_least` when their readme provides them.

## Optional data assets

`onyx update` also mirrors two optional files next to the database when
the mirror publishes them: `popular.json` (fresh popular plugin/theme
lists replacing the built-in seeds) and `fingerprints.json` (MD5 core
fingerprints that power `--fingerprint-db` automatically). Both are
signature-verified when `ONYX_DB_PUBKEY` is set; a missing asset is a
warning, never an error.

## The database

The feed comes from the Wordfence Intelligence Vulnerability Database,
which is licensed free for personal and commercial use, including
redistribution. The mirror lives in the
[`onyx-db`](https://github.com/Boreas37/onyx-db) repository, updated daily.
See its README for the license terms.

### Read index sidecar

`onyx update` also writes a pre-built index sidecar (`<db>.idx`); scans
then start ~6x faster (~0.3s vs ~1.6s on the full 151MB feed) at roughly
half the memory, because the 39k-record feed no longer needs its JSON
re-parse. The sidecar is a cache: it is regenerated whenever the feed
changes and any corruption or staleness silently falls back to the
regular loader.

### Incremental updates and signatures

`onyx update` first checks the mirror's `manifest.json`: when it publishes
a delta from the checksum you have on disk, only that changeset (a few KB)
is downloaded and applied — the full 151 MB feed transfers only on the
first run or when no delta applies. Any manifest/delta problem falls back
to the full download with a warning, so updates never get *worse*.

For supply-chain hardening, point `ONYX_DB_PUBKEY` at a minisign public
key; update then verifies the feed signature (`<asset>.minisig`) after
every download, the `manifest.json` signature (so the delta selection
itself is authenticated), and refuses to bless a database that fails
verification — a missing or bad signature is a hard error, not a warning.
A manifest older than the last accepted one is rejected as a downgrade
(`ONYX_ALLOW_OLDER_MANIFEST=1` to override), and deltas now carry a
semantic result digest that `ApplyDelta` verifies after reconstruction
(byte-for-byte equality is impossible by design, so the digest covers
id + compact-record content in sorted order instead). Public keys and
signatures interoperate with minisign 0.12 in both directions, including
its default pre-hashed `ED` signatures; the trusted-comment binding uses
minisign's raw-64-byte construction with a legacy fallback for previously
published onyx artifacts. Secret keys are onyx-specific plaintext files,
not interchangeable with minisign's scrypt-encrypted boxes.

The delta fast-path also carries a downgrade guard: `onyx update` refuses
a `manifest.json` whose `generated_at` is older than the last accepted one
(`dst + ".manifest-ts"`) and falls back to the full download. Set
`ONYX_ALLOW_OLDER_MANIFEST=1` to bypass, or `ONYX_MANIFEST_URL` to point
the updater at a different mirror for testing.

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
