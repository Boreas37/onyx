# WPScan Feature Inventory (2026-08)

> Compiled from the WPScan source tree (commit `f6169f00`, version **4.1.0**, cloned into `.wpscan-src/` for read-only reference) plus the official README (`README.md`). Every option below was read directly from the controller CLI option definitions:
> `app/controllers/core/cli_options.rb`, `app/controllers/core.rb`, `app/controllers/enumeration/cli_options.rb`, `app/controllers/password_attack.rb`, `app/controllers/vuln_api.rb`, `app/controllers/custom_directories.rb`, `app/controllers/interesting_findings.rb`, `app/controllers/wp_version.rb`, `app/controllers/main_theme.rb`, `app/controllers/aliases.rb`.
> Anything that could not be found in the current source is explicitly marked **[NOT FOUND in 4.1.0]**.

---

## 1. CLI Command Structure and Global Options

Single executable `wpscan`, one scan command (`--url`), no subcommands. Options are parsed by the `opt_parse_validator` gem. Options can also be loaded from config files: `$XDG_CONFIG_HOME/wpscan/scan.json|scan.yml`, `~/.config/wpscan/scan.{json,yml}`, `~/.wpscan/scan.{json,yml}`, `pwd/.wpscan/scan.{json,yml}` (snake_case keys, e.g. `api_token`, `max_threads`). `--url` is **required unless** `--help`, `--hh`, or `--version` is given.

### Global / target options
| Flag | Description | Default |
|---|---|---|
| `-u, --url URL` | The URL to scan | required; protocol defaults to `http` |
| `-o, --output FILE` | Write results to FILE | — |
| `-f, --format FORMAT` | Output format: `cli`, `cli-no-colour`, `cli-no-color`, `json`, `jsonl`, `sarif` | `cli` |
| `--[no-]stream` | Stream enumeration findings (plugins/themes/users) as discovered instead of batching; no effect for `json`/`sarif` | `true` |
| `--detection-mode MODE` | `mixed`, `passive`, or `aggressive` | `mixed` |
| `--scope DOMAINS` | Comma-separated (sub-)domains in scope; wildcards allowed (`*.target.tld`) | — |
| `--exclude-vulns UUIDs` | Comma-separated vulnerability UUIDs to exclude from results | — |
| `--force` | Do not check if target returns 403 / is WordPress | off |
| `--server SERVER` | Force server module: `apache`, `iis`, `nginx` | auto-detect |
| `--[no-]update` | Whether to update the local vulnerability database | prompt if stale (interactive) / auto if files missing |
| `--max-scan-duration SECONDS` | Abort the scan after N seconds | — |
| `--max-log-file-size MiB` | Skip PHP log file inspection (debug.log, error_log, …) above this size | 20 |

### Help / info options
| Flag | Description |
|---|---|
| `-h, --help` | Display the **simple** help (non-advanced options) and exit |
| `--hh` | Display the **full** help (all options incl. `advanced: true` ones) and exit |
| `--version` | Display the version and exit |
| `-v, --verbose` | Verbose mode (extra detail, per-step messages) |
| `--[no-]banner` | Whether to display the banner | `true` |
| `--stealthy` | Alias for `--random-user-agent --detection-mode passive` (alias controller) |

### Exit codes (`lib/wpscan/exit_code.rb`)
`0` OK (no vulnerabilities found) · `1` CLI option error · `2` interrupted · `3` unhandled exception · `4` error, scan did not finish · `5` target has at least one vulnerability.

---

## 2. Enumeration Modes (`--enumerate`)

`-e, --enumerate [OPTS]` — comma-separated list of choices. If given **without value**, defaults to `vp,vt,tt,cb,dbe,bf,u,m`. Choices:

| Choice | Meaning | Notes |
|---|---|---|
| `vp` | **Vulnerable plugins** | slug list = plugins known to have vulnerabilities |
| `ap` | **All plugins** | slug list = all known plugin slugs |
| `p` | **Popular plugins** | slug list = most popular plugins |
| `vt` | **Vulnerable themes** | |
| `at` | **All themes** | |
| `t` | **Popular themes** | |
| `tt` | **Timthumbs** | brute-force timthumb script locations from `timthumbs-v3.txt` |
| `cb` | **Config backups** | brute-force `wp-config.php` backup filenames from `config_backups.txt` |
| `dbe` | **DB exports** | brute-force database dump filenames from `db_exports.txt` |
| `bf` | **Backup folders** | brute-force backup folder names from `backup_folders.txt` |
| `u` | **Users** | accepts an ID range, e.g. `u1-5`; empty value ⇒ `u1-10` |
| `m` | **Medias** | accepts an ID range, e.g. `m1-15`; empty value ⇒ `m1-100`; requires "Plain" permalink setting to detect |

Incompatibilities enforced: only one of `vp/ap/p`; only one of `vt/at/t`.

Related overrides:
- `--plugins-list LIST` — enumerate only the given plugin slugs; **overrides** `vp/ap/p` (collisions are dropped with a notice).
- `--themes-list LIST` — same for themes; **overrides** `vt/at/t`.
- `--users-list LIST` — usernames to check during user enumeration from login error messages.
- `--exclude-usernames REGEXP` — exclude matching usernames (case-insensitive).
- `--exclude-content-based REGEXP` — exclude all responses whose headers/body match (case-insensitive, regexp delimiters optional) during parts of enumeration.
- Per-type lists for special checks: `--timthumbs-list FILE`, `--config-backups-list FILE`, `--db-exports-list FILE`, `--backup-folders-list FILE` (defaults point at files shipped in the local DB).

Enumeration runs plugin/theme checks with the **default of `--plugins-detection` = `passive`** when the user does not set a mode, regardless of the global `--detection-mode` (README explicitly warns about this).

### How enumeration works
- **Plugins/themes**: passive finders parse the homepage and/or 404 pages (URLs in JS vars, comments, body/header patterns, `?ver=` query params, `wp-json` REST API endpoint) to discover slugs; aggressive finders brute-force known-location URLs (`.../wp-content/plugins/<slug>/readme.txt` style requests, valid response codes 200/401/403/500). Versions are then probed (readme `Stable tag`, style.css header, changelog, etc.) at `--plugins-version-detection`/`--themes-version-detection` modes. `--plugins-threshold` (default 100) / `--themes-threshold` (default 20) abort with an error if a known-locations brute-force finds more than N items (0 disables).
- **Users**: from the WP REST API (`/wp-json/wp/v2/users`), `?author=N` redirects, oEmbed, login error messages ("invalid username"), RSS feeds, sitemaps, etc.
- **Medias**: brute-force `/wp-content/uploads/YYYY/MM/ID.ext` style URLs over an ID range.
- **Timthumbs**: request each known timthumb location, fingerprint the returned script.
- **Config backups**: request known wp-config.php backup filenames (`.bak`, `.sav`, `~`, `#`, …).
- **DB exports**: request known SQL dump paths.
- **Backup folders**: request known backup directory names (e.g. `backup-*`).

---

## 3. Detection Modes (`--detection-mode`, `--plugins-detection`, `--themes-detection`)

Three modes, each per-component-overridable:

| Mode | Behavior |
|---|---|
| `passive` | Only passive detection: parse responses of already-requested pages (homepage, 404 page, common endpoints). No additional requests for discovery. |
| `aggressive` | Only aggressive detection: make extra requests — brute-force known locations / dictionary of slugs, version probe URLs, etc. |
| `mixed` | Passive first, then aggressive (for confirmation/versions/details). Default. |

Per-component overrides (all `mixed|passive|aggressive`, all `advanced`):
- `--plugins-detection MODE` (note: defaults to **passive** when only `-e` is used)
- `--plugins-version-detection MODE` / `--plugins-version-all` (check *all* version locations instead of stopping at first hit)
- `--themes-detection MODE`
- `--themes-version-detection MODE` / `--themes-version-all`
- `--users-detection MODE`
- `--wp-version-detection MODE` / `--wp-version-all` (confidence threshold 0 vs 100)
- `--main-theme-detection MODE`
- `--interesting-findings-detection MODE`

---

## 4. Scan Behavior

### Rate / concurrency
| Flag | Description | Default |
|---|---|---|
| `-t, --max-threads VALUE` | Max concurrent HTTP requests (Typhoeus hydra) | 5 |
| `--throttle MilliSeconds` | Sleep before every request; **forces max threads to 1** | off |
| `--request-timeout SECONDS` | Per-request timeout | 60 |
| `--connect-timeout SECONDS` | Connection timeout | 30 |

### Requests / identity
| Flag | Description |
|---|---|
| `--user-agent VALUE, --ua` | Custom User-Agent |
| `--random-user-agent, --rua` | Random UA per scan |
| `--user-agents-list FILE` | List used with `--random-user-agent` (default: bundled `user_agents.txt`) |
| `--headers HEADERS` | Extra headers to append to all requests |
| `--vhost VALUE` | Host header (virtual host) to send |

### Output behavior
- `-v/--verbose`, `--[no-]banner`, `--[no-]stream` as in §1.
- Formats: `cli` (colored, interactive: progress bar, prompts), `cli-no-colour`/`cli-no-color` (plain text), `json` (single document at end), `jsonl` (one JSON object per finding, streams), `sarif` (SARIF 2.1.0). **[NOT FOUND in 4.1.0: `csv` output format]**.
- `-o, --output FILE` writes the output to a file.
- There is **no `--quiet` / `--silent` flag** — [NOT FOUND in 4.1.0]. Output suppression is not directly supported; non-TTY runs degrade to log lines.

### Caching
| Flag | Description | Default |
|---|---|---|
| `--cache-ttl TIME_TO_LIVE` | HTTP response cache TTL in seconds | 600 |
| `--cache-dir PATH` | Cache directory | `$TMPDIR/wpscan/cache` (or XDG cache) |
| `--clear-cache` | Clear the cache before the scan | off |

---

## 5. Special Checks

### Config backups (`cb`), DB exports (`dbe`), medias (`m`), timthumbs (`tt`), backup folders (`bf`)
See §2 — all are dictionary/range brute-force finders with per-type list files. Finding models: `ConfigBackup`, `DbExport`, `Media`, `Timthumb`, plus `BackupFolder`-style findings, each reported with `found_by`, `confidence`, and `interesting_entries`.

### Interesting findings (always run, not part of `-e`)
`robots.txt`, headers (server, X-Powered-By, cookies flags, content-type sniffing), `readme.html`/`readme.txt` (WP exposed), registration endpoint, multisite detection, mu-plugins, `wp-cron.php`, XML-RPC interface (`/xmlrpc.php` — enabled?, available methods), debug log, PHP disabled functions, full path disclosure, upload directory listing, upload SQL dump, backup DB, Duplicator installer log, `emergency.php` password reset script, Fantastico fileslist, search-replace-db and TMM DB migrate scripts, redirect handling.

### Password attack (`--passwords` triggers the PasswordAttack controller)
| Flag | Description | Default |
|---|---|---|
| `--passwords FILE, -P` | Wordlist of passwords; if no usernames supplied, user enumeration runs first | required to trigger |
| `--usernames LIST, -U` | Usernames to attack (list or `user1,user2`) | enumerate |
| `--password-attack ATTACK` | Force mechanism: `wp-login`, `xmlrpc`, `xmlrpc-multicall` | auto-detect |
| `--multicall-max-passwords MAX_PWD` | Max passwords per XML-RPC multicall request | 500 |
| `--login-uri URI` | Custom login page path (if not `/wp-login.php`) | — |
| `--wordlist-skip N` | Skip first N passwords (resume) | 0 |
| `--max-retries N` | Retries for failed requests (network/proxy errors) | 0 |

Auto-detection: if XML-RPC is enabled and `wp.getUsersBlogs` works → multicall if WP < 4.4 else XML-RPC; otherwise `wp-login`. Progress bar, per-user success lines, final `users` report. Errors: `NoLoginInterfaceDetected`, `XMLRPCNotDetected`.

### Authenticated inventory (`--wp-auth`)
REST-API authoritative plugin/theme inventory using a WordPress **Application Password** (WP ≥ 5.6): `/wp-json/wp/v2/plugins` and `/wp-json/wp/v2/themes`. When present, `-e` plugin/theme enumeration is bypassed entirely.

### SAML (`--expect-saml`)
Launches an interactive browser for SAML IdP login when the target redirects with `SAMLRequest`; session cookies are reused for the rest of the scan.

---

## 6. API Integration

| Flag | Description |
|---|---|
| `--api-token TOKEN` | WPScan API token (https://wpscan.com/profile). Also via env `WPSCAN_API_TOKEN` (CLI wins) or config file. |
| `--enterprise-db-token TOKEN` | Use a **local** enterprise vulnerability DB dump (downloaded from `enterprise-data.wpscan.org` during DB update) instead of per-finding API calls. Mutually exclusive with `--api-token`; env `WPSCAN_ENTERPRISE_DB_TOKEN`. |
| `--proxy-target-only` | Apply `--proxy` only to target requests, not to API/DB-update requests. |

With a valid API token: vulnerability data is fetched in real time — one API request per WordPress version, plugin, and theme found. Free tier: **25 requests/day**; when exhausted the scan continues without vulnerability data. Without a token the scan runs fully against the **local database** (updated via `wpscan --update` from `data.wpscan.org`; stored in `~/.cache/wpscan/db` or legacy `~/.wpscan/db`) — i.e. `--api-token` upgrades the local-data experience (vuln lookups + false-positive reduction via API-confirmed data), it is not required to run a scan.

---

## 7. Other Capabilities

### DB update / maintenance
- `--update` (i.e. `--url` absent + `--update`): update local DB (checksums, incremental) and exit.
- `--no-update`: never update; errors if DB files are missing; otherwise staleness prompt (interactive only).
- DB contents include wordpress/plugin/theme version fingerprints (`wp_fingerprints.json`), dynamic finders (`dynamic_finders.yml`), vuln API metadata, and the brute-force list files (`backup_folders.txt`, `config_backups.txt`, `db_exports.txt`, `timthumbs-v3.txt`).

### HTTP / transport
- `--proxy protocol://IP:port` (protocols depend on installed cURL; `socks5h://` for proxy-side DNS, e.g. Tor `.onion`) + `--proxy-auth login:password`.
- `--http-auth login:password` (Basic HTTP auth).
- `--cookie-string COOKIE` (`c1=v1; c2=v2`) + `--cookie-jar FILE` (read/write; default `$TMPDIR/wpscan/cookie_jar.txt`).
- `--disable-tls-checks`: skip SSL/TLS certificate verification, downgrade to TLS 1.0+ (cURL ≥ 7.66).
- `--ignore-main-redirect` (scan original URL despite out-of-scope redirect; no effect with `--follow-redirect`) and `--follow-redirect` (auto-update URL to redirect destination, adds host to scope).
- Scheme-only (http↔https) redirects are always followed.
- 403 handling: abort unless `--force`; `--force` also skips the "not WordPress" check (WordPress detection: generator meta, wp-content paths, wp-login, /wp-json, etc.).

### WordPress-specific discovery
- `--wp-content-dir DIR` / `--wp-plugins-dir DIR`: override custom `wp-content`/plugins directory paths when not auto-detected (auto-detection also scans the homepage for non-standard paths like `app/themes`).
- **[NOT FOUND in 4.1.0: `--uploads-dir` option]** (removed in modern versions).
- **[NOT FOUND in 4.1.0: `--exclude`/`--include` slug-list flags]** — superseded by `--plugins-list`/`--themes-list`, `--exclude-content-based`, `--exclude-usernames`, `--exclude-vulns`.
- WordPress.com-hosted targets and not-fully-installed WP (`/wp-admin/install.php`) are handled with dedicated errors/exits.

### Full `--help` (WPScan 4.1.0) option reference
```
-u, --url URL                    The URL to scan
    --force                      Do not check if the target is running WordPress or returns a 403
-o, --output FILE                Output to FILE
-f, --format FORMAT              Output results in the format supplied (cli, cli-no-colour, cli-no-color, json, jsonl, sarif)
    --[no-]stream                Emit enumeration findings as discovered (default true)
    --detection-mode MODE        mixed|passive|aggressive (default mixed)
    --scope DOMAINS              Comma separated (sub-)domains in scope (advanced)
    --exclude-vulns UUIDs        Comma separated vulnerability UUIDs to exclude (advanced)
-h, --help                       Display the simple help and exit
    --hh                         Display the full help and exit
    --version                    Display the version and exit
    --ignore-main-redirect       Ignore the main redirect (advanced)
    --follow-redirect            Automatically update the URL to the destination of the redirect (advanced)
-v, --verbose                    Verbose mode
    --[no-]banner                Display the banner (default true)
    --max-scan-duration SECONDS  Abort the scan if it exceeds this time (advanced)
    --max-log-file-size MiB      Skip PHP log files above this size (default 20, advanced)
    --server SERVER              apache|iis|nginx (advanced)
    --[no-]update                Whether or not to update the Database
    --user-agent VALUE, --ua     Custom User-Agent
    --headers HEADERS            Additional headers to append in requests (advanced)
    --vhost VALUE                Virtual host (Host header) (advanced)
    --random-user-agent, --rua   Random user-agent per scan
    --user-agents-list FILE      List of agents for --random-user-agent (advanced)
    --http-auth login:password   Basic HTTP authentication
    --wp-auth login:password     WP admin (Application Password) for REST API inventory
-t, --max-threads VALUE          Max threads (default 5)
    --throttle MilliSeconds      Wait before each request; sets threads to 1
    --request-timeout SECONDS    Request timeout (default 60)
    --connect-timeout SECONDS    Connection timeout (default 30)
    --disable-tls-checks         Disable SSL/TLS verification, downgrade TLS (advanced-ish)
    --proxy protocol://IP:port   HTTP/SOCKS proxy
    --proxy-auth login:password  Proxy auth
    --cookie-string COOKIE       Cookie string c1=v1[; c2=v2]
    --cookie-jar FILE            Cookie jar (default $TMPDIR/wpscan/cookie_jar.txt)
    --expect-saml                Expect SAML auth; interactive browser login (advanced)
    --cache-ttl SECONDS          Cache TTL (default 600, advanced)
    --clear-cache                Clear cache before scan (advanced)
    --cache-dir PATH             Cache directory (advanced)
    --api-token TOKEN            WPScan API token
    --enterprise-db-token TOKEN  Local enterprise DB dump token (advanced)
    --proxy-target-only          Proxy only for target requests
    --wp-content-dir DIR         Custom wp-content directory
    --wp-plugins-dir DIR         Custom plugins directory
    --interesting-findings-detection MODE (advanced)
    --wp-version-all             Check all version locations (advanced)
    --wp-version-detection MODE  (advanced)
    --main-theme-detection MODE  (advanced)
-e, --enumerate [OPTS]           vp,ap,p,vt,at,t,tt,cb,dbe,bf,u,m; empty = vp,vt,tt,cb,dbe,bf,u,m
    --exclude-content-based REGEXP
    --plugins-list LIST          (advanced)
    --plugins-detection MODE     default passive for -e
    --plugins-version-all        (advanced)
    --plugins-version-detection MODE
    --plugins-threshold N        default 100 (advanced)
    --themes-list LIST           (advanced)
    --themes-detection MODE      (advanced)
    --themes-version-all         (advanced)
    --themes-version-detection MODE (advanced)
    --themes-threshold N         default 20 (advanced)
    --timthumbs-list FILE        (advanced)
    --config-backups-list FILE   (advanced)
    --db-exports-list FILE       (advanced)
    --backup-folders-list FILE   (advanced)
    --users-list LIST            (advanced)
    --users-detection MODE       (advanced)
    --exclude-usernames REGEXP
    --passwords FILE, -P         Wordlist
    --usernames LIST, -U         Usernames
    --multicall-max-passwords N  default 500
    --password-attack ATTACK     wp-login|xmlrpc|xmlrpc-multicall
    --login-uri URI              Custom login page
    --wordlist-skip N            default 0
    --max-retries N              default 0
    --stealthy                   Alias: --random-user-agent --detection-mode passive
```

---

## 8. onyx Comparison Table

Legend: ✅ = implemented · ⚠️ = partial/limited · ❌ = missing · (N/A) = by-design difference.

| Feature | WPScan | onyx (current) | onyx (gap — suggestion) |
|---|---|---|---|
| WordPress detection (generator meta, wp-content, wp-login, /wp-json) | ✅ multi-signal + `--force` skip | ✅ `detectWP` (scanner.go:397) | — |
| WordPress version detection | ✅ many locations (`?ver=`, readme, RSS, dynamic finders, `--wp-version-all`, confidence) | ⚠️ only homepage generator meta tag | Probe more version locations (readme.html, feed links, `wp-includes/version.php`-style fingerprints); add `--wp-version-all`/confidence |
| Plugin enumeration | ✅ passive + aggressive, `vp/ap/p` lists, `--plugins-list`, version fingerprinting, thresholds | ⚠️ passive homepage regex + brute-force top-200 slugs from local DB; version from `readme.txt` Stable tag | Add `vp/vt` (vulnerable-only) modes, explicit lists (`--plugins-list`), per-type detection-mode overrides, `?ver=`/changelog version probing |
| Theme enumeration | ✅ passive + aggressive, `vt/at/t`, `--themes-list` | ⚠️ passive + brute-force; version from `style.css` | Same as plugins |
| User enumeration | ✅ REST API, `?author=N`, oEmbed, login errors, sitemaps; ranges `u1-5`; `--exclude-usernames` | ⚠️ `/wp-json/users` + `?author=N` walk (10 IDs); no range/exclude | Add `u` ranges, login-error-message enumeration, `--exclude-usernames` |
| Config backup detection (`cb`) | ✅ dictionary brute-force `wp-config.php` backups | ❌ | Add `cb` finder with wordlist |
| DB export detection (`dbe`) | ✅ | ❌ | Add `dbe` finder |
| Timthumb detection (`tt`) | ✅ | ❌ | Add `tt` finder |
| Media enumeration (`m`) | ✅ ID-range brute-force of uploads URLs | ❌ | Add `m` (needs plain permalinks note) |
| Backup folder detection (`bf`) | ✅ | ❌ | Add `bf` |
| Interesting findings (robots.txt, readme.html, headers, xmlrpc, debug.log, upload dir listing, … ~20 finders) | ✅ always-on controller | ❌ (only WP-presence evidence strings) | Add key ones: xmlrpc.php, readme.html, robots.txt, upload dir listing, debug.log |
| wp-login brute force | ✅ | ❌ | Add `--passwords`/`--usernames` wp-login attacker |
| XML-RPC password attack (+ multicall) | ✅ auto-detect + `--password-attack` | ❌ (XML-RPC not probed) | Probe xmlrpc.php; add xmlrpc + multicall attackers, `--multicall-max-passwords` |
| Authenticated REST inventory (`--wp-auth`) | ✅ Application Password → wp-json plugins/themes | ⚠️ anonymous `/wp-json/wp/v2/plugins` only (scanner.go:433) | Support authenticated REST inventory |
| Detection modes (passive/aggressive/mixed) | ✅ global + per-component | ❌ (always passive+aggressive mixed, aggressive capped by request budget) | Add `--detection-mode` + `--plugins-detection`/`--themes-detection` |
| Rate limiting | `--throttle` (ms, forces 1 thread) | ✅ `--rate-limit N` req/s + `--stealth` (1 req/s) + 429 adaptive backoff | — (different mechanism, equivalent intent) |
| Concurrency | `-t/--max-threads` (default 5) | ✅ `--threads` (default 5) | — |
| Timeouts | `--request-timeout` (60) + `--connect-timeout` (30) | ⚠️ single `--timeout` (10s) | Add separate connect timeout |
| Random user-agent | ✅ `--rua` + list file | ❌ (sends `Go-http-client/1.1`) | Add `--user-agent`/`--random-user-agent` (blocks UA-based WAFs) |
| Proxy | ✅ `--proxy` (+socks5h) `--proxy-auth` `--proxy-target-only` | ❌ | Add proxy support |
| Cookies / headers / http-auth | ✅ `--cookie-string`, `--cookie-jar`, `--headers`, `--http-auth`, `--vhost` | ❌ | Add cookie/header/auth options |
| TLS controls | ✅ `--disable-tls-checks` | ❌ | Add TLS skip flag (advanced) |
| Redirect handling | ✅ `--ignore-main-redirect`, `--follow-redirect`, scheme-only auto-follow | ⚠️ default follow; no flags (only `?author=` uses no-redirect client) | Add ignore/follow flags + scope handling |
| Output formats | ✅ cli, cli-no-colour, json, jsonl, sarif | ⚠️ table + json; no csv/sarif/jsonl | Add `--format` (jsonl streaming, sarif) |
| Output file | ✅ `-o/--output` | ✅ `--output FILE` (JSON only) | — |
| Verbose/quiet | `-v/--verbose`; no quiet | ✅ `--verbose`, `--silent` (progress only) | Consider `-q` full-quiet |
| API integration | ✅ WPScan API token (25/day), enterprise DB token, false-positive reduction | (N/A) no external API by design — local Wordfence feed (`data/wordfence.json`, `onyx update`) | Optional: pluggable remote vuln provider |
| Local vuln database | ✅ XDG cache DB, incremental update, `--update`/`--no-update`, staleness prompt | ✅ local JSON DB, `onyx update` subcommand + auto-download when missing | Staleness prompt / checksum incremental |
| Custom dirs (`--wp-content-dir`, `--wp-plugins-dir`) | ✅ + auto-detection | ❌ hardcoded `/wp-content/` paths | Add flags + homepage path sniffing |
| Exclusions (`--exclude-content-based`, `--exclude-usernames`, `--exclude-vulns`, `--scope`) | ✅ | ❌ | Add `--exclude-content-based`, `--scope` |
| Slug lists (`--plugins-list`, `--themes-list`) | ✅ | ❌ (only internal top-200) | Add explicit list overrides |
| Max scan duration | ✅ `--max-scan-duration` | ❌ | Add scan time cap |
| HTTP caching (`--cache-ttl`, `--cache-dir`, `--clear-cache`) | ✅ | ❌ | Optional Typhoeus-style cache |
| Enumeration streaming | ✅ `--stream` (cli/jsonl) | ⚠️ per-finding lines in verbose mode | — |
| Exit codes (0 ok / 5 vulnerable) | ✅ | ❌ (always 0?) | Add machine-readable exit codes |
| Config file loading (scan.json/yml) | ✅ | ❌ | Add config file support |
| Stealth alias | ✅ `--stealthy` | ⚠️ `--stealth` (throttle only; no random UA) | Extend `--stealth` to include random UA + passive-only |
| Max request budget | ❌ (thresholds instead) | ✅ `--max-requests` (500) + `--api` REST-only mode | — (onyx unique) |
| Min severity filter | ❌ | ✅ `--min-severity` | — (onyx unique) |

---

*Notes: onyx column verified against `/home/boreas/projects/onyx/main.go` and `internal/` at the time of writing. WPScan column verified against `.wpscan-src` (v4.1.0, commit f6169f00). Features marked [NOT FOUND in 4.1.0] were explicitly requested in the task spec but do not exist in the current WPScan source (they existed in older versions or never existed as described).*
