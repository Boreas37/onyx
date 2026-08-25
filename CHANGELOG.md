# Changelog

All notable changes to `onyx`. Versions follow semver; dates are UTC.

## 1.1.1 — 2026-08-25

### Fixed
- Front-controller false-positive: `pluginMainVersion` now requires `Plugin Name:` header (looksLikePluginPHP), closing the `Version: 8.8.8` homepage forgery that made every missing plugin appear installed (`TestScanJobGuardRejectsRewrittenHomepage` was failing).
- Known-locations 401/403/500 are now treated as presence (WPScan parity) — `scanJob` forges an `unknown` detection instead of missing a 403-hardened readme/style.css.
- `backupFolderPaths` dead code activated: `--checks bf` backup-folder finder with `Index of` / `Parent Directory` markers and whitelist entry.

### Changed
- `--plugins-threshold` / `--themes-threshold` flags (WPScan 100/20 parity) — warnings in `Result.Errors` when the count meets the threshold.
- `cacheKey` 64→128-bit (2^64 vs 2^32 birthday bound), `watch.SaveState` 0755/0644→0700/0600, `csvSafe` now trims leading spaces (`  =2+2` bypass closed).
- Update path now uses a 30s `httpClient` and `FetchManifestRaw(nil)` so `ONYX_MANIFEST_URL` and release lookups cannot hang `onyx update` forever; `popular.json`/`fingerprints.json` stale files are removed on bad signature when `ONYX_DB_PUBKEY` is set.

## 0.9.0 — unreleased

### Added
- Core version fallback from `readme.html` (`Version X.Y.Z` heading); the
  detection chain is now meta → rss2 → /feed/ → atom → opml → asset ?ver=
  → readme-html → fingerprint-db.
- Author sitemap discovery (`wp-sitemap-users-1.xml`) — finds users without
  `?author=N` probing and skips the probing when it yields results.
- Single-user REST fallback: when `/wp-json/wp/v2/users` is blocked
  (401/403), individual `/users/<id>` lookups (1..5) are attempted.
- wp-cron.php exposure finding (200 + tiny body ⇒ external cron triggers).
- Report renderer benchmarks (`internal/report/bench_test.go`).
- CHANGELOG.md (this file) and Go test-coverage reporting in CI.

### Changed
- The `.idx` read-index sidecar is gzip-compressed (~59× smaller at feed
  scale); legacy uncompressed sidecars are detected and rebuilt.
- `onyx db lookup` prints remediation guidance and patched-in versions for
  every matching software entry of a record (multi-component records no
  longer show only the first entry).

## 0.8.0 — 2026-08-24

### Added
- REST-API route-based plugin discovery (`/wp-json/` namespaces; source
  `rest-routes`, confidence 85).
- Media enumeration by attachment ID for the `m` token (`/?p=N`, capped,
  media-exposure finding).
- TimThumb version extraction from exposed copies.
- Findings are severity-ordered (worst CVSS first) before enrichment.
- GitLab SAST output format (`--format gitlab-sast`,
  `gl-sast-report.json` 15.x with NVD-linked CVE identifiers).
- `--disable-tls-checks` and `--update-db` flags.
- `Result.scanned_at` timestamp in every JSON result; deterministic
  Markdown/HTML timestamps.
- Nightly real-WordPress end-to-end job (mysql+wordpress service containers,
  wp-cli install, scan assertions against a stock install).

### Fixed
- Real-WP e2e: wp-cli install URL now matches the scan base URL so the
  homepage answers 200 instead of redirecting to port 80.
- e2e shell scripts are committed executable (permission denied on runners).

## 0.7.0 — 2026-08-24

### Added
- `--enumerate` WPScan-style tokens: `p`/`vp`/`ap` plugins, `t`/`vt`/`at`
  themes (comma-separated; legacy letters still accepted).
- Active-install counts from the mirror's `popular.json`
  (`counts_plugins`/`counts_themes`) surfaced as `active_installs` in JSON
  and an `onyx:active-installs` CycloneDX property.
- XML-RPC method inventory (`xmlrpc_methods`, capped 20) plus an
  exposes-N-methods Interesting entry.
- `--wp-version X.Y.Z`: pin the core version and skip detection
  (source `override`, confidence 100).
- Brute-force modules join the global 429 cooldown and retry each attempt
  once.

### Changed
- nuclei runs templates in batches of 10 with a fresh 60s timeout each;
  partial failures no longer discard other results.
- `onyx db diff` reports shared ids, per-type counts and the first 50
  added/removed records with title+CVE; `onyx db lookup` shows remediation.

## 0.6.0 — 2026-08-24

### Added
- Request decoration: `--basic-auth`, `--cookie`, `--headers`, `--vhost`.
- `--force` (scan non-WordPress-looking targets) and `--exclude-vulns`
  (drop findings by vulnerability id).
- Graceful SIGINT/SIGTERM: scan context is cancelled and partial results
  reported with a warning.
- `onyx cache stats|purge`; HTTP cache files use 0600/0700 permissions.

## 0.5.0 — 2026-08-24

### Added
- Detection: display names from the feed, `remediation` +
  `patched_versions` in findings, `tested_up_to`/`requires_at_least` from
  readme/style.css headers, 404-page plugin/theme discovery, WAF/challenge
  page detection, login-error username oracle, MD5 core-fingerprint table
  support, popular plugin/theme seed lists.
- Supply chain: manifest signature verification, manifest freshness guard
  (downgrade protection), delta de-duplication, single-pass base hashing
  (TOCTOU closed), truthful `.sha256` bookkeeping.
- Ops: `onyx doctor`, config cascade (`~/.config/onyx/scan.json`),
  `--jobs N` concurrent multi-target scanning, `--webhook-format slack`.
- CI: hermetic end-to-end scan job, fuzz matrix expansion, scratch Docker
  image, SPDX SBOM attached to releases.

### Fixed
- HTML/CSV/Markdown injection via feed-controlled severity fields
  (whitelist + escaping at every render site).
- XML injection into outbound multicall requests from target-controlled
  author slugs.
- `version.Parse` integer wraparound (18-digit cap, strict bracket bounds,
  dash-star ranges).
- Missing request accounting in author/XML-RPC/auth paths; stale HTTP-cache
  eviction; timeout-less update/intel clients.

## 0.4.0 — 2026-08-23

### Fixed (security audit)
- minisign interop with minisign 0.12: 64-byte comment-binding signature
  (legacy 74-byte fallback), pre-hashed `ED` support via an in-package
  BLAKE2b, corrected secret-key documentation.
- Delta pipeline: base-hash TOCTOU closed; upstream-artifact-pointer
  semantics documented; downgrade/replay window documented and guarded.
- Feed-controlled ratings whitelisted at load time and escaped in every
  renderer; XML-RPC credentials XML-escaped; `wp-includes/version.php`
  false positive removed; front-controller rewrite guards added
  (content-authenticity checks + `/?rest_route=` fallback).
- Integer overflow in version parsing could fabricate range matches.
- Timeout-less HTTP clients in update/intel paths; missing request
  counters; wp-login brute force required a `/wp-admin` redirect;
  HTTP-cache TTL eviction; database index aliasing; hardcoded year ceilings.

## 0.3.1 — 2026-08-23

### Added
- Resilient 429 handling: global cooldown, retries, adaptive pacing,
  early abort.

### Changed
- Markdown, HTML and JUnit output formats; Homebrew tap distribution.

## 0.3.0 — 2026-08-22

### Added
- Initial public feature set: WordPress fingerprinting, passive/aggressive
  plugin & theme enumeration, user enumeration, Wordfence-feed matching,
  table/JSON/SARIF/CSV/CycloneDX outputs, watch mode, XML-RPC and wp-login
  credential auditing.
