# onyx E2E Test Results

- Date: 2026-08-17 (UTC 11:34)
- Binary: built from commit `3b52be3` (feat: slug lists, max-scan-duration, http cache, jsonl streaming, timthumb check, config file)
- Targets: https://wpscan-vulnerability-test-bench.ddev.site (WP 7.0.4, Elementor 3.0.0 + Essential Addons 5.0.0), http://127.0.0.1:18153, http://127.0.0.1:18155, plus a local UA-logging sim (127.0.0.1:18473/18474) built in /tmp for HTTP-behavior evidence
- DB: /tmp/test-db.json (38,884 records; 151,590,613 bytes)
- Scope: testing only — no Go code modified, nothing committed

## Summary

- Total tests: 32 | Passed: 29 | Failed: 3

## Failures (priority order)

| # | Test | Komut | Beklenen | Gerçek | Sorun |
|---|------|-------|----------|--------|-------|
| 22 | Proxy routing on dead proxy | `--proxy http://127.0.0.1:1` | Connection error, exit 2 | exit 0, `is_wordpress: true`, scan "completes" with 0 findings | `detectWP()` records `"homepage fetch failed: <err>"` **as evidence**, so `IsWordPress = len(evidence)>0` becomes true despite total connectivity failure; scan continues and exits 0. Real bug — see main.go:817-821 / scanner.go:1126-1130 chain. Same misclassification applies to any unreachable host |
| 5 | User enumeration (real bench) | `--enumerate u` | superadmin, simpleadmin, editor, author, contributor, subscriber listed | `users` missing from JSON; only error `wp-json/wp/v2/users returned unparseable data`; zero users | Three causes on the bench: (1) REST `/wp-json/wp/v2/users` response is prefixed by PHP `Deprecated` notices (Essential Addons) so `json.Unmarshal` fails; (2) author redirect Location is `/blog/author/superadmin/` but `authorSlugRe` requires `^/author/` (scanner.go:53) — subdirectory multisite missed; (3) `/?author=2..6` return 200 (no redirect) so `usersFromAuthors` skips them. Works correctly against sim 18153 (admin/editor found) — environment + regex paths, not enumeration logic itself |
| 24 | HTTP cache second-run speedup | `--cache-ttl 24` twice | Second scan fast (from cache) | Local sim: live requests 47 → 9 (good); real bench: 6.5s → 6.2s (1.1x) | Cache only stores HTTP 200 responses (scanner.go:517-520). Brute-force probes are mostly 404s, re-fetched every scan, so realistic second scans are barely faster. Mechanism works, expectation not met for brute-force-heavy scans |

## Notes (per-test evidence)

### A. Temel Tarama

1. ✅ PASS — `go build -o onyx .` → `onyx` produced, 8,445,992 bytes. Binary built to /tmp/opencode/onyx and run for every test below.
2. ✅ PASS — `./onyx scan https://wpscan-vulnerability-test-bench.ddev.site --db /tmp/test-db.json`
   - `[High] [plugin:elementor:3.0.0] 41 vulnerabilities (worst: Elementor <= 3.19.0 - Authenticated(Contributor+) Arbitrary File Deletion and PHAR Deserialization)`
   - `[Critical] [plugin:essential-addons-for-elementor-lite:5.0.0] 63 vulnerabilities (worst: Essential Addons for Elementor <= 5.0.4 - Local File Inclusion)`
   - WordPress core 7.0.4, XML-RPC enabled, 3 interesting findings; exit 5.
3. ✅ PASS — `--json` → valid JSON; `findings[].slug/name/type/installed_version/vulnerabilities[]` present with fields `id,title,cve,cvss_score,cvss_rating,description,affected_versions,published_at`. 2 findings (elementor 41, eael 63 vulns).
4. ✅ PASS — `--min-severity high` → exactly elementor **2** and essential-addons **7** findings (High/Critical only) — matches previously verified counts.

### B. Enumerasyon Modları

5. ❌ FAIL — `--enumerate u` on real bench: no users listed; `errors: ["wp-json/wp/v2/users returned unparseable data"]`. Same command against sim 18153 works: `users: [admin(1), editor(2)]`. (Details in Failures table.)
6. ✅ PASS — `--enumerate p` → detected elementor 3.0.0 + essential-addons-for-elementor-lite 5.0.0, 2 findings, exit 5.
7. ✅ PASS — `--enumerate t` → detected `twentytwentyfive` theme v1.5, no findings, exit 0.
8. ✅ PASS — `--enumerate m` → `interesting: [..., "media uploads present"]` (homepage references /wp-content/uploads/).
9. ✅ PASS — `--checks cb,dbe,timthumb` → no config backups/db exports/timthumb found (expected on bench), no crash, clean JSON with `config_backups`/`db_exports` absent and errors only the usual auth-skipped note. Exit 5 (plugins still found).

### C. Detection Modları

10. ✅ PASS — `--detection-mode passive` → elementor + essential-addons both detected (homepage references), 2 findings, exit 5.
11. ✅ PASS — `--detection-mode aggressive` → DB top-N brute-force found both plugins, same findings, exit 5.
12. ✅ PASS — `--detection-mode mixed` (default; proven by test 2) → both passive and aggressive results.

### D. Çıktı Formatları

13. ✅ PASS — `--format jsonl` → 2 lines, each a valid Finding JSON (`slug,installed_version,name,type,vulnerabilities`).
14. ✅ PASS — `--format sarif` → `version == "2.1.0"` (verified via python json; jq not installed on host); `$schema` = sarif-schema-2.1.0; tool `onyx 0.1.0`, 104 results (2 findings × 104 vulns), ruleId = CVE ids.
15. ✅ PASS — `--format json --output /tmp/onyx-test.json` → file written (99,555 bytes), valid JSON, 2 findings, target correct; exit 5.
16. ✅ PASS — `--stream` → 2 JSON Lines emitted as found; first line `{"slug":"elementor","type":"plugin",...41 vulns}`.

### E. HTTP Davranışı

17. ✅ PASS — `--user-agent "Mozilla/5.0 TestUA"` → all 21 requests logged with exactly that UA (0 non-matching) — verified via local UA-logging sim (127.0.0.1:18473).
18. ✅ PASS — `--random-user-agent` → 8 distinct real browser UAs over 21 requests (Chrome/Firefox/Edge/Safari variants). Rotation confirmed; consecutive duplicates can occur (random pick per request).
19. ✅ PASS — `--rate-limit 3` → measured 3.0 req/s over scan phase (26 requests on local sim: baseline 2.8s incl. DB load; limited run 11.4s).
20. ✅ PASS — `--stealth` → measured 1.0 req/s (21 requests over ~21s scan phase, 23.8s wall incl. 2.8s DB load).
21. ✅ PASS — `--connect-timeout 5 --request-timeout 5` → clean run on real bench (exit 5, both plugins, zero stderr errors). Against a local server sleeping 30s/request, run finished in 12.7s — request timeouts enforced (would otherwise be ~126s).
22. ❌ FAIL — `--proxy http://127.0.0.1:1` → exit **0** (expected 2), `is_wordpress: true`, `evidence: ['homepage fetch failed: ... proxyconnect tcp: dial tcp 127.0.0.1:1: connect: connection refused']`. See Failures table — fetch failure counted as WP evidence.
23. ✅ PASS — 429 sim (127.0.0.1:18155) → JSON `rate_limit_hits: 5`, stderr shows `[INF] rate limited (429) — backing off 1s` ×5; scan still completed, exit 5.

### F. Cache

24. ❌ FAIL (partial) — `--cache-ttl 24` twice: local sim 47 → 9 live requests (200s served from cache; 17 cache files), but real bench 6.5s → 6.2s (1.1x). 404 brute-force misses are never cached, so the "second scan fast" claim doesn't hold for realistic scans. See Failures table.

### G. Sınırlar ve Exclusions

25. ✅ PASS — `--max-scan-duration 3s` on bench → JSON `timed_out: true`, stderr `[WARN] scan timed out after 3s — results may be incomplete`; partial results returned, exit 5.
26. ✅ PASS — `--exclude-content-based "Cloudflare"` → no match on bench homepage, scan proceeds normally (2 findings, exit 5).
27. ✅ PASS — `--scope ".*ddev\.site"` → in scope, 2 findings, exit 5. `--scope ".*example\.com"` → `scan failed: target out of scope`, exit **2**.
28. ✅ PASS — `--plugins-list` (file with `# test list` + `elementor`) → exactly **one** plugin probed: `/wp-content/plugins/elementor/readme.txt` (no other plugin requests in sim log); detected elementor only.

### H. Config + Exit Codes

29. ✅ PASS — `--config /tmp/opencode/config.json` (`url` + `min_severity: high`, format table) → scanned the intended target, high+ findings only. CLI override check: config `min_severity: critical` + CLI `--min-severity low` → both plugins shown (CLI wins). Config `format: json` applied.
30. ✅ PASS (with caveat) — vulnerable target → exit **5** (tests 2/3/4); clean target (local sim, no findings) → exit **0** (tests 7/17); malformed URL `not-a-url` → `error: invalid target URL` exit **2**. Caveat: unreachable-but-valid host (`http://no-such-host-onyx-test.invalid`) also returns **0** — same fetch-failure-is-evidence bug as test 22; only malformed URLs exit 2.

### I. Regression

31. ✅ PASS — `go vet ./...` clean (exit 0); `go test ./...` (fresh, `-count=1`) all packages `ok`.
32. ✅ PASS — `onyx update --db /tmp/opencode/onyx-db-update.json` → fetched latest release from Boreas37/onyx-db, unpacked 151,590,613 bytes, exit 0. (GitHub network test; output written to /tmp, not the repo.)

## Root-cause notes (no code changes made)

- **Bug A (tests 22/30 caveat):** `detectWP` (scanner.go:811-816) returns `"homepage fetch failed: ..."` as evidence; `Scan` then sets `IsWordPress = coreVersion != "" || len(evidence) > 0` (scanner.go:1126-1128). Any network/proxy/TLS failure is therefore misclassified as a successful WordPress detection and the scan exits 0. A dead proxy should surface as a hard error (exit 2).
- **Bug B (test 5):** author redirect regex `^/author/([^/]+)` (scanner.go:53) doesn't match `Location: /blog/author/superadmin/` on subdirectory multisites; user enumeration also depends on `/?author=N` returning a 30x, but WP 7.x returns 200 with the author page for IDs ≥ 2 on this bench; and REST user listing is unparseable when PHP notices are emitted before JSON. Individually environment quirks, but combined: `--enumerate u` finds zero users on the real bench.
- **Bug C (test 24):** cache writes only HTTP 200 bodies (scanner.go:517-520); degrading to few effective hits for brute-force scans.

## Harness artifacts

- All outputs: /tmp/opencode/ (test2.out … test32 outputs, JSON bodies, UA-log sim server + req.log, config files, downloaded DB).
- No repository files were modified or committed (`git status` clean apart from pre-existing untracked docs/E2E_TEST_SPEC.md and this report).