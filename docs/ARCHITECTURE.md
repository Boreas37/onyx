# Architecture

```
onyx scan https://target.tld
  │
  ├─ update (optional) ──► wordfence-latest.json.gz  ──► data/wordfence.json
  │                           (+ delta → manifest.json)      (+ .idx sidecar, gob+gzip)
  │
  ├─ db.LoadCached ──► DB{Records, bySlug, topSlugs}   (Load falls back when .idx is stale)
  │
  ├─ scanner.NewScanner ──► http.Client (UA rotation, TLS fingerprint, SOCKS5/HTTP proxy,
  │   │                        per-host limiter) + rateLimiter (global 429 cooldown,
  │   │                        adaptive spacing, early abort)
  │   │
  │   └─ Scan() ──► detectWP (meta → rss → opml → asset ?ver → readme.html → fingerprint)
  │                  ├─ interestingFinders (static probes, content-checked)
  │                  ├─ buildJobs (passive slugs + rest-route slugs + 404-page refs
  │                  │             + top-N vuln slugs + popular seeds)
  │                  ├─ fetch loop (worker pool, semaphore = --threads)
  │                  │     └─ scanJob → ExtractVersionFrom{Readme,StyleCSS,Changelog,Composer}
  │                  │              → matchDatabase (version.InRanges)
  │                  └─ mergePassiveDetections (?ver= versions), user enumeration
  │                     (REST → author-sitemap → single-user → ?author=N → login oracle),
  │                     media probing (/?p=N), brute force (wp-login / XML-RPC multicall)
  │                     wp-cron ping probe, XML-RPC method inventory
  │
  ├─ intel.Enrich (EPSS + CISA KEV, cached; optional)
  │
  ├─ nuclei verification (--nuclei) + PoC lookup
  │
  └─ report (table/json/jsonl/sarif/csv/cyclonedx/md/html/junit/gitlab-sast)
       + Summary, RateLimitedAbort, ScannedAt, SchemaVersion
```

## Supply Chain

`onyx update` with `ONYX_DB_PUBKEY` verifies detached Ed25519 signatures
(minisign, Ed + pre-hashed ED via BLAKE2b) over the raw gz artifact, each
delta, `manifest.json`, and the optional `popular.json.gz` /
`fingerprints.json.gz` assets. The manifest's `generated_at` is
monotonicity-checked (downgrade guard) and delta entries are de-duplicated.
Deltas carry a semantic result digest (`result_semantic_sha256` = sha256
over `id\x00compact(record)\n` sorted by id) to detect corruption even
though byte-for-byte reconstruction is impossible by design.

## Concurrency

The worker pool spawns one goroutine per job gated by a semaphore; a
single `rlMu`-guarded rate-limit state (`cooldownUntil`, `sendSlot`,
`spacing`, `consecOK`, `abortRateLimited`) is shared; `-race` covers it.
Multi-target (`--jobs`) runs whole scans concurrently with a second
semaphore and worst-exit-code aggregation.
