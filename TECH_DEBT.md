# TECH_DEBT.md — kanıtlanmış teknik borç (2026-09-10)

HEAD: `26a05336fb25c70223c95386e0d12066e97b2aa8` — dal: `tech-debt-maintenance`
Baseline: `go build` OK, `go vet` OK. `go test ./...` başlangıç hataları (hepsi platform/test-altyapı, ürün değil):
- `TestNucleiPipelineVerification` FAIL (mock `nuclei-mock` Windows'ta exec değil)
- `TestUpdateIncrementalChecksumNoOp` TempDir cleanup kilidi (Windows dosya kilidi)
- `internal/dbupdate TestGenerateKeypairFileModes` (Unix dosya modu Windows'ta tutmaz)
- `internal/nuclei` 4 FAIL (mock `nuclei` exec biti Windows'ta yok)
- `internal/scanner` tam süit >120sn (429/rate-limit testleri gerçek bekleme içeriyor; yavaş ama geçiyor)

Akış: CLI/config → hedef tespiti → sürüm çıkarımı → DB eşleştirme → rapor; update → manifest/delta/full → doğrulama → disk/index.

## P0 — doğruluk / veri kaybı / güvenlik (DÜZELTİLDİ, testli)
- [x] W-1 `main.go:1621` + `internal/watch/run.go`: eksik/hatalı tarama (`err`, `TimedOut`, `RateLimitedAbort`, `nil`) `resolved` üretip baseline'ı eziyordu. Çözüm: incomplete ise diff/save yok, exit 2. Test: `TestAuditIncompleteScanPreservesBaseline`.
- [x] S-1 `internal/scanner/scanner.go:headerTransport`: `--allow-foreign-redirect` + basic-auth/cookie/headers yabancı hosta sızıyordu. Çözüm: yalnızca aynı authority'de dekore et (`targetAuth`). Test: `TestAuditCredsNotLeakedOnForeignRedirect`.
- [x] V-1 `internal/version/compare.go`: operator/star/dash/bare uçlarda trailing junk sessizce kesiliyordu (fail-open). Çözüm: `parseStrictVersion` ile `qualifierTail` zorunluluğu. Test: `TestParseRangesErrors` genişletildi.
- [x] D-1 `internal/db/db.go`: tüm software'i bozuk kayıt ghost olarak kalıyordu. Çözüm: `len(rec.Software)==0` ise ekleme. Test: `TestAuditGhostRecordDropped`.
- [x] D-2 `internal/db/db.go:decodeSoftware`: structured slug normalize edilmiyordu (`Elementor` miss). Çözüm: `slugify` + `Type` lowercase/trim. Test: `TestAuditStructuredSlugNormalized`.
- [x] D-3 `internal/db/db.go:Lookup`: shallow copy `Software` slice/map paylaşıyordu. Çözüm: deep-copy. Test: `TestAuditLookupDeepCopy`.
- [x] D-4 `internal/db/index.go:LoadCached`: `rebuildFromIndex` hatası fallback'siz dönüyordu. Çözüm: hata halinde `Load`'a düş.

## P0 — updater (DÜZELTİLDİ)
- [x] U-1 `main.go:downloadFeed`: `http.DefaultClient` (timeoutsuz). Çözüm: `httpClient` (30sn).
- [x] U-2 `main.go:updateOptionalAssets`: aynı fd'ye okuma+yazma, truncate yok, fd/sig leak. Çözüm: ayrı decode temp + rename, close/remove.
- [x] U-3 `internal/dbupdate/manifest.go:FetchManifestRaw`: 4MiB sessiz kesme. Çözüm: max+1 oku, aşımda hata.
- [x] U-4 `internal/dbupdate/delta.go`: `result_records` mismatch dosyayı bırakıyordu. Çözüm: `os.Remove`.
- [x] U-5 `dbcmd.go:doctor --network`: manifest sig URL'yi dosya sanıyordu + timeoutsuz client. Çözüm: nil client + sig'yi temp dosyaya indirip doğrula.

## P1 — CLI/config (DÜZELTİLDİ, uyumluluk korunarak)
- [x] C-P1 `main.go`: 9 anahtar `setFlags`'te izlenmiyordu (enumerate, max-requests, crawl-pages, stealth, random-ua, no-brute, fail-on, strict-wp, per-host-rate-limit) → config CLI'yı eziyordu. Çözüm: parse'ta işaretle. Test: `TestAuditCliWinsOverConfig`.
- [x] C-P2 `main.go`: `--rate-limit 0` / `--per-host-rate-limit 0` (`0=unlimited`) flag'i düşüyordu. Çözüm: `>=0` ata + `setFlags`; geçersiz/negatifte mevcut sessiz-fallback korundu (`TestParseScanArgsWAFFlags` kilitliyor, exit-2'ye çevrilmedi).
- [x] C-P3 `main.go`: `--stream`→jsonl varsayılanı config tarafından eziliyordu. Çözüm: applyConfig/profile sonrası uygula. Test: `TestAuditStreamImpliesJsonlAfterConfig`.
- [x] M-4 `report.NoColor` sticky. Çözüm: `runScan` başında `report.NoColor = (o.format=="cli-no-colour")`.

## P1 — rapor (DÜZELTİLDİ, goldens korunarak)
- [x] O-1 `main.go:splitNucleiArgs`: tırnaklı argüman yutuluyordu. Çözüm: quote-aware splitter. Test: `TestAuditSplitNucleiArgsQuoted`.
- [x] O-2 `report.go`: SARIF `onyx:severity` whitelist'sizdi. Çözüm: `sevClass`. Goldens geçti.
- [x] O-3 `report_formats.go`: JUnit kontrol karakterleri sanitize edilmiyordu. Çözüm: `sanitize.Text` (rating/title/labels/patched); mesaj ön-eki `sevClass`'a ÇEVRİLMEDİ çünkü `TestWriteJUnitHostileFieldsRoundTrip` ham rating'i kilitliyor (şema uyumluluğu).
- [x] O-4 `report_formats.go`: Markdown CVE linki `CVE-1](evil` ile kırılabiliyordu. Çözüm: sıkı `isCVEID`, yoksa düz hücre.
- [x] S-2 `diffcmd.go:example-config`: format listesi eksikti. Çözüm: `gitlab-sast, cli-no-colour` eklendi.
- [x] C-1/C-2 `completion.go`: yanlış (`--content-dir/--plugins-dir`) ve eksik flag/subcommand'lar. Çözüm: `--wp-content-dir/--wp-plugins-dir`, eksik flag'ler, `-T`, bash `doctor/diff/example-config`, db `diff`.
- [x] C-3 `dbcmd.go`: trailing `--db` değersiz yutuluyordu. Çözüm: usage hatası (exit 2).
- [x] D-diff `diffcmd.go`: `unchanged` satırı `type` içermiyordu. Çözüm: `type/slug cve` formatı.

## P1 — watch/intel/nuclei (KISMEN)
- [x] W-3 `watch.go`: `New` sıralı değildi. Çözüm: `Slug/CVE` sort. Test: `TestAuditNewSorted`.
- [ ] W-2 tam key migrasyonu (baseline `typ+slug`): şema değişikliği + eski state uyumluluğu gerektiğinden YAPILMADI. `Resolved` typesiz kalıyor (eski baseline'da type yok); kalan iş.
- [x] I-1 `intel.go:Load`: EPSS/KEV all-or-nothing'dı. Çözüm: ikisini dene, ikisi de başarısızsa hata; kısmi yükle. Mevcut intel testleri geçti.
- [ ] I-2 `intel.go:parseEPSS` `sc.Err()` yoksayma: hard-error'a çevrilmedi çünkü `TestParseEPSSHostileInputs` kısmi-başarıyı kilitliyor. Davranış korunup NOT ile belgelendi; warnings-plumbing gerektirir (kalan iş).
- [x] N-1 `nuclei.go`: 64KB scanner limiti + `sc.Err` yoksayma + sınırsız stderr. Çözüm: 1MB buffer + Err kontrolü (partial + hata) + 1MB stderr cap. `TestParseLine` geçti; `Run` mock-exec Windows hataları önceden vardı, değişmedi.

## P1 — scanner HTTP (KISMEN)
- [x] S-2 `fetchHeaders`/`checkXMLRPC`/`fetchAuth`: 429 sayılmıyordu (`Summary.RateLimited` eksik). Çözüm: `noteRateLimited` (retry döngüsüne çekmeden, davranış korunarak). Mevcut XMLRPC/WPAuth testleri geçti.
- [x] S-3 `exploit.go:loginOracle`: 429'u masked sanıp duruyordu. Çözüm: 429 dalı (note + gate + `continue`). Mevcut oracle testleri geçti.
- [x] S-5 kısmi: oracle limiter `RateLimit`'i yok sayıyordu (sabit 1sn). Çözüm: `s.opts.RateLimit`'ten init. Brute (`wp-login`/`xmlrpc`) yollarına `lim`/`perHostWait` EKLENMEDİ: kod "deliberately do not gate on the enumeration cooldown" diyor ve brute zaten `bruteLim` ile 1/sn paced; davranış değişikliği riskiyle bu turda dokunulmadı.
- [ ] S-4 `--max-requests` job sayıyor (3x + retry aşımı): bütçe semantiği değişeceğinden YAPILMADI (karar gerekli).

## Bilinçli değiştirilmeyen (karar gerekli)
- M-1 `--output/--outputs` çok hedefte son hedefe eziliyor: sessiz veri kaybı, ama düzeltme (reddetme veya suffix) çıkış/dosya davranışını değiştirir.
- M-2 exit `4` vs `5` tie order-dependent: rank değişikliği exit-code anlamını değiştirir.
- M-3 `--jobs N` stdout interleave + global `NoColor` race: sıralı tamponlu yazım gerekir (şema/stdout riski).
- S-4, W-2 tam migrasyon, I-2 warnings-plumbing, S-5 brute per-host: yukarıda gerekçeli.
- Windows'a özgü test-altyapı hataları (dosya modu, exec biti, TempDir kilidi): ürün hatası değil.
- Mirror/workflow/token tarafı kapsam dışı (AGENTS.md §2). `onyx-db`'de bakım yapılmadı, canlı mirror çalıştırılmadı.

## Doğrulama (gerçekten çalıştı)
- `go build ./...` OK, `go vet ./...` OK (son durumda).
- `go test ./internal/version/ ./internal/db/ ./internal/report/ ./internal/watch/ ./internal/intel/` OK.
- `go test ./internal/dbupdate/` tek FAIL: önceden var olan `TestGenerateKeypairFileModes` (Windows modu).
- `go test . -run TestParseScanArgs|TestProfile|TestAudit` OK; `TestUpdate*`'ta önceden var olan Windows kilit FAIL'i dışında OK.
- Hermetik e2e (bash yokluğunda Python eşdeğeri): fake WP + minimal feed ile `ptum` taraması exit 5, version 7.1, acme-toolbox 1.2.0, users admin, decoy FP yok — GEÇTİ.
- `scripts/e2e.sh` bash yokluğunda Windows'ta koşturulamadı ("geçti" yazılmadı); `scripts/e2e-realwp.sh` Docker/WP lab gerektirdiğinden koşturulmadı.
- Fuzz: bu turda kısa fuzz koşturulmadı (Windows + süre); parser/renderer değişiklikleri mevcut seed-corpus testleriyle (`FuzzParse`/`FuzzInAffected` seed'leri, `TestWriteJUnitHostileFieldsRoundTrip`) doğrulandı.
