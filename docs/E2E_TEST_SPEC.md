# onyx — UÇTAN UCA TEST SPEC (end-to-end verification)

Proje: /home/boreas/projects/onyx — Go, local-first WP vulnerability scanner.
Part 1-4 tüm WPScan gap özellikleri implement edildi. Şimdi HER ŞEYİ GERÇEKTEN test et ve bulduğun sorunları rapor et.

## Test Ortamları (hazır, kurma)

1. **Automattic test-bench (GERÇEK WP):** https://wpscan-vulnerability-test-bench.ddev.site
   - WP 7.0.4 multisite, Elementor 3.0.0 + Essential Addons 5.0.0 kurulu (ikisi de ZAFİYETLİ)
   - Kullanıcılar: superadmin, simpleadmin, editor, author, contributor, subscriber (şifre: password)
   - DB: /tmp/test-db.json (38,884 kayıt — aynı zamanda data/wordfence.json symlink'i)
2. **Local sim'ler (çalışıyor):** 18153 (users+author redirect), 18155 (her 8. istekte 429)

## Test Matrisi — HER KOMUTU GERÇEKTEN ÇALIŞTIR, çıktıyı doğrula

### A. Temel Tarama
1. `go build -o onyx .` → binary üretilmeli
2. `./onyx scan https://wpscan-vulnerability-test-bench.ddev.site --db /tmp/test-db.json`
   - ✅ elementor + essential-addons zafiyetleri bulunmalı (Critical + High görünmeli)
3. `./onyx scan https://wpscan-vulnerability-test-bench.ddev.site --db /tmp/test-db.json --json`
   - ✅ findings JSON'da, doğru alan adları
4. `./onyx scan https://wpscan-vulnerability-test-bench.ddev.site --db /tmp/test-db.json --min-severity high`
   - ✅ sadece High+; elementor 2, eael 7 zafiyet göstermeli (eskiden doğrulanmıştı)

### B. Enumerasyon Modları
5. `--enumerate u` → kullanıcılar (superadmin, simpleadmin, editor...)
6. `--enumerate p` → sadece plugin
7. `--enumerate t` → sadece theme
8. `--enumerate m` → media/interesting
9. `--checks cb,dbe,timthumb` → config backup/db export/timthumb kontrolü (test-bench'te muhtemelen yok — temiz raporlanmalı, crash yok)

### C. Detection Modları
10. `--detection-mode passive` → elementor bulunmalı (homepage referansı var)
11. `--detection-mode aggressive` → DB top-N brute-force
12. `--detection-mode mixed` (default) → ikisi

### D. Çıktı Formatları
13. `--format jsonl` → her finding tek satır JSON
14. `--format sarif` → geçerli SARIF 2.1.0 (jq ile doğrula: `.version == "2.1.0"`)
15. `--format json --output /tmp/onyx-test.json` → dosyaya yazıldı, geçerli JSON
16. `--stream` → jsonl streaming (bulgu anında basılır)

### E. HTTP Davranışı
17. `--user-agent "Mozilla/5.0 TestUA"` → isteklerde UA değişiyor (test-bench access log'undan veya sim'den doğrula)
18. `--random-user-agent` → her istek farklı UA
19. `--rate-limit 3` → saniyede max 3 istek (süre ölç)
20. `--stealth` → 1 req/s
21. `--connect-timeout 5 --request-timeout 5` → çalışıyor, hata yok
22. `--proxy http://127.0.0.1:1` → bağlantı hatası VERMELİ (exit 2) — proxy yönlendirmesi çalışıyor kanıtı
23. 429 sim (http://127.0.0.1:18155) → `rate_limit_hits > 0` ve backoff logları

### F. Cache
24. `--cache-ttl 24` ile aynı hedefe 2 kez tara → ikinci tarama hızlı (cache'ten)

### G. Sınırlar ve Exclusions
25. `--max-scan-duration 3s` → zaman aşımı, TimedOut raporlanmalı (yavaş hedef: test-bench yeterli)
26. `--exclude-content-based "Cloudflare"` → eşleşmezse tarama devam; test-bench'e uygunsa devam etmeli
27. `--scope ".*ddev\.site"` → test-bench kapsamda, çalışmalı; `--scope ".*example\.com"` → "out of scope" + exit 2
28. `--plugins-list` ile geçici dosya (elementor satırı) → sadece o plugin denenmeli

### H. Config + Exit Codes
29. `--config config.json` (url + min_severity) → çalışmalı, CLI flag'leri override etmeli
30. Exit codes: zafiyetli hedef → `echo $?` = 5; zafiyetsiz → 0; geçersiz URL → 2

### I. Regression
31. `go vet ./...` + `go test ./...` — hepsi yeşil
32. `onyx update` — DB güncellemesi çalışıyor (GitHub'dan çeker; bu testi /tmp'e çıktı vererek yap)

## RAPOR FORMATI — docs/E2E_TEST_RESULTS.md dosyasına yaz

```markdown
# onyx E2E Test Results (2026-08-17)

## Summary
- Total tests: N | Passed: N | Failed: N

## Failures (öncelik sırasıyla)
| # | Test | Komut | Beklenen | Gerçek | Sorun |

## Notes
- Her test için: ✅ PASS / ❌ FAIL + kanıt (çıktı snippet'i)
```

## KURALLAR
- /tmp'ye yazma YASAK değil — test çıktıları için /tmp OK (sadece repo'ya /tmp dosyası commit ETME)
- onyx Go kodunu DEĞİŞTİRME — sadece test et, rapor yaz
- Uydurma yok: test gerçekten çalışmadıysa FAIL yaz
- Commit YAPMA (sadece rapor dosyası oluştur, git'e ekleme — ya da ekle ama commit etme, bırak staged kalsın; en temizi: raporu yaz, commit ETME)
- Rapor İngilizce
