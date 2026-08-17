# onyx — WPScan Gap Implementation Spec

Kaynak: `/home/boreas/projects/onyx/docs/wpscan-features.md` §8 (onyx Comparison Table).
Proje: `/home/boreas/projects/onyx` — Go, module `github.com/Boreas37/onyx`, stdlib only, tüm testler yeşil olmalı.

Bu spec, §8'deki eksiklerin **en yüksek değerli olanlarını** kapsar. Sırayla implement et, hepsini yapabildiğin kadar tamamla. Eksik bırakırsan raporda belirt.

## 1. Random User-Agent + özel UA (WAF engelleme)
- `--user-agent STRING` flag: tüm isteklerde `User-Agent` header'ını değiştir
- `--random-user-agent` flag: her istekte rastgele UA (liste: Chrome/FF/Safari/Edge ~10 gerçekçi UA string'i, sabit bir slice'tan)
- Default davranış değişmesin (Go-http-client kalır) — sadece flag verilince
- `--stealth` flag'i artık ayrıca random UA da uygulasın (rapor önerisi)

## 2. HTTP Proxy Desteği
- `--proxy URL` flag: http://, https://, socks5:// (socks5 için stdlib `golang.org/x/net/proxy` GEREKMEZ — sadece http/https destekle, socks'u "not supported" diye hata ver; ya da net/http Transport.Proxy ile http proxy yeterli)
- `http.Transport{Proxy: http.ProxyURL(...)}` — mevcut client'a bağla
- `--proxy-auth user:pass` flag (opsiyonel, URL içinde de olabilir)

## 3. Detection Mode Flag'leri (passive/aggressive/mixed)
- `--detection-mode passive|aggressive|mixed` (default mixed)
- `passive`: sadece homepage HTML referansları (aggressive brute-force YOK)
- `aggressive`: passive atla, sadece DB top-N brute-force
- `mixed`: ikisi birden (mevcut davranış)
- Options'a `DetectionMode string` ekle, buildJobs buna göre dallansın

## 4. XML-RPC Tespiti + Password Attack
- `xmlrpc.php` varlığını tara: `POST /xmlrpc.php` `system.listMethods` → 200 + "methodResponse" içeriyorsa aktif
- Sonuçta `XMLRPC bool` alanı + tabloda "XML-RPC: enabled" satırı
- `--password-attack` flag (opsiyonel, şimdilik SADECE tespit — brute-force attacker implement etme, sadece tespit + raporla; rapor §8'de "attack" kısmı ayrı yazılabilir)

## 5. Config Backup + DB Export Finder
- `--check config-backup` ve `--check db-export` (ya da tek `--checks cb,dbe` enum)
- `cb`: wp-config.php backup dosyalarını dene: `wp-config.php~`, `wp-config.php.bak`, `wp-config.bak`, `wp-config.php.old`, `wp-config.php.save`, `wp-config.php.swp`, `wp-config.txt`, `wp-config.php.txt`, `.wp-config.php.swp`, `wp-config.php.orig`
- `dbe`: `.sql`, `.sql.gz`, `.zip`, `.tar.gz`, `dump.sql`, `backup.sql`, `db.sql`, `database.sql`, `wp.sql` (kökte + /db/, /backup/, /sql/ alt dizinlerinde)
- Bulunan: `ConfigBackups []string`, `DBExports []string` Result alanları + tablo satırları
- Sadece HTTP 200 + non-trivial boyut (Content-Length > 100) kabul

## 6. Çıktı Formatları: jsonl + sarif
- `--format table|json|jsonl|sarif` (default table; `--json` eski flag kalır, `--format json` ile eşdeğer)
- `jsonl`: her bulgu tek satır JSON (streaming — scanner.Scan() sonrası değil, bulgu bulundukça basılabilir; basit: sonuçları iterate et, her finding satır bas)
- `sarif`: SARIF 2.1.0 JSON şeması (minimal: runs[0].tool.driver.name="onyx", rules=findings, results=her zafiyet — basit ama geçerli yapı)
- `--output FILE` ile birleşik çalışsın

## 7. Makine-Okunur Exit Codes
- 0: tarama tamam, zafiyet yok (veya WP değil)
- 5: zafiyet bulundu (findings > 0)
- 2: hata (target geçersiz, DB yok, network fail)
- README'de belgele

## 8. Ayrı Connect/Request Timeout
- `--connect-timeout S` (default 10) — dial timeout
- `--request-timeout S` (default 10) — toplam istek timeout (mevcut `--timeout` alias olarak kalsın)
- net.Dialer{Timeout: connect} + http.Transport

## 9. --wp-content-dir / --wp-plugins-dir
- `--wp-content-dir PATH` (default "wp-content")
- `--wp-plugins-dir PATH` (default "wp-content/plugins")
- Tarama path'leri bunları kullansın (buildJobs, passive regex → path'ler dinamik)

## 10. --exclude-content-based + --scope
- `--exclude-content-based REGEX`: homepage HTML'de REGEX eşleşirse taramayı durdur (WAF/error sayfası tespiti)
- `--scope REGEX`: sadece REGEX ile eşleşen URL'ler taransın (basit: sadece aynı host — advanced scope implement etme, flag kabul et ama sadece host-check yap)

## KALİTE GEREKSİNİMLERİ
- `go build ./...`, `go vet ./...`, `go test ./...` hepsi geçmeli
- Her yeni özellik için en az 1 unit test (httptest ile)
- Mevcut testleri KIRMA
- Stdlib only — yeni dependency YOK
- main.go'daki elle arg-parse'e yeni flag'leri ekle (--flag VALUE formatı)
- usage() çıktısını güncelle
- README.md: yeni flag'leri belgele, exit codes bölümü ekle
- Commit: `git -c user.name="Boreas37" -c user.email="" commit -m "feat: WPScan gaps — UA, proxy, detection modes, xmlrpc, config backup, jsonl/sarif, exit codes, timeouts, custom dirs, exclusions"`
- /tmp'ye YAZMA — her şey proje içinde

## DOĞRULAMA
1. `go build ./... && go vet ./... && go test ./...` — hepsi temiz
2. Smoke: `go build -o onyx . && ./onyx scan https://wpscan-vulnerability-test-bench.ddev.site --detection-mode passive --format jsonl` — JSONL satırları çıktıda
3. `./onyx scan ... --user-agent "Mozilla/5.0 (X11; Linux x86_64) Chrome/126" --xmlrpc` gibi kombinasyonlar çalışmalı
4. Exit code testi: zafiyetli hedefte `echo $?` → 5 olmalı
