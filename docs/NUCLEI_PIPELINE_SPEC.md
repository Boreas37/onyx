# onyx — Nuclei Pipeline Feature (RustScan --nmap tarzı)

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.

## Amaç
RustScan'ın `--nmap` parametresi gibi: onyx normal WP taramasını yapar, sonra
bulduğu zafiyetleri (CVE ID'leri) **otomatik olarak nuclei ile doğrular**.
Kullanıcı `--nuclei` flag'ini verirse pipeline devreye girer.

## Davranış

### `onyx scan <url> --nuclei`
1. Normal onyx taraması tamamlanır (mevcut akış, hiçbir şey değişmez)
2. `res.Findings`'ten tüm CVE ID'lerini topla (benzersiz, örn. CVE-2025-8081, CVE-2024-24934...)
3. Her CVE için template dosyasını bul:
   - `--nuclei-template-dir PATH` (default: `~/nuclei-templates` veya `$NUCLEI_TEMPLATES_DIR` env)
   - Yol: `<dir>/http/cves/2026/CVE-2026-XXXXX.yaml` — yıl klasörü CVE'nin yılına göre (2002-2026 arası; yıl klasörü yoksa `http/cves/` altında recursive ara)
   - Template bulunamazsa: `[WARN] no nuclei template for CVE-2026-XXXXX` → atla (hata değil)
4. Bulunan template'leri topla, tek nuclei çağrısı yap:
   ```
   nuclei -target <url> -t <template1> -t <template2> ... -json -silent
   ```
   - `-silent`: sadece match'leri basar
   - `-json`: JSONL çıktı
   - Eğer template sayısı fazlaysa (>10): tek tek değil, hepsini tek komutta geç
   - nuclei binary'si: `$NUCLEI_BIN` env veya `nuclei` (PATH'te ara; yoksa hata değil WARN + pipeline atla)
5. Nuclei çıktısını parse et (JSONL): her match için `template-id`, `matched-at`, `info.severity`, `info.name`, `matcher-name`
6. Sonuçları `Result`'a ekle:
   ```go
   type NucleiResult struct {
       TemplateID  string `json:"template_id"`
       CVE         string `json:"cve,omitempty"`
       MatchedAt   string `json:"matched_at"`
       Severity    string `json:"severity"`
       Name        string `json:"name"`
       MatcherName string `json:"matcher_name,omitempty"`
   }
   ```
   `Result.Nuclei []NucleiResult` alanı (JSON: `nuclei: [...]`)
7. Tablo çıktısında bölüm:
   ```
   Nuclei verification:
     [critical] [cve-2025-8081] Elementor File Read (matched at https://host/...)
   ```
8. Exit code: nuclei bulgu bulursa yine 5 (zaten findings varsa 5); sadece nuclei bulgu bulduysa da 5

### Flag'ler
- `--nuclei` — pipeline'ı aç
- `--nuclei-template-dir PATH` — template dizini (default: `~/nuclei-templates`)
- `--nuclei-args "..."` — nuclei'ye ekstra argümanlar (örn. `-H "X-Api-Key: x"` — dikkat: string olarak shell'e değil, direkt exec argümanlarına split edilecek)

### Pipeline hataları (yumuşak)
- nuclei binary yok → `[WARN] nuclei not found in PATH — skipping verification` → tarama sonucu normal döner
- template yok → WARN + atla
- nuclei exit != 0 → WARN + atla (nuclei match bulamayınca da 0 döner; crash'te 1 döner)

## Implementasyon Notları
- `internal/nuclei/` paketi yeni: `FindTemplate(dir, cve string) (string, bool)`, `Run(target string, templates []string, extraArgs []string) ([]NucleiResult, error)`
- exec.Command ile çalıştır; stdout'u satır satır oku (JSONL), her satırı parse et
- 60s timeout (context) — nuclei çok uzun sürerse kes
- `main.go`: `--nuclei`, `--nuclei-template-dir`, `--nuclei-args` flag'leri (elle parse'e ekle)
- Scan() sonrası pipeline main'de çalışır (scanner'ı kirletme — orkestrasyon main'de): findings'ten CVE topla → nuclei paketini çağır → res.Nuclei'ye yaz → raporla

## Testler
1. `FindTemplate`: `CVE-2026-69084` → `~/nuclei-templates/http/cves/2026/CVE-2026-69084.yaml` bulunur; bilinmeyen CVE → false
2. `Run` (mock): fake nuclei binary script'i yaz (PATH'e koy) — JSONL çıktı üretir → parse doğru
3. JSONL parse: `{"template-id":"CVE-2026-69084","info":{"name":"X","severity":"critical"},"matched-at":"http://x/","matcher-name":"y"}` → doğru struct
4. Pipeline entegrasyonu: minimal findings → nuclei çağrısı → res.Nuclei dolu

## KALİTE
- go build ./... && go vet ./... && go test ./... yeşil, mevcut testleri KIRMA
- Yeni dependency YOK (exec + encoding/json stdlib)
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: --nuclei pipeline — auto-verify findings with nuclei templates (RustScan --nmap style)"
- /tmp'ye YAZMA — her şey proje içinde (testlerde t.TempDir kullan)