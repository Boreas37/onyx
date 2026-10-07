# onyx Roadmap — Madde 4: Output & Reporting

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: Madde 1-3 tamamlandı. Mevcut özellikleri KORU, kırma.

SADECE şu 3 özelliği implement et:

## 1. CSV Çıktı Formatı (`--format csv`)
- `onyx scan URL --format csv` → CSV çıktı (stdout)
- Sütunlar: `slug,type,installed_version,cve,severity,title,affected_versions`
- Her zafiyet = bir satır (finding başına değil, vulnerability başına)
- CSV kuralları: virgül içeren değerler tırnaklanır, `\n` escape
- encoding/csv stdlib kullan
- `--output FILE` ile dosyaya da yazılabilir
- Test: virgül içeren title (örn. "Elementor, Website Builder") → doğru quote

## 2. `cli-no-colour` Format (`--format cli-no-colour`)
- `--format cli-no-colour`: renkli olmayan tablo (mevcut `--format table` ANSI kodları basar TTY'de)
- Bu format: ANSI kodları HİÇ basmaz (TTY olsa bile)
- Implementasyon: report.go'daki `useColor` global'ini fonksiyon parametresi yap veya package-level flag set et
- En temizi: `report.NoColor = true` package var'ı — PrintBanner/PrintTable renksiz basar
- `--format table` (default): mevcut davranış (TTY'de renk, pipe'ta yok)
- Test: cli-no-colour çıktısında `\x1b` (ESC) karakteri 0 adet

## 3. Scan Summary Statistics
- Tarama sonunda özet bölümü (tüm formatlarda — table ve cli-no-colour'da görünür; JSON'da `summary` alanı):
  ```
  Scan summary:
    Duration:    42.3s
    Requests:    512 (42 rate-limited)
    Detected:    2 components
    Findings:    104 vulnerabilities (2 critical, 7 high, 95 medium)
    Users found: 3
  ```
- JSON'da:
  ```json
  "summary": {"duration_ms": 42300, "requests": 512, "rate_limited": 42, "detected": 2, "findings": 104, "critical": 2, "high": 7, "medium": 95, "low": 0, "users": 3}
  ```
- Veri kaynakları: scanner.Result mevcut alanları + yeni sayaçlar:
  - `Requests int` — toplam HTTP istek sayısı (fetch()'te atomik sayaç)
  - `DurationMS int64` — scan süresi (Scan() başlangıç-bitiş)
  - Severity sayıları: findings'ten say (Critical/High/Medium/Low)
- `--no-summary` flag: özeti kapat
- Test: JSON summary alanı doğru doldurulur; requests sayacı fetch çağrılarıyla eşleşir

## KALİTE
- go build/vet/test yeşil, mevcut testleri KIRMA
- Yeni dependency YOK (encoding/csv stdlib)
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: csv output, cli-no-colour format, scan summary statistics"
- /tmp'ye YAZMA (t.TempDir)