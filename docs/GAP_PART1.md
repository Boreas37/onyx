# onyx Gap Implementation — PART 1 (4 özellik, KÜÇÜK görev)

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.

SADECE şu 4 özelliği implement et. Başka hiçbir şeye dokunma.

## 1. Random User-Agent + özel UA
- `--user-agent STRING`: tüm isteklerde UA header'ını değiştir
- `--random-user-agent`: her istekte rastgele UA (Chrome/FF/Safari/Edge ~8 gerçekçi string, sabit slice)
- Options'a `UserAgent string`, `RandomUA bool` ekle; scanner.NewScanner'da client'a uygula
- fetch()'te her istekte UA set et (transport RoundTripper veya Request.Header)

## 2. Detection Mode
- `--detection-mode passive|aggressive|mixed` (default mixed)
- Options'a `DetectionMode string` ekle
- buildJobs: passive = sadece homepage HTML slug'ları; aggressive = sadece DB top-N; mixed = ikisi
- Mevcut buildJobs mantığını koru, sadece koşullandır

## 3. `--format` çıktı flag'i (jsonl + sarif)
- `--format table|json|jsonl|sarif` (default table; `--json` eski flag `--format json` ile aynı)
- jsonl: her finding tek satır JSON
- sarif: SARIF 2.1.0 minimal (runs[0].tool.driver.name="onyx", results=findings)
- report paketine PrintJSONL, PrintSARIF ekle; main'de format'a göre seç

## 4. Exit Codes
- 0: tarama tamam, zafiyet yok (veya WP değil)
- 5: findings > 0
- 2: hata (geçersiz URL, DB yok, network fail)

## KALİTE
- go build ./... && go vet ./... && go test ./... hepsi geçmeli, mevcut testleri kırma
- Her özellik için en az 1 unit test (httptest)
- Yeni dependency YOK
- main.go elle arg-parse'e flag'leri ekle; usage() güncelle
- Commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: UA options, detection-mode, jsonl/sarif formats, exit codes"
- /tmp'ye yazma