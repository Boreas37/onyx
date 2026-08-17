# onyx — PoC Tracker Fix: Gerçek Format Desteği

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: POC_TRACKER_SPEC.md implement edildi ama GERÇEK tracker formatıyla uyumsuz. Düzelt.

## SORUN (doğrulandı)
CVE-PoC-Tracker gerçek yapısı: `<yıl>/CVE-YYYY-XXXXX.md` **DOSYALARI YOK**.
Gerçek yapı: her yıl klasöründe TEK `README.md` — markdown **tablo** formatında:
```
| CVE | Target repository | Stars | Description |
|---|---|---|---|
| [CVE-2026-0073](https://github.com/xqi1337/poc-CVE-2026-0073) | [xqi1337/poc-CVE-2026-0073](https://github.com/xqi1337/poc-CVE-2026-0073) | 1 | desc |
| [CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | [0xbinder/CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | 26 | desc |
```
- Sütunlar pipe (`|`) ile ayrılmış: CVE | Target repository | Stars | Description
- Aynı CVE birden çok satırda (birden çok PoC repo)
- Stars sütunu zaten var (ama taze değil — GitHub API ile güncellemek yine iyi)
- Kök `README.md` de "1,114 CVEs · 1,996 PoC repositories" özeti

## FIX
`internal/pocs/pocs.go`'daki `ExtractLinks` (ve `cvePath`) mantığını değiştir:

1. **CVE dosyası aramayı BIRAK** — onun yerine:
   - `<dir>/<yıl>/README.md` dosyasını aç (yıl = CVE'den çıkar, örn. CVE-2026-0073 → 2026)
   - Dosya yoksa: tüm `<dir>/<yıl>/README.md` dosyalarında ara (WalkDir ile) — CVE'nin yılı farklı klasördeyse
2. **Tablo satırlarını parse et**: her satırda
   - `| CVE-XXXX-YYYY | [name](url) | stars | desc |` deseni
   - Satır CVE'mizle eşleşiyorsa → URL'yi çıkar (ilk `https://github.com/...` linki)
   - Stars sütununu da oku (fallback olarak kullan — GitHub API hata verirse bu değer kullanılır)
3. Dönüş: `[]ExtractedPoC{URL string, Stars int}` — mevcut API'ye uyum sağla (ExtractLinks imzası değişebilir ama main.go'daki kullanımı güncelle)
4. `Fetcher.Fetch`: link + fallback stars ile GitHub API'den GÜNCEL yıldızı çek; API hatası/rate limit'te tablodaki yıldızı kullan (0 yerine!) — spec'teki "error→0" yerine "error→table stars"

## TESTLER (gerçek formatla)
1. Fake tracker dir (t.TempDir): `2026/README.md` yaz — CVE-2026-0073 için 3 satır (farklı repolar, farklı stars) + başka CVE satırları → ExtractLinks sadece bizim CVE'nin linklerini döndürür, stars'lar doğru
2. CVE yılı farklı klasörde (örn. CVE-2025-XXXX `2025/README.md`) → bulunur
3. Tracker yok / README yok → boş + WARN (mevcut davranış korunur)
4. Fetch: fake GitHub API (httptest) → API stars'ı tablodan farklıysa API değeri kazanır; API 404/rate limit → tablo stars kullanılır

## DOĞRULAMA (canlı)
```
/tmp/cve-tracker gerçek tracker klonudur (1,114 CVE, 1999-2026 klasörleri)
go run ile ExtractLinks(/tmp/cve-tracker, "CVE-2026-0073") → ≥8 link dönmeli
CVE-2026-0257 → ≥4 link
```

## KALİTE
- go build/vet/test yeşil, mevcut testleri kırma (pocs_test.go'yu yeni formata güncelle)
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "fix: parse CVE-PoC-Tracker table format (year README.md), table stars as fallback"
- /tmp'ye YAZMA (t.TempDir)