# onyx Roadmap — Madde 3: Data Layer

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: Madde 1-2 tamamlandı. Mevcut özellikleri KORU, kırma.

SADECE şu 4 özelliği implement et:

## 1. Scanner Feed Desteği (`onyx update --feed scanner`)
- Wordfence iki feed sunar: `production` (detaylı, doğrulanmış) ve `scanner` (geniş kapsam, noisier)
- `onyx update --feed scanner` → scanner feed'ini indirir (URL: https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner, aynı auth)
- `onyx update` (default) → production (mevcut davranış)
- `--db` ile farklı dosyaya kaydet (örn. `data/wordfence-scanner.json`)
- scanner feed kayıtları production'dan farklı bir şemada olabilir (minimal: sadece detection bilgisi) — db.Load'ın bunu tolere etmesi gerekir:
  - `software` alanı yoksa / boşsa: `title` içindeki "Plugin Name < X.Y.Z" deseninden slug + version aralığı çıkar (regex: `(.+) (?:<|<=|=) ([0-9.]+)`)
  - Parse edilemeyen kayıtlar atlanır (db.skipped sayacı zaten var)
- Test: minimal scanner-feed formatı (title-based) → db.Load doğru yükler

## 2. Incremental DB Updates + Checksum (`onyx update`)
- Feed indirirken SHA-256 checksum hesapla (indirilen gzip)
- `data/wordfence.json.sha256` dosyasına yaz (yanına)
- Sonraki `onyx update`'te: önce checksum'ı oku, yeni indirilenle karşılaştır:
  - Aynı → "already up to date" mesajı + dosyayı DEĞİŞTİRME (0 byte yazma, hızlı)
  - Farklı → normal güncelle
- Bu, her güncellemede gereksiz 151MB yazmayı önler (sadece feed gerçekten değişince)
- Ayrıca `--force` flag: checksum kontrolünü atla, her zaman yaz
- Test: aynı checksum → no-op; farklı → yazılır; --force → her zaman yaz

## 3. `--no-update` Flag
- `onyx scan --no-update`: scan başında "DB yoksa otomatik indir" davranışını kapatır — DB yoksa direkt hata (exit 2)
- Mevcut: DB yoksa otomatik update. Bu flag verilirse: hata
- Test: --no-update + eksik DB → exit 2

## 4. Staleness Prompt Geliştirme
- Mevcut: 14 gün + `--no-update-check` bastırma (Part 3'ten)
- Geliştirme: uyarıya DB yaşını gün olarak ekle + feed tipini göster:
  `[WARN] database is 20 days old (production feed) — run 'onyx update' for fresh data`
- DB yaşı: mtime'den değil, indirme zamanından hesapla — `data/wordfence.json.sha256` yoksa mtime fallback (mevcut)
- Ayrıca: `data/wordfence.json.feedtype` dosyasına feed tipini yaz (production/scanner) — update'te okunur, uyarıda gösterilir
- Test: yaş + feed tipi doğru görüntülenir

## KALİTE
- go build/vet/test yeşil, mevcut testleri KIRMA
- Yeni dependency YOK (crypto/sha256 stdlib)
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: scanner feed support, incremental checksum updates, --no-update, richer staleness"
- /tmp'ye YAZMA (t.TempDir)