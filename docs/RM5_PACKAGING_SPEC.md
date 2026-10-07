# onyx Roadmap — Madde 5: Packaging & Distribution

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: Madde 1-4 tamamlandı. Mevcut özellikleri KORU, kırma.
Bu madde ÇOĞUNLUKLA CI/dosya işi — Go kodundan çok repo yapılandırması.

SADECE şu 3 özelliği implement et:

## 1. GitHub Actions Release Workflow
- Yeni dosya: `.github/workflows/release.yml`
- Trigger: `on: push: tags: ['v*']`
- Job: multi-platform build (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
- Adımlar:
  1. checkout
  2. `actions/setup-go@v5` (go 1.23)
  3. `goreleaser` KULLANMA (external tool) — basit `go build` + `tar.gz`/`zip` paketleme adımları:
     - her platform için: `GOOS=x GOARCH=y go build -trimpath -ldflags "-s -w" -o onyx-<os>-<arch>` 
     - tar.gz (linux/darwin) + zip (windows)
  4. `softprops/action-gh-release@v2` ile release'e asset'leri ekle (tag'den otomatik)
  5. Checksum dosyası: `sha256sum onyx-* > checksums.txt` → asset
- Ayrıca: Docker image build + push (mevcut build-image.yml'i koru — release'de de çalışsın; ayrı durması sorun değil)
- Gereksinim: workflow dosyasını YAZ (test etme imkanı yok — syntax doğruluğunu kontrol et, YAML bozuk olmasın)

## 2. Homebrew Tap
- Yeni repo gerektirir ama sadece dosyaları hazırla: `docs/homebrew/onyx.rb` — formula şablonu:
  ```ruby
  class Onyx < Formula
    desc "Local-first WordPress vulnerability scanner"
    homepage "https://github.com/Boreas37/onyx"
    url "https://github.com/Boreas37/onyx/releases/download/vVERSION/onyx-darwin-arm64.tar.gz"
    sha256 "REPLACE_WITH_CHECKSUM"
    version "VERSION"
    def install
      bin.install "onyx"
    end
  end
  ```
- `docs/homebrew/README.md`: tap kurulum adımları (`brew tap Boreas37/homebrew-onyx`, `brew install onyx`)
- Not: gerçek tap repo'su AYRI bir GitHub repo'su ister (homebrew-onyx) — bunu sadece dokümante et, repo oluşturma

## 3. SBOM + Build Metadata (`onyx version --json`)
- `onyx version --json` → makine formatı:
  ```json
  {"version": "0.2.0", "go_version": "go1.23.4", "os": "linux", "arch": "arm64", "commit": "abcdef", "build_time": "2026-08-17T00:00:00Z"}
  ```
- Build metadata: `-ldflags "-X main.buildCommit=<sha> -X main.buildTime=<time>"` ile gömülür
- main.go'da: `var buildCommit, buildTime string` — boşsa "-" veya "unknown"
- CI'da (release workflow) bu ldflags ile build edilir; lokal build'de "unknown"
- Ayrıca basit SBOM: `docs/SBOM.md` — projenin bağımlılık listesi (stdlib only: GO tarafında 0 external dependency; sadece Go stdlib + build araçları: Docker, DDEV — not edilir)
- `onyx version` (düz): mevcut davranışı koru (`onyx 0.2.0`)
- Test: `--json` çıktısı geçerli JSON + doğru alanlar

## KALİTE
- go build/vet/test yeşil, mevcut testleri KIRMA
- Yeni dependency YOK
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: release workflow, homebrew formula template, version --json + build metadata"
- /tmp'ye YAZMA (t.TempDir)