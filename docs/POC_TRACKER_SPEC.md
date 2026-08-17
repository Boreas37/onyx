# onyx — PoC Tracker Integration (SONRAKİ GÖREV — nuclei pipeline bitince yap)

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: `--nuclei` pipeline özelliği (NUCLEI_PIPELINE_SPEC.md) önce implement edilmeli.

## Amaç
nuclei pipeline'ı bir finding (match) ürettiğinde, kullanıcının CVE-PoC-Tracker
repo'sundan o CVE için **en çok yıldızı olan 5 PoC repo linkini** ve **tracker
repo linkini** çıktıya ekle. Kullanıcı "dahası burada" diyebilsin.

## Davranış

### `onyx scan <url> --nuclei` (nuclei finding ürettiğinde)
Her nuclei match'inin CVE'si için:
1. **CVE-PoC-Tracker'dan PoC linklerini bul** — lokal klon (varsayılan: `~/projects/cve-hunter/../cve-tracker` veya `$POC_TRACKER_DIR` env):
   - Tracker repo: `Boreas37/CVE-PoC-Tracker` (~1,114 CVE + ~1,996 PoC kaydı, markdown dosyalarında)
   - Format: `<yıl>/CVE-YYYY-XXXXX.md` dosyaları, içinde PoC repo linkleri
   - CVE dosyasını bul, içindeki GitHub repo linklerini çıkar (`https://github.com/<owner>/<repo>` desenleri)
2. **GitHub API ile yıldız sayılarını çek** (en çok yıldızlı 5'i seçmek için):
   - `GET https://api.github.com/repos/{owner}/{repo}` → `stargazers_count`
   - Rate limit dikkat: 5 link için 5 API çağrısı (60/hr unauth) — kabul edilebilir
   - `GITHUB_TOKEN` env varsa Bearer header olarak kullan
   - API hatasında: yıldız bilinmiyor → yıldız 0 varsay, yine de listele
3. **Top 5'i seç** (yıldıza göre azalan) — 5'ten az varsa hepsi
4. Çıktıya ekle:
   - `Result.PoCs []PoCLink` alanı:
     ```go
     type PoCLink struct {
         URL    string `json:"url"`
         Stars  int    `json:"stars"`
         CVE    string `json:"cve"`
     }
     ```
   - Tablo çıktısında bölüm:
     ```
     PoC references (from CVE-PoC-Tracker):
       CVE-2025-8081:
         ⭐ 1243  https://github.com/owner/repo1
         ⭐ 98    https://github.com/owner/repo2
         ...
       more: https://github.com/Boreas37/CVE-PoC-Tracker
     ```
   - JSON'da `pocs: [...]`
5. **Tracker repo linki her zaman eklenir:** `https://github.com/Boreas37/CVE-PoC-Tracker`

### Flag'ler
- `--poc-tracker-dir PATH` — tracker klonu dizini (default: `~/projects/cve-tracker`)
- `--no-pocs` — PoC aramayı kapat (sadece nuclei bulgusu)

### Yumuşak hatalar
- Tracker klonu yok → `[WARN] CVE-PoC-Tracker not found at <dir> — skipping PoC lookup`
- CVE dosyası tracker'da yok → atla (WARN yok, sessiz)
- GitHub API rate limit → yıldızlar 0 gösterilir, linkler yine listelenir

## Testler
1. Tracker'daki CVE markdown'ından repo linki çıkarma (fake dosya ile)
2. Yıldız sıralama: fake GitHub API server (httptest) ile 5+ link → top 5 seçimi
3. PoC yok / tracker yok → boş sonuç + WARN, crash yok

## KALİTE
- go build/vet/test yeşil, mevcut testleri kırma
- Yeni dependency YOK (net/http + encoding/json)
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: PoC tracker integration — top-5 starred PoC links per nuclei finding"
- /tmp'ye YAZMA (t.TempDir kullan)
