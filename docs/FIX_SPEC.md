# onyx — E2E Bug Fix Spec (3 bug)

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Kaynak: docs/E2E_TEST_RESULTS.md'deki kök neden analizi. SADECE bu 3 bug'ı düzelt, başka şeye dokunma.

## Bug A — Fetch hatası "WP evidence" olarak sayılıyor (KRİTİK)
**Belirti:** `--proxy http://127.0.0.1:1` → exit 0 (beklenen 2), `is_wordpress: true`. Erişilemeyen host da exit 0.
**Kök neden:** `detectWP()` (scanner.go ~811-816) homepage fetch hatasını `evidence`'a ekliyor: `"homepage fetch failed: <err>"`. Sonra `Scan()`: `IsWordPress = coreVersion != "" || len(evidence) > 0` — yani network/proxy/TLS hatası "WordPress bulundu" sayılıyor.
**Fix:**
1. `detectWP()` fetch hatasını **evidence'a EKLEME** — ayrı `fatalErr error` olarak döndür
2. `Scan()`: `fatalErr != nil` ise → `ErrNotWordPress` yerine yeni hata döndür (örn. `fmt.Errorf("cannot reach target: %w", err)`) + exit code 2
3. Yani: home'a hiç ulaşılamıyorsa (connection refused, timeout, proxy hatası, DNS) → sert hata + exit 2
4. Dikkat: **wp-login/wp-json fetch hataları** (ikincil istekler) bu davranışı değiştirmesin — sadece HOMEPAGE fetch'i fatal sayılır (WP tespitinin birincil kanıtı)
5. Test: `--proxy http://127.0.0.1:1` → exit 2 + "cannot reach target"; ulaşılamayan host → exit 2

## Bug B — User enumeration: subdirectory multisite + PHP notice prefix
**Belirti:** Test-bench'te `--enumerate u` → 0 kullanıcı (sim'de çalışıyor).
**Kök nedenler (3 ayrı):**
1. `authorSlugRe` (`^/author/([^/]+)` scanner.go:53) alt dizin multisite Location'unu yakalamıyor: `/blog/author/superadmin/`
2. REST `/wp-json/wp/v2/users` yanıtı PHP `Deprecated` notice'larıyla başlıyor → `json.Unmarshal` başarısız
3. `/?author=N` N≥2 için 30x yerine 200 dönüyor (WP 7.x) → redirect zinciri yok

**Fix:**
1. Regex'i genelleştir: `(?:^|/)author/([^/?#]+)` — herhangi bir dizin derinliğinde `/author/<slug>/` yakala (test-bench'in `/blog/author/superadmin/`'ını da)
2. `usersFromAPI`'de JSON parse'ı dayanıklı yap: body'de ilk `[` veya `{` karakterini bul, ondan sonrasını json.Unmarshal et (PHP notice prefix'lerini atla). Hiç `[`/`{` yoksa "unparseable" hata
3. `usersFromAuthors`'da 200 yanıtları da dene: 30x redirect yoksa ama `/author/<slug>/` sayfası 200 dönüyorsa, `?author=N` body'sindeki `<link rel="canonical" href=".../author/<slug>/">` veya body'deki `/author/<slug>/` referansını regex'le yakala → slug çıkar. Yani redirect OLMAZSA da body'den çıkarım yap
4. Test: sim'e `/blog/author/<slug>` formatında bench-benzeri davranış ekle (ya da unit test: authorSlugFromLocation'a `/blog/author/superadmin/` ver → "superadmin" dönmeli)

## Bug C — Cache 404'leri cache'lemiyor
**Belirti:** `--cache-ttl 24` ikinci tarama hızlanmıyor (6.5s→6.2s) çünkü brute-force probları 404 ve her seferinde yeniden isteniyor.
**Kök neden:** Cache sadece HTTP 200 body'lerini yazıyor (scanner.go ~517-520).
**Fix:**
1. 404 (ve 403/500 gibi deterministik olumsuz yanıtlar) da cache'lensin — cached entry: status code + body (body boş olabilir)
2. Cache hit'te: status code'u da geri ver (sadece body değil) — çağıran kod 404 görüp job'ı atlayabilsin
3. 5xx (500, 502, 503) cache'LEME — geçici hatalar, taze istek gerekli
4. Test: aynı hedefe `--cache-ttl 24` ile 2 kez tara → ikinci taramada brute-force istek sayısı da düşmeli (sadece 200'ler değil)

## KALİTE
- go build ./... && go vet ./... && go test ./... hepsi geçmeli, mevcut testleri KIRMA
- Her fix için unit test (yukarıdaki test talimatları)
- Mevcut E2E raporundaki PASS testleri gerilemesin
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "fix: fatal fetch errors exit 2, robust user enum (subdir multisite, PHP notices, no-redirect), cache negative responses"
- /tmp'ye YAZMA — her şey proje içinde