# Görev: WPScan Tam Özellik Analizi (rapor üret)

Amaç: WPScan'ın TÜM kabiliyetlerini, CLI seçeneklerini, davranışlarını ve özelliklerini keşfedip kapsamlı bir rapor üret. Bu rapor daha sonra onyx (Go'da yazılmış local-first WordPress zafiyet tarayıcısı) için özellik ekleme kararlarında kullanılacak.

## Yapılacaklar (sırayla)

1. **WPScan repo'sunu klonla** (sadece okuma amaçlı — /tmp YASAK, proje içine klonla):
   ```
   cd /home/boreas/projects/onyx && rm -rf .wpscan-src && git clone --depth 1 https://github.com/wpscanteam/wpscan.git .wpscan-src
   ```

2. **CLI seçeneklerini çıkar**: `wpscan-src/lib/wpscan/` altındaki option tanımlarını incele (özellikle `lib/wpscan/options.rb` veya benzeri). Ayrıca `wpscan-src/README.md` ve `wpscan-src/spec/` dosyalarına bak.

3. **Dokümantasyonu tara**: WPScan'ın resmi dokümantasyonundan (wpscan.com/wordpress-security-scanner, github wiki) özellikleri doğrula.

4. **Rapor yaz** — `/home/boreas/projects/onyx/docs/wpscan-features.md` dosyasına (dizini yoksa oluştur). Rapor şu bölümleri içermeli:

   ### Rapor formatı (markdown):
   ```markdown
   # WPScan Özellik Envanteri (2026-08)
   
   ## 1. CLI Komut Yapısı ve Global Seçenekler
   - [her flag: adı, kısa açıklaması, varsayılan değeri]
   
   ## 2. Enumerasyon Modları (--enumerate)
   - Her mod: ne yapar, nasıl çalışır
   - u, vp, vt, p, t, ap, at, tt, cb, dbe, m, ve kombinasyonları
   
   ## 3. Tespit Modları (--detection-mode, --plugins-detection, --themes-detection)
   - passive / aggressive / mixed: ne fark var, hangi istekleri atıyor
   
   ## 4. Tarama Davranışı
   - rate limit, throttle, random user-agent, max-threads, request timeout
   - progress/verbose/quiet çıktı modları
   - output formatları (cli, json, csv) ve output dosyası
   
   ## 5. Özel Kontroller
   - config backup (cb), db export (dbe), medya (m), tema başlıkları (tt)
   - wp-login brute force, xmlrpc, password attack modları
   
   ## 6. API Entegrasyonu
   - api-token ne işe yarar, API ile neler değişir (vuln verisi, false positive azalması)
   
   ## 7. Diğer Kabiliyetler
   - force update, update, version, help davranışları
   - ssl/ignore-redirect, proxy, cookie, header özellikleri
   - exclude-content-based, plugins-version-detection gibi gelişmiş seçenekler
   
   ## 8. onyx ile Karşılaştırma Tablosu
   | Özellik | WPScan | onyx (mevcut) | onyx (eksik — öneri) |
   ```

5. **Doğrulama**: Raporun gerçek CLI seçeneklerine dayandığından emin ol — `wpscan-src` içindeki option tanımlarını gerçekten oku. Uydurma seçenek ekleme; bulamadığın şeyi "bulunamadı" diye işaretle.

## Kısıtlar
- Sadece ANALİZ + RAPOR — onyx kodunu DEĞİŞTİRME
- wpscan-src'ye commit/push YOK (sadece /tmp'de klon)
- Rapor dosyasını yaz (docs/wpscan-features.md)
- Git commit yapma (ana repo'ya dokunma — sadece rapor dosyası oluştur)
- Türkçe değil, İNGİLİZCE yaz raporu (teknik terimler aynen)
- Kapsamlı ol — WPScan'ın `--help` çıktısındaki HER seçeneği içer (exclude, include, plugins-version-detection, themes-version-detection, force, wp-content-dir, wp-plugins-dir, uploads-dir gibi sık kullanılmayanları da)
