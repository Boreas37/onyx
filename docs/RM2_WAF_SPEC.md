# onyx Roadmap — Madde 2: WAF Evasion & Hardening

Proje: /home/boreas/projects/onyx — Go, module github.com/Boreas37/onyx, stdlib only.
Önkoşul: Madde 1 (exploit checks) tamamlandı — mevcut tüm özellikleri KORU, kırma.

SADECE şu 4 özelliği implement et:

## 1. SOCKS5 Proxy Desteği (`--proxy socks5://...`)
- `--proxy socks5://host:port` ve `socks5h://host:port` formatlarını kabul et (socks5h = DNS proxy üzerinden)
- Mevcut http/https proxy desteği korunur
- Implementasyon: `golang.org/x/net/proxy` GEREKMİYOR — Go 1.23'te `net/http.Transport.DialContext` ile elle SOCKS5 handshake yapmak zor; ama kural "yeni dependency YOK" ise:
  - ALTERNATİF: stdlib'de SOCKS5 client yok. Basit bir SOCKS5 CONNECT handshake implement et (RFC 1928): greeting (0x05, nmethods=1, no-auth 0x00) → CONNECT isteği → yanıt. ~60 satır, sadece TCP bağlantı kurma.
  - DialContext'i custom dialer ile değiştir: `Transport.DialContext = func(ctx, network, addr) { conn := socks5Dial(proxyAddr, addr); return conn }`
- `--proxy-auth user:pass` flag: SOCKS5 username/password auth (RFC 1929) — opsiyonel, verilirse kullan
- Test: fake SOCKS5 server (net.Listen + basit handshake yanıtları) ile bağlantı doğrula

## 2. TLS Fingerprint Rotation (`--tls-fingerprint MODE`)
- MODE: `chrome` | `firefox` | `random` (default: off — mevcut davranış)
- Implementasyon kısıtı: gerçek JA3 fingerprint (uTLS) yeni dependency ister — YAPMA. Bunun yerine:
  - `--tls-fingerprint chrome/firefox`: `Transport.TLSClientConfig`'te el yapımı farklılıklar uygula: `MaxVersion` (TLS 1.3), `MinVersion`, `CipherSuites` seçimi (Chrome: TLS_AES_128_GCM_SHA256 + X25519 öncelikli), `CurvePreferences` (X25519), `NextProtos` (h2, http/1.1)
  - `random`: her istekte yukarıdaki parametre setlerinden rastgele birini seç (2-3 farklı kombinasyon tanımla)
  - Bu gerçek JA3 rotasyonu değil ama TLSClientConfig varyasyonu — WAF'ların basit TLS parmak izi kontrollerine karşı işe yarar
- Options'a `TLSFingerprint string` ekle; NewScanner'da transport'u buna göre yapılandır
- Test: TLS config varyasyonlarının farklı olduğunu doğrula (unit test — CipherSuites/CurvePreferences farklı)

## 3. Per-Host Rate Limiting (`--per-host-rate-limit N`)
- `--per-host-rate-limit N`: her benzersiz host için ayrı rate limit (N req/s)
- Fark: mevcut `--rate-limit` GLOBAL (tüm istekler tek sayaç); per-host her hedef host için kendi limiter'ı
- Implementasyon: `map[string]*rateLimiter` + mutex — her host (scheme://host:port) ayrı limiter
- `--rate-limit` ve `--per-host-rate-limit` birlikte verilirse: per-host host bazında, global toplamda da uygulanır (ikisi birden çalışır)
- Test: 2 host'a istek at (fake server'lar), per-host limiter'ların ayrı çalıştığını doğrula (host A hızlı, host B yavaş)

## 4. `--proxy-target-only`
- Flag: `--proxy-target-only` — proxy yalnızca TARANAN HEDEF için kullanılır (diğer bağlantılar direkt)
- Mevcut davranış: proxy tüm isteklere uygulanır. Bu flag verilirse: proxy sadece hedef host'a giden isteklerde kullanılır
- Implementasyon: custom DialContext — hedef host match ederse proxy, değilse direkt dial
- Test: hedef host proxy'den geçer, diğer host direkt (fake proxy + fake server logları)

## KALİTE
- go build ./... && go vet ./... && go test ./... hepsi geçmeli, mevcut testleri KIRMA
- Yeni dependency YOK (SOCKS5 elle implement, TLS config stdlib)
- Her özellik için unit test
- main.go elle arg-parse'e flag'leri ekle; usage() güncelle
- commit: git -c user.name="Boreas37" -c user.email="" commit -m "feat: socks5 proxy, tls fingerprint rotation, per-host rate limit, proxy-target-only"
- /tmp'ye YAZMA (t.TempDir kullan)