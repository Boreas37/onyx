package scanner

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestTLSFingerprintConfigs verifies the hand-rolled TLSClientConfig
// variations differ in the fields WAFs inspect (CipherSuites and
// CurvePreferences) and pin the TLS version range.
func TestTLSFingerprintConfigs(t *testing.T) {
	chrome := tlsFingerprintConfig("chrome")
	firefox := tlsFingerprintConfig("firefox")
	generic := tlsFingerprintConfig("generic")
	for name, cfg := range map[string]*tls.Config{"chrome": chrome, "firefox": firefox, "generic": generic} {
		if cfg == nil {
			t.Fatalf("tlsFingerprintConfig(%q) = nil", name)
		}
		if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
			t.Errorf("%s version range = %d..%d, want TLS 1.2..1.3", name, cfg.MinVersion, cfg.MaxVersion)
		}
	}
	if reflect.DeepEqual(chrome.CipherSuites, firefox.CipherSuites) {
		t.Error("chrome and firefox must order cipher suites differently")
	}
	if reflect.DeepEqual(chrome.CurvePreferences, firefox.CurvePreferences) {
		t.Error("chrome and firefox must prefer curves differently")
	}
	if reflect.DeepEqual(generic.CipherSuites, firefox.CipherSuites) {
		t.Error("generic must be a distinct third cipher suite set")
	}
	if reflect.DeepEqual(generic.CurvePreferences, chrome.CurvePreferences) {
		t.Error("generic must be a distinct third curve set")
	}
	if tlsFingerprintConfig("bogus") != nil {
		t.Error("unknown fingerprint name must return nil")
	}
}

// TestRandomTLSFingerprintFromSet verifies random picks only come from the
// known combination set and actually rotate.
func TestRandomTLSFingerprintFromSet(t *testing.T) {
	cfg := func(name string) *tls.Config { return tlsFingerprintConfig(name) }
	inSet := func(c *tls.Config) bool {
		for _, name := range []string{"chrome", "firefox", "generic"} {
			if reflect.DeepEqual(c, cfg(name)) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c := randomTLSFingerprint()
		if !inSet(c) {
			t.Fatalf("random fingerprint %+v is not one of the known sets", c)
		}
		for _, name := range []string{"chrome", "firefox", "generic"} {
			if reflect.DeepEqual(c, cfg(name)) {
				seen[name] = true
			}
		}
	}
	if len(seen) != 3 {
		t.Errorf("random rotations only produced %v over 100 picks, want all 3 sets", seen)
	}
}

// TestNewScannerTLSFingerprint verifies the transport wiring for each mode:
// chrome/firefox pin a TLSClientConfig, random rotates per connection
// (DialTLSContext + no keep-alives) unless an HTTP proxy forces the
// per-scan fallback, and unknown modes are rejected.
func TestNewScannerTLSFingerprint(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	sc, err := NewScanner(d, "http://example.test", Options{TLSFingerprint: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	tr := sc.client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil {
		t.Fatal("chrome mode must set TLSClientConfig")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.CipherSuites, tlsFingerprintConfig("chrome").CipherSuites) {
		t.Error("transport cipher suites do not match the chrome set")
	}
	if tr.DialTLSContext != nil || tr.DisableKeepAlives {
		t.Error("chrome mode must keep normal connection pooling")
	}

	sc, err = NewScanner(d, "http://example.test", Options{TLSFingerprint: "firefox"})
	if err != nil {
		t.Fatal(err)
	}
	tr = sc.client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil {
		t.Fatal("firefox mode must set TLSClientConfig")
	}
	if reflect.DeepEqual(tr.TLSClientConfig.CipherSuites, tlsFingerprintConfig("chrome").CipherSuites) {
		t.Error("firefox transport must not reuse the chrome cipher set")
	}

	sc, err = NewScanner(d, "http://example.test", Options{TLSFingerprint: "random"})
	if err != nil {
		t.Fatal(err)
	}
	tr = sc.client.Transport.(*http.Transport)
	if tr.DialTLSContext == nil {
		t.Fatal("random mode must install a per-connection TLS dialer")
	}
	if !tr.DisableKeepAlives {
		t.Error("random mode must disable keep-alives for per-request rotation")
	}
	if tr.TLSClientConfig != nil {
		t.Error("random mode must not pin a fixed TLSClientConfig")
	}

	sc, err = NewScanner(d, "http://example.test", Options{TLSFingerprint: "random", Proxy: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	tr = sc.client.Transport.(*http.Transport)
	if tr.DialTLSContext != nil {
		t.Error("random + http proxy must not use DialTLSContext (unsupported by net/http)")
	}
	if tr.TLSClientConfig == nil {
		t.Error("random + http proxy must fall back to a fixed random TLSClientConfig")
	}

	if _, err := NewScanner(nil, "http://example.test", Options{TLSFingerprint: "edge"}); err == nil {
		t.Fatal("expected error for an unknown --tls-fingerprint mode")
	}
}

// TestNewScannerInsecureTLSComposition verifies InsecureTLS composes with
// every --tls-fingerprint branch instead of being overwritten by them:
// the flag survives the chrome/firefox and random+proxy config
// replacements (on a Clone, never on the shared fingerprint table) and a
// later fingerprint-only scan still gets the pristine shared config.
func TestNewScannerInsecureTLSComposition(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	sc, err := NewScanner(d, "https://example.test", Options{InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	tr := sc.client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureTLS alone must set InsecureSkipVerify")
	}

	for _, fp := range []string{"chrome", "firefox"} {
		sc, err = NewScanner(d, "https://example.test", Options{InsecureTLS: true, TLSFingerprint: fp})
		if err != nil {
			t.Fatal(err)
		}
		tr = sc.client.Transport.(*http.Transport)
		if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("InsecureTLS + %s fingerprint must keep InsecureSkipVerify", fp)
		}
		// The shared fingerprint table must stay pristine: a later scan
		// without InsecureTLS must not inherit the flag.
		sc2, err := NewScanner(d, "https://example.test", Options{TLSFingerprint: fp})
		if err != nil {
			t.Fatal(err)
		}
		if tr2 := sc2.client.Transport.(*http.Transport); tr2.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("%s fingerprint scan without InsecureTLS inherited skip-verify from the shared table", fp)
		}
	}

	sc, err = NewScanner(d, "https://example.test", Options{InsecureTLS: true, TLSFingerprint: "random", Proxy: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	tr = sc.client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureTLS + random/proxy fallback must keep InsecureSkipVerify")
	}
	if tlsFingerprintConfig("chrome").InsecureSkipVerify {
		t.Fatal("shared fingerprint table mutated by the random/proxy fallback")
	}
}

// TestInsecureTLSScansSelfSigned verifies the end-to-end behavior against a
// real TLS endpoint: a self-signed certificate fails the scan without
// InsecureTLS, succeeds with it, and the combination with a chrome
// fingerprint (which replaces TLSClientConfig wholesale) still succeeds.
func TestInsecureTLSScansSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hi</body></html>`))
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))

	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err == nil {
		t.Error("scan against a self-signed cert without InsecureTLS must fail")
	}

	sc, err = NewScanner(d, srv.URL, Options{InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Errorf("scan with InsecureTLS: %v", err)
	}

	sc, err = NewScanner(d, srv.URL, Options{InsecureTLS: true, TLSFingerprint: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Errorf("scan with InsecureTLS + chrome fingerprint: %v", err)
	}

	sc, err = NewScanner(d, srv.URL, Options{InsecureTLS: true, TLSFingerprint: "random"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Errorf("scan with InsecureTLS + random fingerprint: %v", err)
	}
}
