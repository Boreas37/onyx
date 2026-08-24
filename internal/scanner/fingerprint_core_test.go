package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// emojiBody is the exact bytes served for the fingerprinted core asset; its
// md5 (e7aa5f688646b1a822e3026e8fc4ba92) is the one the in-repo
// testdata/fingerprint.json table maps onto WordPress 6.1/6.2.
const emojiBody = "/* wp-emoji-release placeholder */\n"

// fingerprintCoreServer serves the fingerprinted emoji asset (and 404s the
// polyfill asset listed second in the table).
func fingerprintCoreServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-includes/js/wp-emoji-release.min.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(emojiBody))
	})
	return httptest.NewServer(mux)
}

// TestFingerprintCoreFromFixture drives fingerprintCore against the tiny
// in-repo fixture table: the served emoji asset matches the fixture md5 and
// yields the first listed version.
func TestFingerprintCoreFromFixture(t *testing.T) {
	srv := fingerprintCoreServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{
		FingerprintDB: filepath.Join("testdata", "fingerprint.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := sc.fingerprintCore()
	if !ok {
		t.Fatal("fingerprintCore found nothing, want 6.1")
	}
	if v != "6.1" {
		t.Errorf("fingerprintCore version = %q, want 6.1 (first listed version)", v)
	}
}

// TestDetectWPFingerprintFallback verifies the fingerprint table is used as
// a final core-version fallback when every cheaper source comes up empty:
// the scan reports the fingerprinted version, tagged source "fingerprint"
// with confidence confFingerprint.
func TestDetectWPFingerprintFallback(t *testing.T) {
	srv := fingerprintCoreServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{
		FingerprintDB: filepath.Join("testdata", "fingerprint.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "6.1" {
		t.Fatalf("core version = %q, want 6.1 via fingerprint", ver)
	}
	if len(sc.coreEvidence) != 1 ||
		sc.coreEvidence[0].Source != "fingerprint" ||
		sc.coreEvidence[0].Version != "6.1" ||
		sc.coreEvidence[0].Confidence != confFingerprint {
		t.Errorf("coreEvidence = %+v, want [fingerprint 6.1 conf 85]", sc.coreEvidence)
	}
	if !containsEvidence(ev, "6.1") {
		t.Errorf("evidence %v does not mention 6.1", ev)
	}
}

// TestFingerprintCoreMissingTableDegradesGracefully verifies a nonexistent
// --fingerprint-db path is a soft skip: the fingerprint probe finds nothing
// and a full Scan still succeeds without error.
func TestFingerprintCoreMissingTableDegradesGracefully(t *testing.T) {
	srv := fingerprintCoreServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{
		FingerprintDB: filepath.Join("testdata", "does-not-exist.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := sc.fingerprintCore(); ok {
		t.Errorf("missing table reported %q, want no result", v)
	}
	// A bare (non-WordPress) homepage makes Scan report ErrNotWordPress —
	// the point is that a broken fingerprint table must never abort or
	// panic the scan beyond that.
	if _, err := sc.Scan(); err != nil && err != ErrNotWordPress {
		t.Fatalf("Scan with missing fingerprint table: %v", err)
	}
}

// TestFingerprintCoreBrokenTableDegradesGracefully verifies an unparseable
// --fingerprint-db file is also a soft skip: no panic, no result, and the
// scan keeps working.
func TestFingerprintCoreBrokenTableDegradesGracefully(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := fingerprintCoreServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{FingerprintDB: broken})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := sc.fingerprintCore(); ok {
		t.Errorf("broken table reported %q, want no result", v)
	}
	if _, err := sc.Scan(); err != nil && err != ErrNotWordPress {
		t.Fatalf("Scan with broken fingerprint table: %v", err)
	}
}

// TestFingerprintCoreDisabledWithoutOption verifies fingerprintCore is a
// no-op when no --fingerprint-db was configured.
func TestFingerprintCoreDisabledWithoutOption(t *testing.T) {
	srv := fingerprintCoreServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := sc.fingerprintCore(); ok {
		t.Errorf("fingerprintCore without a table reported %q", v)
	}
}

// containsEvidence reports whether any evidence string mentions want.
func containsEvidence(ev []string, want string) bool {
	for _, e := range ev {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}
