package scanner

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// coreProbeHits counts requests per path on the core-override test server.
type coreProbeHits struct {
	mu   sync.Mutex
	hits map[string]int
}

func (h *coreProbeHits) count(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

// coreVersionProbeServer serves a WordPress homepage WITHOUT a generator
// meta tag (so the passive chain must go further) and answers every
// version-detection probe with a version-bearing RSS feed, counting hits
// per request URI. Without --wp-version the chain finds 9.9.9 via the
// first /?feed=rss2 probe; with it, none of the probes may fire.
func coreVersionProbeServer(t *testing.T) (*httptest.Server, *coreProbeHits) {
	t.Helper()
	h := &coreProbeHits{hits: make(map[string]int)}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RequestURI()
		h.mu.Lock()
		h.hits[key]++
		h.mu.Unlock()
		switch key {
		case "/":
			_, _ = w.Write([]byte(`<html><body>wp-content referenced</body></html>`))
		case "/?feed=rss2", "/feed/", "/feed/atom", "/wp-links-opml.php":
			_, _ = w.Write([]byte(`<rss><channel><generator>https://wordpress.org/?v=9.9.9</generator></channel></rss>`))
		case "/wp-login.php":
			_, _ = w.Write([]byte(`<input name='log' id='user_login' />`))
		case "/wp-json/":
			_, _ = w.Write([]byte(`{"name":"fake"}`))
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux), h
}

// TestDetectWPCoreVersionOverride verifies --wp-version pins the core
// version: the version-detection chain (rss/opml/asset/fingerprint, plus
// the wp-login/wp-json evidence fetches) is skipped entirely while the
// homepage is still fetched for passive evidence. The override carries its
// own CoreEvidence entry with source "override" and confidence 100.
func TestDetectWPCoreVersionOverride(t *testing.T) {
	srv, hits := coreVersionProbeServer(t)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{CoreVersionOverride: "6.4.2"})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "6.4.2" {
		t.Errorf("core version = %q, want 6.4.2 (override)", ver)
	}
	if !containsEvidence(ev, "core version overridden via --wp-version") {
		t.Errorf("evidence %v missing the override note", ev)
	}
	if len(sc.coreEvidence) != 1 ||
		sc.coreEvidence[0].Source != "override" ||
		sc.coreEvidence[0].Version != "6.4.2" ||
		sc.coreEvidence[0].Confidence != 100 {
		t.Errorf("coreEvidence = %+v, want [override 6.4.2 conf 100]", sc.coreEvidence)
	}
	// The homepage must still be fetched (passive detection depends on it),
	// but every version-detection probe is skipped.
	if hits.count("/") != 1 {
		t.Errorf("homepage fetched %d times, want 1", hits.count("/"))
	}
	for _, path := range []string{"/?feed=rss2", "/feed/", "/feed/atom", "/wp-links-opml.php", "/wp-login.php", "/wp-json/"} {
		if n := hits.count(path); n != 0 {
			t.Errorf("override still probed %s %d times, want 0", path, n)
		}
	}
}

// TestDetectWPCoreVersionOverrideScan verifies the override surfaces
// through a full Scan: WordPressVersion is the override and CoreEvidence
// carries the override entry.
func TestDetectWPCoreVersionOverrideScan(t *testing.T) {
	srv, _ := coreVersionProbeServer(t)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{CoreVersionOverride: "6.4.2"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("override must still pass the IsWordPress gate")
	}
	if res.WordPressVersion != "6.4.2" {
		t.Errorf("WordPressVersion = %q, want 6.4.2", res.WordPressVersion)
	}
	if len(res.CoreEvidence) != 1 || res.CoreEvidence[0].Source != "override" {
		t.Errorf("CoreEvidence = %+v, want a single override entry", res.CoreEvidence)
	}
}

// TestDetectWPNoOverrideRunsNormalChain verifies that without --wp-version
// the detection chain is untouched: the version comes from the first RSS
// probe and the CoreEvidence source is "rss".
func TestDetectWPNoOverrideRunsNormalChain(t *testing.T) {
	srv, hits := coreVersionProbeServer(t)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "9.9.9" {
		t.Errorf("core version = %q, want 9.9.9 from the RSS probe", ver)
	}
	if !containsEvidence(ev, "RSS feed generator") {
		t.Errorf("evidence %v missing the RSS source note", ev)
	}
	if len(sc.coreEvidence) != 1 || sc.coreEvidence[0].Source != "rss" {
		t.Errorf("coreEvidence = %+v, want a single rss entry", sc.coreEvidence)
	}
	if hits.count("/?feed=rss2") != 1 {
		t.Errorf("/?feed=rss2 probed %d times, want 1", hits.count("/?feed=rss2"))
	}
}
