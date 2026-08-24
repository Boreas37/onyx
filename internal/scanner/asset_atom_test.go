package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestExtractCoreVersionFromAssets drives the pure extractor: the ?ver=
// cache-buster on core-released assets tracks the core version across the
// supported file names and path shapes.
func TestExtractCoreVersionFromAssets(t *testing.T) {
	cases := []struct {
		name string
		html string
		want string
		ok   bool
	}{
		{"emoji release under js/", `<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.1"></script>`, "7.1", true},
		{"emoji release without js/", `<script src="/wp-includes/wp-emoji-release.min.js?ver=7.1"></script>`, "7.1", true},
		{"wp-embed", `<script src="/wp-includes/js/wp-embed.js?ver=6.4.2"></script>`, "6.4.2", true},
		{"wp-util", `<script src="/wp-includes/js/wp-util.js?ver=6.5"></script>`, "6.5", true},
		{"wp-a11y", `<script src="/wp-includes/js/wp-a11y.js?ver=6.5.1"></script>`, "6.5.1", true},
		{"case-insensitive", `<SCRIPT SRC="/WP-INCLUDES/JS/WP-EMBED.JS?VER=6.4"></SCRIPT>`, "6.4", true},
		{"capture stops at next query param", `<script src="/wp-includes/js/wp-embed.js?ver=5.9&amp;x=1"></script>`, "5.9", true},
		{"query before ver not matched", `<script src="/wp-includes/js/wp-embed.js?m=1&ver=5.9"></script>`, "", false},
		{"non-core asset ignored", `<script src="/wp-includes/js/wp-other.js?ver=1.0"></script>`, "", false},
		{"no ?ver ignored", `<script src="/wp-includes/js/wp-embed.js"></script>`, "", false},
		{"no asset refs", `<html><body>hello</body></html>`, "", false},
		{"empty html", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ExtractCoreVersionFromAssets(c.html)
			if ok != c.ok || got != c.want {
				t.Errorf("ExtractCoreVersionFromAssets = (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}

// assetVerServer serves a homepage whose only core-version source is the
// ?ver= cache-buster on wp-emoji-release.min.js (no meta tag, no feeds, no
// opml, no fingerprint table).
func assetVerServer(meta string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>` + meta +
			`</head><body><script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.1"></script></body></html>`))
	})
	return httptest.NewServer(mux)
}

// TestDetectWPCoreVersionFromAssetFallback verifies the asset-ver fallback:
// when the meta tag and every feed/opml source fails, the homepage's
// core-asset ?ver= supplies the version, tagged source "asset-ver" with
// confidence confAssetVer.
func TestDetectWPCoreVersionFromAssetFallback(t *testing.T) {
	srv := assetVerServer("")
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "7.1" {
		t.Fatalf("core version = %q, want 7.1 from asset ?ver=", ver)
	}
	if len(sc.coreEvidence) != 1 ||
		sc.coreEvidence[0].Source != "asset-ver" ||
		sc.coreEvidence[0].Version != "7.1" ||
		sc.coreEvidence[0].Confidence != confAssetVer {
		t.Errorf("coreEvidence = %+v, want [asset-ver 7.1 conf 70]", sc.coreEvidence)
	}
	if !containsEvidence(ev, "7.1") {
		t.Errorf("evidence %v does not mention 7.1", ev)
	}
}

// TestDetectWPCoreVersionMetaBeatsAsset verifies the generator meta tag wins
// over the asset ?ver= cache-buster: the asset extractor is only consulted
// when every earlier source failed.
func TestDetectWPCoreVersionMetaBeatsAsset(t *testing.T) {
	srv := assetVerServer(`<meta name="generator" content="WordPress 6.4.2" />`)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ver, _, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "6.4.2" {
		t.Errorf("core version = %q, want 6.4.2 (meta must win over asset ?ver= 7.1)", ver)
	}
	if len(sc.coreEvidence) != 1 || sc.coreEvidence[0].Source != "meta" {
		t.Errorf("coreEvidence = %+v, want single meta source", sc.coreEvidence)
	}
}

// atomFeedServer serves a site whose RSS2 and /feed/ paths carry no
// generator, but whose /feed/atom feed does (WordPress emits the same
// wordpress.org/?v= generator URL in Atom feeds).
func atomFeedServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head></head><body></body></html>`))
	})
	mux.HandleFunc("/?feed=rss2", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/feed/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/feed/atom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><generator>https://wordpress.org/?v=6.4.3</generator></feed>`))
	})
	mux.HandleFunc("/wp-links-opml.php", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

// TestDetectWPCoreVersionFromAtomFeed verifies /feed/atom is tried as the
// third RSS-style candidate and its generator URL yields the version with
// the existing "rss" source label.
func TestDetectWPCoreVersionFromAtomFeed(t *testing.T) {
	srv := atomFeedServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
	if ver != "6.4.3" {
		t.Fatalf("core version = %q, want 6.4.3 from /feed/atom", ver)
	}
	if len(sc.coreEvidence) != 1 || sc.coreEvidence[0].Source != "rss" {
		t.Errorf("coreEvidence = %+v, want single rss source", sc.coreEvidence)
	}
	if !containsEvidence(ev, "6.4.3") {
		t.Errorf("evidence %v does not mention 6.4.3", ev)
	}
}
