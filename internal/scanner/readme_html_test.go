package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestExtractCoreVersionFromReadmeHTML exercises the readme.html core
// version extractor across the accepted shapes: the canonical
// <h1 id="version"> heading (with or without extra attributes), the looser
// "Version X.Y.Z" element form of older releases, and the rejects — no
// marker, a Version word without digits and prose that must not leak into
// the capture.
func TestExtractCoreVersionFromReadmeHTML(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{
			name: "canonical h1 id=version",
			body: "<h1 id=\"version\">Version 6.4.2</h1>",
			want: "6.4.2", ok: true,
		},
		{
			name: "h1 with attributes around the anchor",
			body: `<html><body><h1 class="wp-readme" id="version">Version 6.5.1</h1></body></html>`,
			want: "6.5.1", ok: true,
		},
		{
			name: "older bare element form",
			body: `<p align="center"><strong>Version 4.9.10</strong></p>`,
			want: "4.9.10", ok: true,
		},
		{
			name: "uppercase spelling via loose form",
			body: "<div>VERSION 5.2</div>",
			want: "5.2", ok: true,
		},
		{
			name: "prerelease suffix kept",
			body: `<h1 id="version">Version 6.5-RC2</h1>`,
			want: "6.5-RC2", ok: true,
		},
		{name: "no version at all", body: "<h1>Welcome!</h1>", want: "", ok: false},
		{
			name: "anchor without digits",
			body: `<h1 id="version">No digits here</h1>`,
			want: "", ok: false,
		},
		{name: "empty body", body: "", want: "", ok: false},
	}
	for _, c := range cases {
		got, ok := ExtractCoreVersionFromReadmeHTML(c.body)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: ExtractCoreVersionFromReadmeHTML = %q, %v; want %q, %v",
				c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestExtractCoreVersionFromReadmeHTMLCapsHostileVersions verifies a
// hostile multi-kilobyte "version" is capped to maxVersionLen runes.
func TestExtractCoreVersionFromReadmeHTMLCapsHostileVersions(t *testing.T) {
	body := `<h1 id="version">Version 9.` + strings.Repeat("9", 10000) + `</h1>`
	v, ok := ExtractCoreVersionFromReadmeHTML(body)
	if !ok {
		t.Fatal("expected the hostile version to be detected")
	}
	if len([]rune(v)) != maxVersionLen {
		t.Errorf("capped length = %d runes, want %d", len([]rune(v)), maxVersionLen)
	}
}

// readmeFallbackServer serves a homepage without any generator meta tag
// (so every cheaper core-version source must fail first), 404s the feed,
// OPML and asset candidates, and answers /readme.html with the given body.
// readmeHits counts /readme.html requests so tests can assert exactly when
// the extra fallback request is spent.
func readmeFallbackServer(homepage, readme string) (*httptest.Server, *atomic.Int64) {
	var readmeHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(homepage))
	})
	mux.HandleFunc("/readme.html", func(w http.ResponseWriter, r *http.Request) {
		readmeHits.Add(1)
		_, _ = w.Write([]byte(readme))
	})
	return httptest.NewServer(mux), &readmeHits
}

const readmeFixture = `<!DOCTYPE html>
<html><head><title>WordPress &#8250; ReadMe</title></head>
<body>
<h1 id="version">Version 6.4.2</h1>
<p>Semper Fi WordPress!</p>
</body></html>`

// TestDetectWPReadmeHTMLFallback drives detectWP against an install whose
// meta/feeds/OPML/assets are all stripped: the readme.html heading must
// become the core version, tagged source "readme-html" with confidence 75,
// after exactly ONE /readme.html request.
func TestDetectWPReadmeHTMLFallback(t *testing.T) {
	srv, hits := readmeFallbackServer("<html><body>hardened homepage</body></html>", readmeFixture)
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
	if ver != "6.4.2" {
		t.Fatalf("core version = %q, want 6.4.2 via readme.html", ver)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("/readme.html fetched %d times during detectWP, want 1", n)
	}
	if len(sc.coreEvidence) != 1 ||
		sc.coreEvidence[0].Source != "readme-html" ||
		sc.coreEvidence[0].Version != "6.4.2" ||
		sc.coreEvidence[0].Confidence != confReadmeHTML {
		t.Errorf("coreEvidence = %+v, want [readme-html 6.4.2 conf 75]", sc.coreEvidence)
	}
	if !containsEvidence(ev, "6.4.2") {
		t.Errorf("evidence %v does not mention 6.4.2", ev)
	}
	if got := sourceConfidence("readme-html"); got != confReadmeHTML {
		t.Errorf("sourceConfidence(readme-html) = %d, want %d", got, confReadmeHTML)
	}
}

// TestDetectWPMetaShortCircuitsReadme verifies the readme.html request is
// NOT spent when the generator meta tag already answered: the fallback
// chain only runs while earlier sources came up empty.
func TestDetectWPMetaShortCircuitsReadme(t *testing.T) {
	homepage := `<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.3.1" /></head><body>hello</body></html>`
	srv, hits := readmeFallbackServer(homepage, readmeFixture)
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
	if ver != "6.3.1" {
		t.Fatalf("core version = %q, want 6.3.1 from the meta tag", ver)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("/readme.html fetched %d times with a working meta tag, want 0", n)
	}
	if len(sc.coreEvidence) != 1 || sc.coreEvidence[0].Source != "meta" {
		t.Errorf("coreEvidence = %+v, want the single meta observation", sc.coreEvidence)
	}
}

// TestDetectWPUnreadableReadmeFallsThroughQuietly verifies a 404
// readme.html is a silent miss: no version, no readme evidence entry, no
// error — the scan just reports whatever other evidence exists.
func TestDetectWPUnreadableReadmeFallsThroughQuietly(t *testing.T) {
	// A plain static site: every probe (feeds, OPML, readme.html) 404s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>plain static page</body></html>"))
	}))
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
	if ver != "" {
		t.Errorf("core version = %q, want empty on a non-WordPress target", ver)
	}
	if containsEvidence(ev, "readme") {
		t.Errorf("evidence %v must not mention readme", ev)
	}
}
