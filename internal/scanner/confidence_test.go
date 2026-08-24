package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestSourceConfidenceMapping pins every Detected/CoreEvidence source to
// its canonical confidence score.
func TestSourceConfidenceMapping(t *testing.T) {
	cases := []struct {
		source string
		want   int
	}{
		{"readme", confReadmeStableTag},
		{"readme-changelog", confReadmeChangelog},
		{"style.css", confStyleCSS},
		{"composer", confComposer},
		{"meta", confMetaGenerator},
		{"rss", confRSSGenerator},
		{"opml", confOPMLGenerator},
		{"passive-ver", confPassiveVer},
		{"rest", confREST},
		{"auth-rest", confAuthREST},
		{"fingerprint", confFingerprint},
		{"mystery", 0},
	}
	for _, c := range cases {
		if got := sourceConfidence(c.source); got != c.want {
			t.Errorf("sourceConfidence(%q) = %d, want %d", c.source, got, c.want)
		}
	}
}

// TestPreferDetected pins the dedup ordering: version-known entries beat
// unknown ones, higher confidence wins, and on equal confidence the
// unauthenticated REST listing beats the authenticated inventory.
func TestPreferDetected(t *testing.T) {
	cases := []struct {
		name string
		a, b Detected
		want bool
	}{
		{"readme beats passive-ver",
			Detected{Slug: "x", Version: "3.0", Source: "readme", Confidence: confReadmeStableTag},
			Detected{Slug: "x", Version: "3.0", Source: "passive-ver", Confidence: confPassiveVer}, true},
		{"passive-ver loses to readme",
			Detected{Slug: "x", Version: "3.0", Source: "passive-ver", Confidence: confPassiveVer},
			Detected{Slug: "x", Version: "3.0", Source: "readme", Confidence: confReadmeStableTag}, false},
		{"rest beats auth-rest on tie",
			Detected{Slug: "x", Version: "1.0", Source: "rest", Confidence: confREST},
			Detected{Slug: "x", Version: "1.0", Source: "auth-rest", Confidence: confAuthREST}, true},
		{"auth-rest loses to rest on tie",
			Detected{Slug: "x", Version: "1.0", Source: "auth-rest", Confidence: confAuthREST},
			Detected{Slug: "x", Version: "1.0", Source: "rest", Confidence: confREST}, false},
		{"known beats unknown even at higher confidence",
			Detected{Slug: "x", Version: "1.0", Source: "readme", Confidence: confReadmeStableTag},
			Detected{Slug: "x", Version: "unknown", Source: "rest", Confidence: confREST}, true},
		{"unknown loses to known",
			Detected{Slug: "x", Version: "unknown", Source: "rest", Confidence: confREST},
			Detected{Slug: "x", Version: "1.0", Source: "readme", Confidence: confReadmeStableTag}, false},
		{"composer beats changelog",
			Detected{Slug: "x", Version: "2.0", Source: "composer", Confidence: confComposer},
			Detected{Slug: "x", Version: "2.0", Source: "readme-changelog", Confidence: confReadmeChangelog}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := preferDetected(c.a, c.b); got != c.want {
				t.Errorf("preferDetected(%+v, %+v) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

// TestScanConfidenceAttachedToSources runs a normal mixed scan against the
// fake WordPress site and verifies every detected component carries the
// confidence of its source (readme 95, style.css 90).
func TestScanConfidenceAttachedToSources(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	bySlug := make(map[string]Detected)
	for _, det := range res.Detected {
		bySlug[det.Slug] = det
	}
	if d, ok := bySlug["elementor"]; !ok || d.Version != "3.24.0" || d.Confidence != confReadmeStableTag {
		t.Errorf("elementor = %+v, want 3.24.0 with confidence %d", d, confReadmeStableTag)
	}
	if d, ok := bySlug["twentytwentyfour"]; !ok || d.Version != "1.1" || d.Confidence != confStyleCSS {
		t.Errorf("twentytwentyfour = %+v, want 1.1 with confidence %d", d, confStyleCSS)
	}
}

// TestScanDedupPassiveNeverOverridesReadme feeds a homepage whose passive
// ?ver= hint (confidence 60) contradicts the probed readme (confidence 95):
// the readme version must win, proving passive detection never overrides a
// stronger source.
func TestScanDedupPassiveNeverOverridesReadme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><script src="/wp-content/plugins/elementor/assets/x.js?ver=9.9.9"></script></body></html>`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== Elementor ===\nContributors: team\nTags: builder\nStable tag: 3.24.0\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, det := range res.Detected {
		if det.Slug != "elementor" {
			continue
		}
		if det.Version != "3.24.0" || det.Source != "readme" || det.Confidence != confReadmeStableTag {
			t.Errorf("elementor = %+v, want 3.24.0 via readme (conf 95), NOT the passive 9.9.9", det)
		}
		return
	}
	t.Errorf("expected an elementor detection, got %+v", res.Detected)
}
