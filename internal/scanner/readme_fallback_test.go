package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestScanJobChangelogFallback verifies a plugin readme with NO "Stable
// tag:" line but a versioned Changelog section still yields a detection,
// tagged source "readme-changelog" with the matching confidence.
func TestScanJobChangelogFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/no-stable/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== No Stable ===
Contributors: team
Tags: things

== Changelog ==

= 2.4.1 =
* Fixed the thing
`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "no-stable", path: "/wp-content/plugins/no-stable/readme.txt"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].Version != "2.4.1" || detected[0].Source != "readme-changelog" || detected[0].Confidence != confReadmeChangelog {
		t.Errorf("detected = %+v, want 2.4.1 via readme-changelog (conf 70)", detected[0])
	}
}

// TestScanJobComposerFallbackMissingReadme verifies a plugin whose readme
// answers 404 still gets a version from composer.json, tagged source
// "composer" with the matching confidence.
func TestScanJobComposerFallbackMissingReadme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/composer-only/composer.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"composer-only","version":"5.0.2"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "composer-only", path: "/wp-content/plugins/composer-only/readme.txt"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].Version != "5.0.2" || detected[0].Source != "composer" || detected[0].Confidence != confComposer {
		t.Errorf("detected = %+v, want 5.0.2 via composer (conf 75)", detected[0])
	}
}

// TestScanJobComposerFallbackVersionlessReadme verifies the composer
// fallback also fires when the readme answers 200 but carries no usable
// version (no stable tag, no changelog).
func TestScanJobComposerFallbackVersionlessReadme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/no-version/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== No Version ===\nContributors: team\n\nNo stable tag, no changelog.\n"))
	})
	mux.HandleFunc("/wp-content/plugins/no-version/composer.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"no-version","version":"1.0.0"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "no-version", path: "/wp-content/plugins/no-version/readme.txt"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].Version != "1.0.0" || detected[0].Source != "composer" {
		t.Errorf("detected = %+v, want 1.0.0 via composer", detected[0])
	}
}

// TestScanJobComposerFallbackRejectsJunk verifies a composer.json whose
// body is not JSON (e.g. a rewritten homepage) yields no version, so the
// job reports nothing rather than a bogus detection.
func TestScanJobComposerFallbackRejectsJunk(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/junky/composer.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>rewritten homepage</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "junky", path: "/wp-content/plugins/junky/readme.txt"})
	if len(detected) != 0 {
		t.Errorf("junk composer.json must not produce a detection, got %+v", detected)
	}
}
