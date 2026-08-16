package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"onyx/internal/db"
	"onyx/internal/version"
)

// minimalFeed writes a small Wordfence-shaped feed and returns its path.
func minimalFeed(t *testing.T) string {
	t.Helper()
	eleRanges, _ := version.ParseRanges("1.0.0 - 3.24.9")
	feed := map[string]any{
		"aaaaaaaa-0000-0000-0000-000000000001": map[string]any{
			"id":    "aaaaaaaa-0000-0000-0000-000000000001",
			"title": "Elementor < 3.25.0 - SQL Injection",
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Elementor", "slug": "elementor",
					"affected_versions": map[string]any{
						"1.0.0 - 3.24.9": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "3.24.9", "to_inclusive": true,
						},
					},
				},
			},
		},
		"bbbbbbbb-0000-0000-0000-000000000002": map[string]any{
			"id":    "bbbbbbbb-0000-0000-0000-000000000002",
			"title": "Twenty Twenty-Four < 1.2 - Stored XSS",
			"software": []any{
				map[string]any{
					"type": "theme", "name": "Twenty Twenty-Four", "slug": "twentytwentyfour",
					"affected_versions": map[string]any{
						"1.0.0 - 1.1": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.1", "to_inclusive": true,
						},
					},
				},
			},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Wire up a callable reference so the ranges are truly built.
	_ = eleRanges
	return path
}

// fakeWordPress serves a minimal WordPress-like site.
func fakeWordPress() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/themes/twentytwentyfour/style.css" />
<link rel="https://api.w.org/" href="http://example/wp-json/" /></body></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' type='text' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake","url":"http://example"}`))
	})
	mux.HandleFunc("/wp-json/wp/v2/plugins", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view","message":"Sorry, you are not allowed to list plugins."}`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Elementor ===
Contributors: elementorteam
Tags: page builder
Stable tag: 3.24.0
License: GPLv3

Elementor is a page builder.
`))
	})
	mux.HandleFunc("/wp-content/themes/twentytwentyfour/style.css", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`/*
Theme Name: Twenty Twenty-Four
Theme URI: https://wordpress.org/themes/twentytwentyfour/
Version: 1.1
Description: Some nice theme.
*/
body { margin: 0; }
`))
	})
	mux.HandleFunc("/wp-content/plugins/akismet/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Akismet ===
Stable tag: 5.3.1
— not yet present in the db, no vuln.
`))
	})
	return httptest.NewServer(mux)
}

func TestDetectWordPress(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ver, ev := sc.detectWP()
	if ver != "6.4.2" {
		t.Errorf("core version = %q, want 6.4.2", ver)
	}
	if len(ev) == 0 {
		t.Error("expected evidence for a WordPress site")
	}
}

func TestScanFindsVulnerableElementor(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection")
	}
	if res.WordPressVersion != "6.4.2" {
		t.Errorf("core version = %q", res.WordPressVersion)
	}

	var found *Finding
	for i := range res.Findings {
		if res.Findings[i].Slug == "elementor" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected finding for elementor, got %+v", res.Findings)
	}
	if found.InstalledVersion != "3.24.0" {
		t.Errorf("installed version = %q, want 3.24.0", found.InstalledVersion)
	}
	if len(found.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(found.Vulnerabilities))
	}
	if found.Vulnerabilities[0].Title != "Elementor < 3.25.0 - SQL Injection" {
		t.Errorf("unexpected title %q", found.Vulnerabilities[0].Title)
	}

	// Theme with no matching vuln must appear as detected but not a finding.
	ok := false
	for _, dts := range res.Detected {
		if dts.Slug == "twentytwentyfour" {
			ok = true
			if dts.Version != "1.1" {
				t.Errorf("theme version = %q, want 1.1", dts.Version)
			}
		}
	}
	if !ok {
		t.Error("expected twentytwentyfour in detected components")
	}
}

func TestScanNonWordPressTarget(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>just some static page</body></html>"))
	}))
	defer plain.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, plain.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != ErrNotWordPress {
		t.Fatalf("expected ErrNotWordPress, got %v", err)
	}
}

func TestNewScannerBadURL(t *testing.T) {
	if _, err := NewScanner(nil, "not a url", Options{}); err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestFingerprintFunctions(t *testing.T) {
	readme := `=== Foo ===
Stable Tag: 1.2.3
`
	if v, ok := ExtractVersionFromReadme(readme); !ok || v != "1.2.3" {
		t.Errorf("readme stable tag = %q, %v", v, ok)
	}

	css := `/*
Theme Name: Bar
Version: v2.1.0
*/
`
	if v, ok := ExtractVersionFromStyleCSS(css); !ok || v != "v2.1.0" {
		t.Errorf("css version = %q, %v", v, ok)
	}

	if _, ok := ExtractVersionFromReadme("no version here"); ok {
		t.Error("readme with no stable tag should report not found")
	}

	html := `<meta name="generator" content="WordPress 6.4.2" />`
	if v, ok := ExtractWordPressVersion(html); !ok || v != "6.4.2" {
		t.Errorf("generator = %q, %v", v, ok)
	}
}

func TestMatchDatabaseUnknownVersionNeverMatches(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, _ := NewScanner(d, "http://example.test", Options{})
	f := sc.matchDatabase("elementor", "plugin", "unknown")
	if len(f.Vulnerabilities) != 0 {
		t.Errorf("unknown version must not match, got %+v", f.Vulnerabilities)
	}
	f = sc.matchDatabase("elementor", "plugin", "3.25.0")
	if len(f.Vulnerabilities) != 0 {
		t.Errorf("patched version 3.25.0 must not match")
	}
	f = sc.matchDatabase("elementor", "plugin", "2.0.0")
	if len(f.Vulnerabilities) != 1 {
		t.Errorf("vulnerable version 2.0.0 must match")
	}
}