package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/version"
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

// reqCounter tallies requests across the fake server, split by category.
type reqCounter struct {
	content  atomic.Int64 // /wp-content/* enumeration hits
	users    atomic.Int64 // /wp-json/wp/v2/users hits
	author   atomic.Int64 // /?author=N hits
	authorMu sync.Mutex
	authorID map[int]int // hits per author id
}

func (c *reqCounter) authorHit(id int) {
	c.author.Add(1)
	c.authorMu.Lock()
	c.authorID[id]++
	c.authorMu.Unlock()
}

func (c *reqCounter) authorHits(id int) int {
	c.authorMu.Lock()
	defer c.authorMu.Unlock()
	return c.authorID[id]
}

// fakeWPServer serves a WordPress-ish site wired for user enumeration.
// wp-json/users responds with usersJSON and usersStatus. author maps
// /?author=N -> the redirect Location (a 404 when absent). The elementor
// plugin readme.txt is served so plugin enumeration can be positively
// verified.
func fakeWPServer(t *testing.T, usersJSON string, usersStatus int, author map[int]string) (*httptest.Server, *reqCounter) {
	t.Helper()
	c := &reqCounter{authorID: map[int]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if a := r.URL.Query().Get("author"); a != "" {
			n, _ := strconv.Atoi(a)
			c.authorHit(n)
			if loc, ok := author[n]; ok && loc != "" {
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/themes/twentytwentyfour/style.css" />
<link rel="https://api.w.org/" href="/wp-json/" /></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake","url":"http://example"}`))
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		c.users.Add(1)
		w.WriteHeader(usersStatus)
		_, _ = w.Write([]byte(usersJSON))
	})
	mux.HandleFunc("/wp-json/wp/v2/plugins", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view","message":"nope"}`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		c.content.Add(1)
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.24.0\n"))
	})
	mux.HandleFunc("/wp-content/themes/twentytwentyfour/style.css", func(w http.ResponseWriter, r *http.Request) {
		c.content.Add(1)
		_, _ = w.Write([]byte("/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.1\n*/\nbody{margin:0}\n"))
	})
	mux.HandleFunc("/wp-content/", func(w http.ResponseWriter, r *http.Request) {
		c.content.Add(1)
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux), c
}

func TestScanUserEnumeration(t *testing.T) {
	usersJSON := `[{"id":1,"name":"Administrator","slug":"admin"},{"id":2,"name":"Simple Admin","slug":"simpleadmin"}]`
	author := map[int]string{
		1: "/author/admin/",
		2: "/author/simpleadmin/",
	}
	srv, c := fakeWPServer(t, usersJSON, 200, author)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Users) != 2 {
		t.Fatalf("expected 2 users, got %+v", res.Users)
	}
	if res.Users[0].Slug != "admin" || res.Users[0].ID != 1 || res.Users[0].Name != "Administrator" {
		t.Errorf("user[0] = %+v, want admin/1/Administrator", res.Users[0])
	}
	if res.Users[1].Slug != "simpleadmin" || res.Users[1].ID != 2 || res.Users[1].Name != "Simple Admin" {
		t.Errorf("user[1] = %+v, want simpleadmin/2/Simple Admin", res.Users[1])
	}

	// User-only enumeration must not touch plugin/theme or api-plugin paths.
	if c.content.Load() != 0 {
		t.Errorf("user-only enumeration made %d /wp-content requests", c.content.Load())
	}
	if c.users.Load() != 1 {
		t.Errorf("users endpoint hit %d times, want 1", c.users.Load())
	}
	if len(res.Detected) != 0 {
		t.Errorf("user-only enumeration should not detect plugins, got %+v", res.Detected)
	}
}

func TestScanAuthorRedirectEnumeration(t *testing.T) {
	// wp-json/users is locked down, so users must come from ?author=N.
	srv, _ := fakeWPServer(t, `{"code":"rest_user_cannot_view"}`, 403, map[int]string{
		1: "/author/admin/",
		2: "http://example.test/author/simpleadmin/",
	})
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Users) != 2 {
		t.Fatalf("expected 2 users from author redirects, got %+v", res.Users)
	}
	if res.Users[0].Slug != "admin" || res.Users[0].ID != 1 {
		t.Errorf("user[0] = %+v, want admin/1", res.Users[0])
	}
	if res.Users[1].Slug != "simpleadmin" || res.Users[1].ID != 2 {
		t.Errorf("user[1] = %+v, want simpleadmin/2", res.Users[1])
	}
}

func TestScanAuthorChecksStopAtTen(t *testing.T) {
	srv, c := fakeWPServer(t, `[]`, 200, nil)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if c.users.Load() != 1 {
		t.Errorf("users endpoint should be hit once, got %d", c.users.Load())
	}
	if c.author.Load() != maxAuthorChecks {
		t.Errorf("author checks = %d, want %d", c.author.Load(), maxAuthorChecks)
	}
	if c.authorHits(10) != 1 {
		t.Errorf("expected author=10 to be tried, got %d", c.authorHits(10))
	}
	if c.authorHits(11) != 0 {
		t.Errorf("author=11 must not be tried")
	}
}

func TestMaxRequestsCapsBruteForce(t *testing.T) {
	srv, c := fakeWPServer(t, `[]`, 200, nil)
	defer srv.Close()
	feed := multiPluginFeed(t, 4)

	d, err := db.Load(feed)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "pt", MaxRequests: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if c.content.Load() != 2 {
		t.Errorf("brute-force requests = %d, want 2 (--max-requests 2 of 4 jobs)", c.content.Load())
	}
	if c.users.Load() != 0 {
		t.Errorf("users should not be enumerated when the budget is exhausted, got %d", c.users.Load())
	}
}

func TestMaxRequestsSharesBudgetWithUsers(t *testing.T) {
	srv, c := fakeWPServer(t, `[{"id":1,"name":"Admin","slug":"admin"}]`, 200, map[int]string{1: "/author/admin/"})
	defer srv.Close()
	feed := multiPluginFeed(t, 2)

	d, _ := db.Load(feed)
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "up", MaxRequests: 3})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// 2 plugin jobs consume the budget, leaving 1 request for the users
	// endpoint and none for author redirects.
	if c.content.Load() != 2 {
		t.Errorf("plugin requests = %d, want 2", c.content.Load())
	}
	if c.users.Load() != 1 {
		t.Errorf("users endpoint = %d, want 1", c.users.Load())
	}
	if c.author.Load() != 0 {
		t.Errorf("author requests = %d, want 0 (no budget left)", c.author.Load())
	}
	if len(res.Users) != 1 {
		t.Errorf("expected admin user from REST API, got %+v", res.Users)
	}
}

func TestEnumeratePluginOnlySkipsThemesAndUsers(t *testing.T) {
	srv, c := fakeWPServer(t, `[{"id":1,"name":"Admin","slug":"admin"}]`, 200, nil)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "p"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var hasPlugin, hasTheme bool
	for _, det := range res.Detected {
		switch det.Slug {
		case "elementor":
			hasPlugin = true
		case "twentytwentyfour":
			hasTheme = true
		}
	}
	if !hasPlugin {
		t.Errorf("expected elementor plugin to be detected, got %+v", res.Detected)
	}
	if hasTheme {
		t.Errorf("theme must not be enumerated with --enumerate p, got %+v", res.Detected)
	}
	if c.users.Load() != 0 {
		t.Errorf("users must not be enumerated with --enumerate p, got %d hits", c.users.Load())
	}
}

func TestDefaultEnumerateIncludesThemes(t *testing.T) {
	srv, _ := fakeWPServer(t, `[]`, 200, nil)
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
	ok := false
	for _, det := range res.Detected {
		if det.Slug == "twentytwentyfour" {
			ok = true
			if det.Version != "1.1" {
				t.Errorf("theme version = %q, want 1.1", det.Version)
			}
		}
	}
	if !ok {
		t.Errorf("default enumerate should probe themes, got %+v", res.Detected)
	}
}

func TestAuthorSlugFromLocation(t *testing.T) {
	cases := []struct {
		loc, want string
	}{
		{"http://example.com/author/admin/", "admin"},
		{"/author/simpleadmin/", "simpleadmin"},
		{"author/no-slash/", "no-slash"},
		{"http://example.com/", ""},
		{"", ""},
		{"/?author=1", ""},
		{"/author/", ""},
	}
	for _, c := range cases {
		if got := authorSlugFromLocation(c.loc); got != c.want {
			t.Errorf("authorSlugFromLocation(%q) = %q, want %q", c.loc, got, c.want)
		}
	}
}

// multiPluginFeed writes a feed containing n plugin slugs.
func multiPluginFeed(t *testing.T, n int) string {
	t.Helper()
	feed := map[string]any{}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("aaaaaaaa-0000-0000-0000-%012d", i)
		feed[id] = map[string]any{
			"id":    id,
			"title": fmt.Sprintf("Plugin %d < 2.0.0", i),
			"software": []any{map[string]any{
				"type": "plugin", "name": fmt.Sprintf("Plugin %d", i), "slug": fmt.Sprintf("plugin-%d", i),
				"affected_versions": map[string]any{
					"1.0.0 - 1.9.9": map[string]any{
						"from_version": "1.0.0", "from_inclusive": true,
						"to_version": "1.9.9", "to_inclusive": true,
					},
				},
			}},
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
