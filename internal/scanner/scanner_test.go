package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
			"cvss": map[string]any{
				"score":  9.1,
				"rating": "critical",
			},
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
			"cvss": map[string]any{
				"score":  7.1,
				"rating": "high",
			},
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

// fakeWordPressMux builds a minimal WordPress-like site handler.
func fakeWordPressMux() *http.ServeMux {
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
	return mux
}

// fakeWordPress serves a minimal WordPress-like site.
func fakeWordPress() *httptest.Server {
	return httptest.NewServer(fakeWordPressMux())
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
	ver, ev, err := sc.detectWP()
	if err != nil {
		t.Fatalf("detectWP: %v", err)
	}
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

// TestScanUnreachableHostFatal verifies a target that cannot be reached at
// all (connection refused) fails the scan with a hard error instead of
// being reported as "not WordPress".
func TestScanUnreachableHostFatal(t *testing.T) {
	// A closed httptest server leaves no listener behind: connecting to
	// it gets an immediate connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err == nil {
		t.Fatal("expected a fatal error for an unreachable host")
	}
	if !strings.Contains(err.Error(), "cannot reach target") {
		t.Errorf("error = %q, want contains %q", err, "cannot reach target")
	}
	if res != nil {
		t.Errorf("expected nil result on fatal fetch failure, got %+v", res)
	}
}

// TestScanDeadProxyFatal verifies a broken proxy (nothing listening on the
// proxy port) is a hard scan failure, not a false "WordPress found".
func TestScanDeadProxyFatal(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, "http://example.test", Options{Proxy: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err == nil {
		t.Fatal("expected a fatal error through a dead proxy")
	}
	if !strings.Contains(err.Error(), "cannot reach target") {
		t.Errorf("error = %q, want contains %q", err, "cannot reach target")
	}
	if res != nil {
		t.Errorf("expected nil result on fatal fetch failure, got %+v", res)
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
		// Count only enumeration-shaped requests (readme.txt/style.css);
		// the always-on interesting finders also hit /wp-content/.
		if strings.HasSuffix(r.URL.Path, "readme.txt") || strings.HasSuffix(r.URL.Path, "style.css") {
			c.content.Add(1)
		}
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

// TestUsersFromAPISkipsPHPNoticePrefix verifies the /wp-json/wp/v2/users
// parser digs the JSON payload out from behind PHP Deprecated/Warning
// notice text that WordPress may prepend to the body.
func TestUsersFromAPISkipsPHPNoticePrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			"Deprecated: Function dynamic_sidebar is deprecated since version 5.0.0! Use widgets instead. in /var/www/html/wp-includes/functions.php on line 521\n" +
				`[{"id":1,"name":"Administrator","slug":"admin"},{"id":2,"name":"Editor","slug":"editor"}]`,
		))
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(errs) != 0 {
		t.Fatalf("usersFromAPI errors = %+v, want none", errs)
	}
	if len(users) != 2 || users[0].Slug != "admin" || users[1].Slug != "editor" {
		t.Errorf("users = %+v, want admin + editor", users)
	}
}

// TestUsersFromAPIUnparseableBody verifies a body with no JSON payload at
// all is reported as unparseable instead of silently yielding no users.
func TestUsersFromAPIUnparseableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>not json</body></html>"))
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(users) != 0 {
		t.Errorf("users = %+v, want none for an unparseable body", users)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "unparseable") {
		t.Errorf("errors = %+v, want one unparseable error", errs)
	}
}

// author200Server answers /?author=N with a 200 page instead of a redirect
// (WP 7.x behaviour), carrying the author slug in a canonical <link> only
// for author=1. The site itself lives under /blog/ (subdir multisite).
func author200Server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("author") == "1" {
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><link rel="canonical" href="https://example.com/blog/author/superadmin/" /></head>
<body><h1>superadmin</h1><a href="/blog/author/superadmin/">Posts by superadmin</a></body></html>`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><a href="/blog/author/superadmin/">superadmin</a></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view"}`))
	})
	return httptest.NewServer(mux)
}

// TestScanAuthorBodyCanonicalEnumeration verifies users are still found
// when /?author=N answers 200 instead of redirecting: the slug is extracted
// from the canonical link / body reference in a subdirectory multisite
// layout (/blog/author/<slug>/).
func TestScanAuthorBodyCanonicalEnumeration(t *testing.T) {
	srv := author200Server()
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
	if len(res.Users) != 1 {
		t.Fatalf("expected 1 user from 200 ?author body, got %+v", res.Users)
	}
	if res.Users[0].Slug != "superadmin" || res.Users[0].ID != 1 {
		t.Errorf("user = %+v, want superadmin/1", res.Users[0])
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
		{"http://example.com/blog/author/superadmin/", "superadmin"},
		{"/blog/author/superadmin/", "superadmin"},
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

// uaRecorder returns a server that records every request's User-Agent.
func uaRecorder() (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var uas []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uas = append(uas, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/themes/twentytwentyfour/style.css" /></body></html>`))
	}))
	recorded := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), uas...)
	}
	return srv, recorded
}

func TestCustomUserAgentOnEveryRequest(t *testing.T) {
	srv, recorded := uaRecorder()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{UserAgent: "onyx-test/1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	uas := recorded()
	if len(uas) == 0 {
		t.Fatal("expected at least one request")
	}
	for _, ua := range uas {
		if ua != "onyx-test/1.0" {
			t.Errorf("User-Agent = %q, want onyx-test/1.0", ua)
		}
	}
}

func TestRandomUserAgentFromFixedSet(t *testing.T) {
	srv, recorded := uaRecorder()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{RandomUA: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	uas := recorded()
	if len(uas) == 0 {
		t.Fatal("expected at least one request")
	}
	inSet := func(ua string) bool {
		for _, u := range browserUAs {
			if u == ua {
				return true
			}
		}
		return false
	}
	for _, ua := range uas {
		if ua == "" {
			t.Error("expected a User-Agent on every request")
		}
		if !inSet(ua) {
			t.Errorf("User-Agent %q not in the random set", ua)
		}
	}
}

func TestDetectionModes(t *testing.T) {
	cases := []struct {
		mode    string
		wantHit int
	}{
		{"passive", 1},    // only the theme referenced in homepage HTML
		{"aggressive", 3}, // only the DB top slugs (plugin-1..3)
		{"mixed", 4},      // both
	}
	for _, c := range cases {
		c := c
		t.Run(c.mode, func(t *testing.T) {
			srv, counter := fakeWPServer(t, `[]`, 200, nil)
			defer srv.Close()
			d, _ := db.Load(multiPluginFeed(t, 3))
			sc, err := NewScanner(d, srv.URL, Options{DetectionMode: c.mode})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sc.Scan(); err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := counter.content.Load(); got != int64(c.wantHit) {
				t.Errorf("%s mode: /wp-content requests = %d, want %d", c.mode, got, c.wantHit)
			}
		})
	}
}

func TestNewScannerRejectsUnknownDetectionMode(t *testing.T) {
	if _, err := NewScanner(nil, "http://example.test", Options{DetectionMode: "loud"}); err == nil {
		t.Fatal("expected error for invalid detection mode")
	}
}

// TestProxyTransport verifies requests are routed through the configured
// HTTP proxy and that non-http(s) schemes are rejected.
func TestProxyTransport(t *testing.T) {
	var mu sync.Mutex
	var hits int
	var sawAbsolute, sawHost string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		if r.URL.IsAbs() {
			sawAbsolute = r.URL.String()
		}
		sawHost = r.Host
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, "http://example.test", Options{Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection through the proxy")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Fatal("no requests reached the proxy")
	}
	if sawAbsolute == "" {
		t.Error("proxy did not receive absolute-URI requests")
	}
	if sawHost != "example.test" {
		t.Errorf("proxy Host = %q, want example.test", sawHost)
	}
}

func TestProxyAcceptsSocks5(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, "http://example.test", Options{Proxy: "socks5://127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("socks5 proxy must be accepted: %v", err)
	}
	tr, ok := sc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", sc.client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("socks5 must not use the http-proxy field (DialContext handles it)")
	}
	if tr.DialContext == nil {
		t.Fatal("socks5 DialContext not set on transport")
	}
}

func TestProxyRejectsUnknownScheme(t *testing.T) {
	_, err := NewScanner(nil, "http://example.test", Options{Proxy: "ftp://127.0.0.1:21"})
	if err == nil {
		t.Fatal("expected error for unsupported proxy scheme")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error = %q, want unsupported proxy scheme", err)
	}
}

func TestProxyRejectsBogusURL(t *testing.T) {
	if _, err := NewScanner(nil, "http://example.test", Options{Proxy: "://"}); err == nil {
		t.Fatal("expected error for invalid proxy URL")
	}
}

// xmlrpcServer serves a WordPress-ish site whose xmlrpc.php answers a
// system.listMethods ping.
func xmlrpcServer(t *testing.T, xmlrpcStatus int) (*httptest.Server, *xmlrpcLog) {
	t.Helper()
	log := &xmlrpcLog{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		log.mu.Lock()
		log.method = r.Method
		log.contentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		log.body = string(b)
		log.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(xmlrpcStatus)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><params><param><value><array><data><value><string>system.listMethods</string></value></data></array></value></param></params></methodResponse>`))
	})
	return httptest.NewServer(mux), log
}

type xmlrpcLog struct {
	mu          sync.Mutex
	method      string
	contentType string
	body        string
}

func TestXMLRPCDetection(t *testing.T) {
	srv, log := xmlrpcServer(t, http.StatusOK)
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
	if !res.XMLRPC {
		t.Fatal("expected XMLRPC=true for a responding xmlrpc.php")
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.method != http.MethodPost {
		t.Errorf("xmlrpc method = %q, want POST", log.method)
	}
	if log.contentType != "text/xml" {
		t.Errorf("xmlrpc Content-Type = %q, want text/xml", log.contentType)
	}
	if !strings.Contains(log.body, "system.listMethods") {
		t.Errorf("xmlrpc body = %q, missing system.listMethods", log.body)
	}
}

func TestXMLRPCSkippedWithNoXMLRPC(t *testing.T) {
	srv, _ := xmlrpcServer(t, http.StatusOK)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{NoXMLRPC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.XMLRPC {
		t.Error("expected XMLRPC=false with --no-xmlrpc")
	}
}

func TestXMLRPCNotEnabledOnUnavailableEndpoint(t *testing.T) {
	srv, _ := xmlrpcServer(t, http.StatusNotFound)
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
	if res.XMLRPC {
		t.Error("expected XMLRPC=false when xmlrpc.php 404s")
	}
}

// backupServer serves a wp-config backup and a too-small decoy.
func backupServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/wp-config.php.bak", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("define('DB_PASSWORD', 'x');\n", 10)))
	})
	mux.HandleFunc("/wp-config.php.old", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tiny"))
	})
	return httptest.NewServer(mux)
}

func TestConfigBackupFinder(t *testing.T) {
	srv := backupServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Checks: "cb"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.ConfigBackups) != 1 || res.ConfigBackups[0] != "/wp-config.php.bak" {
		t.Fatalf("ConfigBackups = %+v, want [/wp-config.php.bak]", res.ConfigBackups)
	}
}

func TestConfigBackupFinderNotRunWithoutChecks(t *testing.T) {
	srv := backupServer()
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
	if len(res.ConfigBackups) != 0 {
		t.Errorf("ConfigBackups = %+v, want empty without --checks", res.ConfigBackups)
	}
}

// dbExportServer serves SQL dumps at root and in a subdirectory, plus a
// non-SQL decoy.
func dbExportServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/dump.sql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DROP TABLE IF EXISTS wp_options;\nCREATE TABLE wp_options (id int);\n"))
	})
	mux.HandleFunc("/db/backup.sql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("INSERT INTO wp_posts (ID, post_title) VALUES (1, 'x');\n"))
	})
	mux.HandleFunc("/backup.sql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>definitely not a dump</body></html>"))
	})
	return httptest.NewServer(mux)
}

func TestDBExportFinder(t *testing.T) {
	srv := dbExportServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Checks: "dbe"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"/dump.sql", "/db/backup.sql"}
	if len(res.DBExports) != len(want) {
		t.Fatalf("DBExports = %+v, want %+v", res.DBExports, want)
	}
	for i := range want {
		if res.DBExports[i] != want[i] {
			t.Errorf("DBExports[%d] = %q, want %q", i, res.DBExports[i], want[i])
		}
	}
}

func TestNewScannerRejectsUnknownCheck(t *testing.T) {
	if _, err := NewScanner(nil, "http://example.test", Options{Checks: "nope"}); err == nil {
		t.Fatal("expected error for unknown check")
	}
}

func TestSplitConnectAndRequestTimeouts(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, "http://example.test", Options{
		ConnectTimeout: 250 * time.Millisecond,
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sc.client.Timeout != 2*time.Second {
		t.Errorf("client.Timeout = %v, want 2s", sc.client.Timeout)
	}
	tr, ok := sc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", sc.client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext not set on transport")
	}
	// Dialing TEST-NET-1 (reserved, unroutable) must fail quickly; the
	// 250ms dialer timeout bounds it even where the network blackholes it.
	start := time.Now()
	conn, err := tr.DialContext(context.Background(), "tcp", "192.0.2.1:9")
	elapsed := time.Since(start)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("expected dial to TEST-NET-1 to fail")
	}
	if elapsed > 5*time.Second {
		t.Errorf("dial took %v, connect timeout not honored", elapsed)
	}
}

func TestTimeoutDefaultsAndAlias(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, "http://example.test", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if sc.client.Timeout != 10*time.Second {
		t.Errorf("default client.Timeout = %v, want 10s", sc.client.Timeout)
	}
	sc2, err := NewScanner(d, "http://example.test", Options{Timeout: 7 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if sc2.client.Timeout != 7*time.Second {
		t.Errorf("client.Timeout with Timeout alias = %v, want 7s", sc2.client.Timeout)
	}
	if _, ok := sc2.client.Transport.(*http.Transport); !ok {
		t.Errorf("transport = %T, want *http.Transport (no UA wrapping)", sc2.client.Transport)
	}
}

// customDirServer only serves components under custom directory names.
func customDirServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/custom-content/themes/twentytwentyfour/style.css" /></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/custom-plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.24.0\n"))
	})
	mux.HandleFunc("/custom-content/themes/twentytwentyfour/style.css", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.1\n*/\nbody{margin:0}\n"))
	})
	return httptest.NewServer(mux)
}

func TestCustomContentAndPluginsDirs(t *testing.T) {
	srv := customDirServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{
		ContentDir: "custom-content",
		PluginsDir: "custom-plugins",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var foundPlugin, foundTheme bool
	for _, det := range res.Detected {
		switch det.Slug {
		case "elementor":
			foundPlugin = true
			if det.Version != "3.24.0" {
				t.Errorf("elementor version = %q, want 3.24.0", det.Version)
			}
		case "twentytwentyfour":
			foundTheme = true
			if det.Version != "1.1" {
				t.Errorf("theme version = %q, want 1.1", det.Version)
			}
		}
	}
	if !foundPlugin {
		t.Errorf("expected elementor via custom plugins dir, got %+v", res.Detected)
	}
	if !foundTheme {
		t.Errorf("expected twentytwentyfour via custom content dir, got %+v", res.Detected)
	}
}

func TestExtractPassiveSlugsIn(t *testing.T) {
	html := `<img src="https://example.com/my-content/themes/twentytwentyfour/style.css" />
<script src="/my-content/plugins/elementor/readme.txt"></script>`
	plugins, themes := ExtractPassiveSlugsIn(html, "my-content")
	if len(plugins) != 1 || plugins[0] != "elementor" {
		t.Errorf("plugins = %+v, want [elementor]", plugins)
	}
	if len(themes) != 1 || themes[0] != "twentytwentyfour" {
		t.Errorf("themes = %+v, want [twentytwentyfour]", themes)
	}
	if p, _ := ExtractPassiveSlugsIn(html, "wp-content"); len(p) != 0 {
		t.Errorf("default dir must not match custom dir slugs, got %+v", p)
	}
}

// interestingServer serves a WordPress-ish site where every always-on
// interesting finder hits.
func interestingServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /wp-admin/\n"))
	})
	mux.HandleFunc("/readme.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<h1>WordPress 6.4.2 — readme</h1>"))
	})
	mux.HandleFunc("/wp-content/debug.log", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PHP Fatal error: out of memory"))
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("XML-RPC server accepts POST requests only."))
	})
	mux.HandleFunc("/wp-content/uploads/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>Index of /wp-content/uploads/</title></head><body><a href="../">Parent Directory</a></body></html>`))
	})
	mux.HandleFunc("/wp-config.php.bak", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("define('DB_PASSWORD', 'secret');"))
	})
	mux.HandleFunc("/wp-includes/version.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("$wp_version = '6.4.2';"))
	})
	return httptest.NewServer(mux)
}

func TestInterestingFinders(t *testing.T) {
	srv := interestingServer()
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
	want := []string{
		"robots.txt with disallow rules",
		"WordPress readme.html exposed",
		"debug.log exposed",
		"xmlrpc.php exposed",
		"uploads directory listing",
		"wp-config.php.bak exposed",
		"wp-includes/version.php exposed",
	}
	if len(res.Interesting) != len(want) {
		t.Fatalf("Interesting = %+v, want %+v", res.Interesting, want)
	}
	for i := range want {
		if res.Interesting[i] != want[i] {
			t.Errorf("Interesting[%d] = %q, want %q", i, res.Interesting[i], want[i])
		}
	}
}

func TestInterestingFindersEmptyWhenNothingExposed(t *testing.T) {
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
	if len(res.Interesting) != 0 {
		t.Errorf("Interesting = %+v, want empty (everything 404s)", res.Interesting)
	}
}

// mediaServer serves a homepage that references the uploads directory.
func mediaServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/uploads/2025/06/photo.jpg" /></body></html>`))
	})
	return httptest.NewServer(mux)
}

func TestMediaEnumerationPresent(t *testing.T) {
	srv := mediaServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, item := range res.Interesting {
		if item == "media uploads present" {
			found = true
		}
	}
	if !found {
		t.Errorf("Interesting = %+v, want media uploads present", res.Interesting)
	}
}

func TestMediaEnumerationOffByDefault(t *testing.T) {
	srv := mediaServer()
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
	for _, item := range res.Interesting {
		if item == "media uploads present" {
			t.Errorf("media uploads must not be flagged without --enumerate m")
		}
	}
}

func TestNewScannerAcceptsMediaEnumeration(t *testing.T) {
	if _, err := NewScanner(nil, "http://example.test", Options{Enumerate: "m"}); err != nil {
		t.Fatalf("--enumerate m should be valid: %v", err)
	}
}

// blockedServer serves a homepage that looks like a WAF block page.
func blockedServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><h1>Access Denied</h1><p>Your request was blocked by Cloudflare.</p></body></html>`))
	}))
}

func TestExcludeContentBasedStopsScan(t *testing.T) {
	srv := blockedServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{ExcludeContentBased: `Access Denied`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != ErrBlocked {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if res != nil {
		t.Error("expected nil result when blocked by --exclude-content-based")
	}
}

func TestExcludeContentBasedNoMatchProceeds(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{ExcludeContentBased: `Access Denied`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Error("expected the scan to proceed when the regex does not match")
	}
}

func TestScopeMismatchStopsScan(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Scope: `^https://target\.example/`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != ErrOutOfScope {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
	if res != nil {
		t.Error("expected nil result when the target is out of scope")
	}
}

func TestScopeMatchProceeds(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Scope: `^http://127\.0\.0\.1:`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Error("expected the scan to proceed when the scope matches")
	}
}

func TestNewScannerRejectsBadRegexes(t *testing.T) {
	if _, err := NewScanner(nil, "http://example.test", Options{Scope: "("}); err == nil {
		t.Fatal("expected error for invalid --scope regex")
	}
	if _, err := NewScanner(nil, "http://example.test", Options{ExcludeContentBased: "["}); err == nil {
		t.Fatal("expected error for invalid --exclude-content-based regex")
	}
}

// TestCacheNegativeResponses verifies deterministic negative responses
// (404s from brute-force probes) are cached: the second scan with the same
// --cache-ttl must not re-request them.
func TestCacheNegativeResponses(t *testing.T) {
	t.Setenv("ONYX_CACHE_DIR", t.TempDir())
	srv, c := fakeWPServer(t, `[]`, 200, nil)
	defer srv.Close()

	d, _ := db.Load(multiPluginFeed(t, 5))
	opts := Options{Enumerate: "pt", CacheTTL: 24 * time.Hour}

	sc1, err := NewScanner(d, srv.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc1.Scan(); err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	first := c.content.Load()
	if first == 0 {
		t.Fatal("expected brute-force probes on the first scan")
	}

	sc2, err := NewScanner(d, srv.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc2.Scan(); err != nil {
		t.Fatalf("second Scan: %v", err)
	}
	if got := c.content.Load(); got != first {
		t.Errorf("brute-force requests after cached scan = %d, want %d (negative responses must be cached)", got, first)
	}

	// 5xx responses must never be cached: serve a 500, scan, then serve
	// 200 and confirm the 500 was not replayed from cache.
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer flaky.Close()
	sc3, err := NewScanner(d, flaky.URL, opts)
	if err != nil {
		t.Fatal(err)
	}
	// A 500 homepage yields no WordPress evidence; the scan reports
	// "not WordPress" but must have left nothing in the cache.
	if _, err := sc3.Scan(); err != nil && err != ErrNotWordPress {
		t.Fatalf("flaky Scan: %v", err)
	}
	if code, _, ok := sc3.cacheGet(flaky.URL + "/"); ok {
		t.Errorf("5xx response was cached: status %d must never be cached", code)
	}
}

// TestScanSummaryCounters verifies the summary statistics built by Scan():
// the requests counter matches the number of fetch() calls issued (every
// GET the server saw), the severity counts match the findings, and the
// derived fields mirror the result.
func TestScanSummaryCounters(t *testing.T) {
	mux := fakeWordPressMux()
	var mu sync.Mutex
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			gets++
			mu.Unlock()
		}
		mux.ServeHTTP(w, r)
	}))
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
	if res.Summary == nil {
		t.Fatal("expected a summary, got nil")
	}
	mu.Lock()
	wantReqs := gets
	mu.Unlock()
	if res.Summary.Requests != wantReqs {
		t.Errorf("summary requests = %d, want %d (one per fetch call)", res.Summary.Requests, wantReqs)
	}
	if res.Summary.Detected != len(res.Detected) {
		t.Errorf("summary detected = %d, want %d", res.Summary.Detected, len(res.Detected))
	}
	if res.Summary.Users != len(res.Users) {
		t.Errorf("summary users = %d, want %d", res.Summary.Users, len(res.Users))
	}
	if res.Summary.RateLimited != res.RateLimitHits {
		t.Errorf("summary rate_limited = %d, want %d", res.Summary.RateLimited, res.RateLimitHits)
	}
	if res.Summary.DurationMS < 0 {
		t.Errorf("summary duration_ms = %d, want >= 0", res.Summary.DurationMS)
	}

	wantF, wantC, wantH, wantM, wantL := 0, 0, 0, 0, 0
	for i := range res.Findings {
		for _, v := range res.Findings[i].Vulnerabilities {
			wantF++
			switch strings.ToLower(v.Rating) {
			case "critical":
				wantC++
			case "high":
				wantH++
			case "medium":
				wantM++
			case "low":
				wantL++
			}
		}
	}
	if res.Summary.Findings != wantF {
		t.Errorf("summary findings = %d, want %d", res.Summary.Findings, wantF)
	}
	if res.Summary.Critical != wantC || res.Summary.High != wantH ||
		res.Summary.Medium != wantM || res.Summary.Low != wantL {
		t.Errorf("summary severities = %d/%d/%d/%d, want %d/%d/%d/%d",
			res.Summary.Critical, res.Summary.High, res.Summary.Medium, res.Summary.Low,
			wantC, wantH, wantM, wantL)
	}
}

// TestScanNoSummarySkipsSummary verifies --no-summary leaves res.Summary
// nil so JSON output omits the summary field.
func TestScanNoSummarySkipsSummary(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{NoSummary: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Summary != nil {
		t.Errorf("summary = %+v, want nil with NoSummary", res.Summary)
	}
}
