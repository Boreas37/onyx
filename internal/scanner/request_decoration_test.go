package scanner

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// capturedHeaders records the request headers of the homepage fetch so
// tests can assert what the transport actually sent on the wire.
type capturedHeaders struct {
	mu            sync.Mutex
	authorization string
	cookie        string
	custom        string
	host          string
	userAgent     string
}

// headerCaptureServer serves a minimal WordPress homepage and captures the
// headers of the "/" request into c.
func headerCaptureServer() (*httptest.Server, *capturedHeaders) {
	c := &capturedHeaders{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.authorization = r.Header.Get("Authorization")
		c.cookie = r.Header.Get("Cookie")
		c.custom = r.Header.Get("X-Custom")
		c.host = r.Host
		c.userAgent = r.Header.Get("User-Agent")
		c.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	return httptest.NewServer(mux), c
}

// TestRequestDecorationAppliesEveryDecoration verifies the headerTransport
// stamps Basic auth, a static Cookie, custom headers and a Host override
// onto the outbound request, and that it composes with the UA transport so
// the User-Agent lands alongside them.
func TestRequestDecorationAppliesEveryDecoration(t *testing.T) {
	srv, c := headerCaptureServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{
		BasicAuthUser: "alice",
		BasicAuthPass: "secret",
		Cookie:        "foo=bar; baz=qux",
		Headers:       map[string]string{"X-Custom": "yes", "X-Second": "two"},
		VHost:         "example.com",
		UserAgent:     "onyx-test/1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sc.fetch("/"); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if c.authorization != wantAuth {
		t.Errorf("Authorization = %q, want %q", c.authorization, wantAuth)
	}
	if c.cookie != "foo=bar; baz=qux" {
		t.Errorf("Cookie = %q, want foo=bar; baz=qux", c.cookie)
	}
	if c.custom != "yes" {
		t.Errorf("X-Custom = %q, want yes", c.custom)
	}
	if c.host != "example.com" {
		t.Errorf("Host = %q, want example.com (vhost override)", c.host)
	}
	if c.userAgent != "onyx-test/1.0" {
		t.Errorf("User-Agent = %q, want onyx-test/1.0 (UA + decorations must both land)", c.userAgent)
	}
}

// TestRequestDecorationEmptyValuesUntouched verifies that zero-value
// decoration options leave the request untouched: no Authorization, no
// Cookie, no custom header, and the Host stays the target's own authority.
func TestRequestDecorationEmptyValuesUntouched(t *testing.T) {
	srv, c := headerCaptureServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sc.fetch("/"); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authorization != "" {
		t.Errorf("Authorization = %q, want empty", c.authorization)
	}
	if c.cookie != "" {
		t.Errorf("Cookie = %q, want empty", c.cookie)
	}
	if c.custom != "" {
		t.Errorf("X-Custom = %q, want empty", c.custom)
	}
	wantHost := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
	if c.host != wantHost {
		t.Errorf("Host = %q, want the target authority %q (no vhost override)", c.host, wantHost)
	}
}

// forceScanServer serves a homepage with ZERO WordPress fingerprints (no
// generator meta, no wp-content, no wp-json) but a real elementor readme at
// the path aggressive enumeration probes, so a --force scan can still find
// vulnerabilities.
func forceScanServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Plain static site</h1></body></html>`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Elementor ===
Contributors: elementorteam
Tags: page builder
Stable tag: 2.0.0
License: GPLv3
`))
	})
	return httptest.NewServer(mux)
}

// TestScanForceSkipsWordPressGate verifies --force: a target with no
// WordPress fingerprints normally fails with ErrNotWordPress, while
// Force=true scans anyway — IsWordPress stays false but enumeration runs
// and the vulnerable elementor is found.
func TestScanForceSkipsWordPressGate(t *testing.T) {
	srv := forceScanServer()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}

	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != ErrNotWordPress {
		t.Fatalf("expected ErrNotWordPress without --force, got %v", err)
	}

	sc2, err := NewScanner(d, srv.URL, Options{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc2.Scan()
	if err != nil {
		t.Fatalf("Scan with --force: %v", err)
	}
	if res.IsWordPress {
		t.Error("IsWordPress must stay false under --force (no fingerprints seen)")
	}
	if res.WordPressVersion != "" {
		t.Errorf("WordPressVersion = %q, want empty under --force", res.WordPressVersion)
	}
	found := false
	for _, f := range res.Findings {
		if f.Slug == "elementor" {
			found = true
			if f.InstalledVersion != "2.0.0" || len(f.Vulnerabilities) != 1 {
				t.Errorf("elementor finding = %+v, want version 2.0.0 with 1 vulnerability", f)
			}
		}
	}
	if !found {
		t.Fatalf("expected elementor finding under --force, got %+v", res.Findings)
	}
}
