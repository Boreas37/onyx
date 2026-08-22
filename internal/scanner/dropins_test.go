package scanner

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestDropinCacheHeaderDetection walks every known page-cache response
// header and verifies each produces its static Interesting entry via
// dropinFinder.
func TestDropinCacheHeaderDetection(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"x-cache", "X-Cache", "HIT", "Page cache detected: cache layer (X-Cache header)"},
		{"x-varnish", "X-Varnish", "146", "Page cache detected: Varnish"},
		{"wp-super-cache", "X-WP-Super-Cache", "1", "Page cache detected: WP Super Cache"},
		{"w3-total-cache", "W3TC", "1", "Page cache detected: W3 Total Cache"},
		{"litespeed-cache", "X-LiteSpeed-Cache", "miss", "Page cache detected: LiteSpeed Cache"},
		{"x-proxy-cache", "X-Proxy-Cache", "HIT", "Page cache detected: cache layer (X-Proxy-Cache header)"},
		{"cloudflare", "CF-Cache-Status", "DYNAMIC", "Page cache detected: Cloudflare"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(c.header, c.value)
				_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			d, err := db.Load(minimalFeed(t))
			if err != nil {
				t.Fatal(err)
			}
			sc, err := NewScanner(d, srv.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := sc.dropinFinder()
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("dropinFinder() = %v, want [%q]", got, c.want)
			}
		})
	}
}

// TestDropinCacheHeadersDedupedAndCapped verifies multiple simultaneous
// cache headers yield distinct entries bounded by maxDropinFindings.
func TestDropinCacheHeadersDedupedAndCapped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, h := range cacheHeaderHints {
			w.Header().Set(h.header, "HIT")
		}
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := sc.dropinFinder()
	if len(got) != maxDropinFindings {
		t.Fatalf("dropinFinder() returned %d entries, want cap %d", len(got), maxDropinFindings)
	}
	seen := make(map[string]bool, len(got))
	for _, entry := range got {
		if seen[entry] {
			t.Errorf("duplicate entry %q", entry)
		}
		seen[entry] = true
		known := false
		for _, h := range cacheHeaderHints {
			if h.finding == entry {
				known = true
				break
			}
		}
		if !known {
			t.Errorf("unexpected entry %q (target-controlled data leaked?)", entry)
		}
	}
}

// muPluginsServer serves the mu-plugins probe paths used by the drop-in
// tests. standardHits counts requests to the default wp-content location so
// tests can prove the configured content dir is honoured.
func muPluginsServer(body string, status int) (*httptest.Server, *atomic.Int64) {
	var standard atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/mu-plugins/", func(w http.ResponseWriter, r *http.Request) {
		standard.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/custom-content/mu-plugins/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>Index of /custom-content/mu-plugins/</title></head>
<body><a href="../">Parent Directory</a><a href="mu-plugin.php">mu-plugin.php</a></body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
	})
	return httptest.NewServer(mux), &standard
}

// TestDropinMuPluginsListing verifies an exposed mu-plugins directory
// listing is flagged, while a 200 page without listing markers is not.
func TestDropinMuPluginsListing(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		want   bool
	}{
		{
			name:   "apache style listing",
			body:   `<html><head><title>Index of /wp-content/mu-plugins/</title></head><body><a href="../">Parent Directory</a></body></html>`,
			status: http.StatusOK,
			want:   true,
		},
		{
			name:   "plain 200 without listing markers",
			body:   `<?php // mu-plugin placeholder ?>nothing to see here`,
			status: http.StatusOK,
			want:   false,
		},
		{
			name:   "404",
			body:   "not found",
			status: http.StatusNotFound,
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := muPluginsServer(c.body, c.status)
			defer srv.Close()

			d, err := db.Load(minimalFeed(t))
			if err != nil {
				t.Fatal(err)
			}
			sc, err := NewScanner(d, srv.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := sc.dropinFinder()
			found := false
			for _, entry := range got {
				if entry == "mu-plugins directory exposed" {
					found = true
				}
			}
			if found != c.want {
				t.Errorf("mu-plugins exposed = %v (entries %v), want %v", found, got, c.want)
			}
		})
	}
}

// TestDropinMuPluginsUsesConfiguredContentDir proves the mu-plugins probe
// follows --content-dir instead of hardcoding wp-content.
func TestDropinMuPluginsUsesConfiguredContentDir(t *testing.T) {
	srv, standardHits := muPluginsServer("", http.StatusOK)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{ContentDir: "custom-content"})
	if err != nil {
		t.Fatal(err)
	}
	got := sc.dropinFinder()
	found := false
	for _, entry := range got {
		if entry == "mu-plugins directory exposed" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mu-plugins finding under custom content dir, got %v", got)
	}
	if n := standardHits.Load(); n != 0 {
		t.Errorf("default wp-content/mu-plugins probed %d times, want 0", n)
	}
}

// TestScanInterestingIncludesDropins runs the whole Scan to prove the
// drop-in findings are wired into Result.Interesting alongside the
// classic interesting finders.
func TestScanInterestingIncludesDropins(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Cache-Status", "HIT")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
	})
	mux.HandleFunc("/wp-content/mu-plugins/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><h1>Index of /wp-content/mu-plugins/</h1></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var haveCloudflare, haveMuPlugins bool
	for _, entry := range res.Interesting {
		switch entry {
		case "Page cache detected: Cloudflare":
			haveCloudflare = true
		case "mu-plugins directory exposed":
			haveMuPlugins = true
		}
	}
	if !haveCloudflare || !haveMuPlugins {
		t.Errorf("Interesting = %+v, want Cloudflare cache + mu-plugins entries", res.Interesting)
	}
	if len(res.Interesting) > 2+maxDropinFindings {
		t.Errorf("Interesting grew unbounded: %+v", res.Interesting)
	}
}
