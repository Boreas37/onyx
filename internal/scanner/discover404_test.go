package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// pluginXFeed writes a feed with a single vulnerable plugin "plugin-x"
// (display name "Plugin X", vulnerable 1.0.0 - 1.9.9), used to prove the
// ?ver= version extracted from the 404 page matches against the database.
func pluginXFeed(t *testing.T) string {
	t.Helper()
	feed := map[string]any{
		"eeeeeeee-0000-0000-0000-00000000000e": map[string]any{
			"id":    "eeeeeeee-0000-0000-0000-00000000000e",
			"title": "Plugin X < 2.0.0 - Reflected XSS",
			"cvss": map[string]any{
				"score":  6.1,
				"rating": "medium",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Plugin X", "slug": "plugin-x",
					"affected_versions": map[string]any{
						"1.0.0 - 1.9.9": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.9.9", "to_inclusive": true,
						},
					},
				},
			},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin-x-feed.json")
	data, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// fourohfourServer serves a WordPress homepage WITHOUT any plugin/theme
// references, and a 200 body with plugin-x / theme-y references (plus a
// ?ver= asset URL for plugin-x) on every path that looks like the
// 404-check probe. Plugin-x's readme and composer.json 404 on purpose so
// the ?ver= version is the only way plugin-x can be detected; theme-y's
// style.css answers a version. notFoundRefs=false makes the probe body
// reference nothing. The probe-hit counter lets tests assert request
// counts.
func fourohfourServer(t *testing.T, notFoundRefs bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var probes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-404-check-") {
			probes.Add(1)
			w.Header().Set("Content-Type", "text/html")
			if notFoundRefs {
				_, _ = w.Write([]byte(`<html><head><title>404</title></head><body>Not found.</body></html>`))
				return
			}
			_, _ = w.Write([]byte(`<html><body>
<script src="/wp-content/plugins/plugin-x/assets/app.js?ver=1.2.3"></script>
<link rel="stylesheet" href="/wp-content/themes/theme-y/style.css" />
</body></html>`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body>wp-content is served from here</body></html>`))
	})
	mux.HandleFunc("/wp-content/themes/theme-y/style.css", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`/*
Theme Name: Theme Y
Version: 3.1
*/
body { margin: 0; }
`))
	})
	return httptest.NewServer(mux), &probes
}

// TestDiscover404AddsJobsAndDetections drives the full scan with
// --discover-404 on: the probe page's plugin-x and theme-y references must
// join enumeration, and the ?ver= version on the probe page must flow into
// passive detection and match against the database (the readme 404s so the
// passive-ver path is the only way plugin-x can be identified).
func TestDiscover404AddsJobsAndDetections(t *testing.T) {
	srv, probes := fourohfourServer(t, false)
	defer srv.Close()

	d, err := db.Load(pluginXFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Discover404: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("404-check probes = %d, want exactly 1", got)
	}

	var pluginX, themeY *Detected
	for i := range res.Detected {
		switch res.Detected[i].Slug {
		case "plugin-x":
			pluginX = &res.Detected[i]
		case "theme-y":
			themeY = &res.Detected[i]
		}
	}
	if pluginX == nil {
		t.Fatalf("plugin-x not detected; the 404-page slug/version flow is broken (%+v)", res.Detected)
	}
	if pluginX.Version != "1.2.3" || pluginX.Source != "passive-ver" {
		t.Errorf("plugin-x = %+v, want version 1.2.3 via passive-ver (readme 404s)", pluginX)
	}
	if themeY == nil {
		t.Fatalf("theme-y not detected; its style.css job must have been queued from the 404 page")
	}
	if themeY.Version != "3.1" || themeY.Source != "style.css" {
		t.Errorf("theme-y = %+v, want version 3.1 via style.css", themeY)
	}

	// The ?ver= version on the 404 page must match against the database.
	var found *Finding
	for i := range res.Findings {
		if res.Findings[i].Slug == "plugin-x" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no finding for plugin-x; the 404-page ?ver= version did not match")
	}
	if found.InstalledVersion != "1.2.3" {
		t.Errorf("finding installed version = %q, want 1.2.3", found.InstalledVersion)
	}
}

// TestDiscover404NoRefsAddsNoJobs verifies a 200 probe page without any
// wp-content references adds no enumeration jobs: nothing from the 404
// page leaks into the detection results.
func TestDiscover404NoRefsAddsNoJobs(t *testing.T) {
	srv, probes := fourohfourServer(t, true)
	defer srv.Close()

	d, err := db.Load(pluginXFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Discover404: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("404-check probes = %d, want exactly 1", got)
	}
	for _, det := range res.Detected {
		if det.Slug == "plugin-x" || det.Slug == "theme-y" {
			t.Errorf("probe-free 404 page leaked detection %+v", det)
		}
	}
	if len(res.Findings) != 0 {
		t.Errorf("probe-free 404 page produced findings: %+v", res.Findings)
	}
}

// TestDiscover404DisabledSkipsProbe verifies the zero value of
// Discover404 (off) performs no extra request: the probe counter stays at
// zero, preserving the historical request budget.
func TestDiscover404DisabledSkipsProbe(t *testing.T) {
	srv, probes := fourohfourServer(t, false)
	defer srv.Close()

	d, err := db.Load(pluginXFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{}) // Discover404 zero value
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := probes.Load(); got != 0 {
		t.Errorf("404-check probes = %d, want 0 with Discover404 off", got)
	}
	if !res.IsWordPress {
		t.Fatal("scan must still detect WordPress without the probe")
	}
}
