package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/db"
)

func regressionFeed(t *testing.T, records map[string]any) *db.DB {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := db.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func affectedSoftware(typ, name, slug, to string) map[string]any {
	return map[string]any{
		"type": typ, "name": name, "slug": slug,
		"affected_versions": map[string]any{
			"<= " + to: map[string]any{
				"from_version": "*", "to_version": to, "to_inclusive": true,
			},
		},
	}
}

func regressionRecord(id string, software ...map[string]any) map[string]any {
	items := make([]any, len(software))
	for i := range software {
		items[i] = software[i]
	}
	return map[string]any{
		"id": id, "title": id, "software": items,
		"cvss": map[string]any{"score": 9.1, "rating": "critical"},
	}
}

func wordpressMux(homepage string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(homepage))
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func TestScanMatchesDetectedCoreVersion(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"core-vuln": regressionRecord("core-vuln", affectedSoftware("core", "WordPress", "wordpress-core", "6.4.2")),
	})
	mux := wordpressMux(`<meta name="generator" content="WordPress 6.4.1">`)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(database, srv.URL, Options{Enumerate: "m", NoXMLRPC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Type != "core" || res.Findings[0].Slug != "wordpress-core" {
		t.Fatalf("core findings = %+v, want wordpress-core vulnerability", res.Findings)
	}
}

func TestScanMatchesUnauthenticatedRESTInventory(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"plugin-vuln": regressionRecord("plugin-vuln", affectedSoftware("plugin", "Elementor", "elementor", "3.24.0")),
	})
	mux := wordpressMux(`<meta name="generator" content="WordPress 6.4.2">`)
	mux.HandleFunc("/wp-json/wp/v2/plugins", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"plugin":"elementor/elementor.php","version":"3.24.0","name":"Elementor"}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(database, srv.URL, Options{APIOnly: true, Enumerate: "p", NoXMLRPC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Slug != "elementor" || res.Findings[0].InstalledVersion != "3.24.0" {
		t.Fatalf("REST findings = %+v, want vulnerable Elementor 3.24.0", res.Findings)
	}
}

func TestMatchDatabaseRequiresComponentType(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"theme-vuln":  regressionRecord("theme-vuln", affectedSoftware("theme", "Shared Theme", "shared", "2.0.0")),
		"plugin-vuln": regressionRecord("plugin-vuln", affectedSoftware("plugin", "Shared Plugin", "shared", "0.5.0")),
	})
	sc, err := NewScanner(database, "https://example.test", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := sc.matchDatabase("shared", "plugin", "1.0.0"); len(got.Vulnerabilities) != 0 {
		t.Fatalf("plugin matched theme vulnerability: %+v", got)
	}
	jobs := sc.buildJobs()
	seen := map[string]bool{}
	for _, job := range jobs {
		if job.slug == "shared" {
			seen[job.kind] = true
		}
	}
	if !seen["plugin"] || !seen["theme"] {
		t.Fatalf("jobs for shared slug = %+v, want both plugin and theme", jobs)
	}
}

func TestForeignPassiveAssetIsIgnored(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"plugin-vuln": regressionRecord("plugin-vuln", affectedSoftware("plugin", "Elementor", "elementor", "3.24.0")),
	})
	mux := wordpressMux(`<meta name="generator" content="WordPress 6.4.2">
<script src="https://cdn.example.test/wp-content/plugins/elementor/app.js?ver=3.24.0"></script>`)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(database, srv.URL, Options{Enumerate: "m", NoXMLRPC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detected) != 0 || len(res.Findings) != 0 {
		t.Fatalf("foreign asset produced target detections: detected=%+v findings=%+v", res.Detected, res.Findings)
	}
}

func TestAPIOnlyDoesNotLeakPassiveDetections(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"plugin-vuln": regressionRecord("plugin-vuln", affectedSoftware("plugin", "Elementor", "elementor", "3.24.0")),
	})
	mux := wordpressMux(`<meta name="generator" content="WordPress 6.4.2">
<script src="/wp-content/plugins/elementor/app.js?ver=3.24.0"></script>`)
	mux.HandleFunc("/wp-json/wp/v2/plugins", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(database, srv.URL, Options{APIOnly: true, Enumerate: "p", NoXMLRPC: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detected) != 0 || len(res.Findings) != 0 {
		t.Fatalf("API-only leaked passive results: detected=%+v findings=%+v", res.Detected, res.Findings)
	}
}

func TestBlockedProbeDoesNotCreateComponent(t *testing.T) {
	database := regressionFeed(t, map[string]any{
		"plugin-vuln": regressionRecord("plugin-vuln", affectedSoftware("plugin", "Ghost", "ghost", "1.0.0")),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	sc, err := NewScanner(database, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, findings := sc.scanJob(job{kind: "plugin", slug: "ghost", path: "/wp-content/plugins/ghost/readme.txt"})
	if len(detected) != 0 || len(findings) != 0 {
		t.Fatalf("generic 403 created phantom component: detected=%+v findings=%+v", detected, findings)
	}
}

func TestRetryAfterWaitHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sc, err := NewScanner(regressionFeed(t, map[string]any{}), srv.URL, Options{Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err = sc.fetch("/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fetch error = %v, want context deadline", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled Retry-After wait took %s", elapsed)
	}
}

func TestNewScannerRejectsTargetQueryAndFragment(t *testing.T) {
	for _, target := range []string{"https://example.test/blog?preview=1", "https://example.test/blog#main"} {
		if _, err := NewScanner(nil, target, Options{}); err == nil {
			t.Errorf("NewScanner(%q) accepted ambiguous target URL", target)
		}
	}
}

func TestSitemapSitePathForSubdirectoryInstall(t *testing.T) {
	got, ok := sitemapSitePath("https://example.test/blog/post-1/", "https://example.test/blog")
	if !ok || got != "/post-1/" {
		t.Fatalf("sitemapSitePath = (%q, %v), want (/post-1/, true)", got, ok)
	}
}
