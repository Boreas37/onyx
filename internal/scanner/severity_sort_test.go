package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/version"
)

// severityFeed writes a Wordfence-shaped feed with two plugin records:
// zzplugin carrying the given CVSS and aaplugin carrying the other, both
// vulnerable in the 1.0.0 release only. Returns the feed path.
func severityFeed(t *testing.T, zzCVSS, aaCVSS float64, zzRating, aaRating string) string {
	t.Helper()
	range1, _ := version.ParseRanges("1.0.0 - 1.0.0")
	feed := map[string]any{
		"cccccccc-0000-0000-0000-000000000003": map[string]any{
			"id":    "cccccccc-0000-0000-0000-000000000003",
			"title": "ZZPlugin < 1.1 - Critical",
			"cvss": map[string]any{
				"score":  zzCVSS,
				"rating": zzRating,
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "ZZPlugin", "slug": "zzplugin",
					"affected_versions": map[string]any{
						"1.0.0 - 1.0.0": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.0.0", "to_inclusive": true,
						},
					},
				},
			},
		},
		"dddddddd-0000-0000-0000-000000000004": map[string]any{
			"id":    "dddddddd-0000-0000-0000-000000000004",
			"title": "AAPlugin < 1.1 - High",
			"cvss": map[string]any{
				"score":  aaCVSS,
				"rating": aaRating,
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "AAPlugin", "slug": "aaplugin",
					"affected_versions": map[string]any{
						"1.0.0 - 1.0.0": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.0.0", "to_inclusive": true,
						},
					},
				},
			},
		},
	}
	_ = range1
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// severitySite serves a WordPress-like homepage that references both
// plugins with ?ver=1.0.0 cache-busters (no readme probes, no routes):
// both findings come from the passive-ver merge.
func severitySite() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><script src="/wp-content/plugins/zzplugin/js/zz.js?ver=1.0.0"></script>
<script src="/wp-content/plugins/aaplugin/js/aa.js?ver=1.0.0"></script></body></html>`))
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

// TestScanFindingsSeveritySorted verifies the no-intel findings ordering:
// the higher-CVSS finding comes first regardless of slug order, and equal
// scores fall back to slug ascending.
func TestScanFindingsSeveritySorted(t *testing.T) {
	t.Run("high score beats low score regardless of slug", func(t *testing.T) {
		srv := severitySite()
		defer srv.Close()

		d, err := db.Load(severityFeed(t, 9.1, 7.1, "critical", "high"))
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
		if len(res.Findings) != 2 {
			t.Fatalf("Findings = %+v, want 2", res.Findings)
		}
		if res.Findings[0].Slug != "zzplugin" || res.Findings[1].Slug != "aaplugin" {
			t.Errorf("Findings order = [%s, %s], want [zzplugin, aaplugin] (worst CVSS desc)",
				res.Findings[0].Slug, res.Findings[1].Slug)
		}
	})

	t.Run("equal scores fall back to slug ascending", func(t *testing.T) {
		srv := severitySite()
		defer srv.Close()

		d, err := db.Load(severityFeed(t, 7.1, 7.1, "high", "high"))
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
		if len(res.Findings) != 2 {
			t.Fatalf("Findings = %+v, want 2", res.Findings)
		}
		if res.Findings[0].Slug != "aaplugin" || res.Findings[1].Slug != "zzplugin" {
			t.Errorf("Findings order = [%s, %s], want [aaplugin, zzplugin] (slug ascending)",
				res.Findings[0].Slug, res.Findings[1].Slug)
		}
	})
}

// TestWorstCVSS verifies the severity-ordering helper directly: the worst
// score across a finding's vulnerabilities wins, and a finding with no
// vulnerabilities scores 0.
func TestWorstCVSS(t *testing.T) {
	if got := worstCVSS(Finding{Slug: "a", Vulnerabilities: []Vulnerability{
		{CVSSScore: 3.1},
		{CVSSScore: 9.8},
		{CVSSScore: 5.4},
	}}); got != 9.8 {
		t.Errorf("worstCVSS = %v, want 9.8", got)
	}
	if got := worstCVSS(Finding{Slug: "b"}); got != 0 {
		t.Errorf("worstCVSS (no vulns) = %v, want 0", got)
	}
}
