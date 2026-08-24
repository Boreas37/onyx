package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// dupFeed writes a feed with TWO vulnerable records for the same slug
// ("dup-plugin"), both affecting 1.0.0 - 1.9.9, and returns the feed path
// plus both record IDs.
func dupFeed(t *testing.T) (string, string, string) {
	t.Helper()
	id1 := "eeeeeeee-0000-0000-0000-0000000000e1"
	id2 := "eeeeeeee-0000-0000-0000-0000000000e2"
	feed := map[string]any{
		id1: map[string]any{
			"id":    id1,
			"title": "Dup Plugin < 2.0.0 - SQLi",
			"cvss": map[string]any{
				"score": 9.1, "rating": "critical",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Dup Plugin", "slug": "dup-plugin",
					"affected_versions": map[string]any{
						"1.0.0 - 1.9.9": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.9.9", "to_inclusive": true,
						},
					},
				},
			},
		},
		id2: map[string]any{
			"id":    id2,
			"title": "Dup Plugin < 2.0.0 - XSS",
			"cvss": map[string]any{
				"score": 6.1, "rating": "medium",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Dup Plugin", "slug": "dup-plugin",
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
	path := filepath.Join(dir, "dup-feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, id1, id2
}

// TestMatchDatabaseExcludeVulns verifies --exclude-vulns: a record whose ID
// is listed is skipped before range matching, leaving only the other record
// for the same slug in the findings; without the option both match, and the
// match is case-sensitive.
func TestMatchDatabaseExcludeVulns(t *testing.T) {
	path, id1, id2 := dupFeed(t)
	d, err := db.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// No exclusion: both records match.
	sc, _ := NewScanner(d, "http://example.test", Options{})
	f := sc.matchDatabase("dup-plugin", "plugin", "1.5.0")
	if len(f.Vulnerabilities) != 2 {
		t.Fatalf("no exclusion: got %d vulnerabilities, want 2 (%+v)", len(f.Vulnerabilities), f.Vulnerabilities)
	}

	// Excluding id1 leaves only id2.
	sc2, _ := NewScanner(d, "http://example.test", Options{ExcludeVulns: []string{id1}})
	f2 := sc2.matchDatabase("dup-plugin", "plugin", "1.5.0")
	if len(f2.Vulnerabilities) != 1 {
		t.Fatalf("excluding %s: got %d vulnerabilities, want 1", id1, len(f2.Vulnerabilities))
	}
	if f2.Vulnerabilities[0].ID != id2 {
		t.Errorf("remaining vuln ID = %q, want %q (excluded %s)", f2.Vulnerabilities[0].ID, id2, id1)
	}

	// Case-sensitive: an uppercase spelling does not exclude the lowercase ID.
	sc3, _ := NewScanner(d, "http://example.test", Options{ExcludeVulns: []string{strings.ToUpper(id1)}})
	if f3 := sc3.matchDatabase("dup-plugin", "plugin", "1.5.0"); len(f3.Vulnerabilities) != 2 {
		t.Errorf("case-mismatched exclusion dropped a record (%d vulns, want 2)", len(f3.Vulnerabilities))
	}
}

// vectorFeed writes a feed with two records for "vec-plugin", one carrying a
// CVSS vector string and one without it.
func vectorFeed(t *testing.T) string {
	t.Helper()
	idWith := "ffffffff-0000-0000-0000-0000000000f1"
	idWithout := "ffffffff-0000-0000-0000-0000000000f2"
	feed := map[string]any{
		idWith: map[string]any{
			"id":    idWith,
			"title": "Vec Plugin < 2.0.0 - RCE",
			"cvss": map[string]any{
				"score": 9.8, "rating": "critical",
				"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Vec Plugin", "slug": "vec-plugin",
					"affected_versions": map[string]any{
						"1.0.0 - 1.9.9": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.9.9", "to_inclusive": true,
						},
					},
				},
			},
		},
		idWithout: map[string]any{
			"id":    idWithout,
			"title": "Vec Plugin < 2.0.0 - CSRF",
			"cvss": map[string]any{
				"score": 5.3, "rating": "medium",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Vec Plugin", "slug": "vec-plugin",
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
	path := filepath.Join(dir, "vector-feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMatchDatabaseCVSSVector verifies the emitted vulnerability carries the
// matched record's CVSS vector, and that a record without a vector keeps the
// cvss_vector JSON key omitted (omitempty).
func TestMatchDatabaseCVSSVector(t *testing.T) {
	d, err := db.Load(vectorFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := NewScanner(d, "http://example.test", Options{})
	f := sc.matchDatabase("vec-plugin", "plugin", "1.5.0")
	if len(f.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(f.Vulnerabilities))
	}

	var withVec, withoutVec *Vulnerability
	for i := range f.Vulnerabilities {
		v := &f.Vulnerabilities[i]
		if v.CVSSVector != "" {
			withVec = v
		} else {
			withoutVec = v
		}
	}
	if withVec == nil || withVec.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("vector-bearing vulnerability = %+v, want the feed vector", withVec)
	}
	if withoutVec == nil {
		t.Fatal("expected a vulnerability without a vector")
	}

	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	js := string(out)
	if !strings.Contains(js, `"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`) {
		t.Error("JSON output lost the cvss_vector field")
	}
	// Exactly one occurrence: the empty-vector record must stay omitted.
	if strings.Count(js, `"cvss_vector"`) != 1 {
		t.Errorf("cvss_vector must appear exactly once (empty vectors omitted), got %d", strings.Count(js, `"cvss_vector"`))
	}
}

// TestScanCVSSVectorJSONFlow verifies the CVSS vector survives a full Scan
// end-to-end through the JSON result (not just the raw Finding).
func TestScanCVSSVectorJSONFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/plugins/vec-plugin/vec.png" /></body></html>`))
	})
	mux.HandleFunc("/wp-content/plugins/vec-plugin/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== Vec Plugin ===\nStable tag: 1.5.0\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := db.Load(vectorFeed(t))
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
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	js := string(out)
	if strings.Count(js, `"cvss_vector"`) != 1 {
		t.Errorf("cvss_vector must appear exactly once in scan JSON, got %d", strings.Count(js, `"cvss_vector"`))
	}
}
