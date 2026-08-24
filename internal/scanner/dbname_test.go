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

// namedFeed writes a Wordfence-shaped feed whose records exercise the
// display-name and fix-metadata plumbing: "acme-plugin" carries a real
// display name plus remediation guidance and patched versions, while
// "ghost-plugin" omits the name field entirely (NameFor must then fall
// back to the slug).
func namedFeed(t *testing.T) string {
	t.Helper()
	feed := map[string]any{
		"cccccccc-0000-0000-0000-00000000000c": map[string]any{
			"id":    "cccccccc-0000-0000-0000-00000000000c",
			"title": "Acme Plugin < 2.0.0 - Arbitrary File Upload",
			"cvss": map[string]any{
				"score":  8.8,
				"rating": "high",
			},
			"software": []any{
				map[string]any{
					"type": "plugin", "name": "Acme Plugin", "slug": "acme-plugin",
					"affected_versions": map[string]any{
						"1.0.0 - 1.9.9": map[string]any{
							"from_version": "1.0.0", "from_inclusive": true,
							"to_version": "1.9.9", "to_inclusive": true,
						},
					},
					"patched":          true,
					"patched_versions": []any{"2.0.0"},
					"remediation":      "Update to version 2.0.0 or newer.",
				},
			},
		},
		"dddddddd-0000-0000-0000-00000000000d": map[string]any{
			"id":    "dddddddd-0000-0000-0000-00000000000d",
			"title": "Ghost Plugin < 1.1.0 - CSRF",
			"cvss": map[string]any{
				"score":  6.1,
				"rating": "medium",
			},
			"software": []any{
				// Deliberately no "name" field: the slug must be used.
				map[string]any{
					"type": "plugin", "slug": "ghost-plugin",
					"affected_versions": map[string]any{
						"0.5.0 - 1.0.9": map[string]any{
							"from_version": "0.5.0", "from_inclusive": true,
							"to_version": "1.0.9", "to_inclusive": true,
						},
					},
				},
			},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "named-feed.json")
	data, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// namedFeedServer serves a WordPress homepage referencing both fixture
// plugins, with readmes answering Stable tag versions inside the
// vulnerable ranges.
func namedFeedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><img src="/wp-content/plugins/acme-plugin/acme.png" />
<img src="/wp-content/plugins/ghost-plugin/ghost.png" /></body></html>`))
	})
	mux.HandleFunc("/wp-content/plugins/acme-plugin/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Acme Plugin ===
Contributors: acmeteam
Tags: utility
Stable tag: 1.5.0
License: GPLv2
`))
	})
	mux.HandleFunc("/wp-content/plugins/ghost-plugin/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Ghost Plugin ===
Contributors: ghost
Stable tag: 1.0.5
`))
	})
	return httptest.NewServer(mux)
}

// TestScanDisplayNameAndFixMetadata verifies A1 end-to-end: a finding for a
// slug the database knows by a display name carries that name instead of
// the slug, a slug the database does not know falls back to the slug, and
// the first matching software entry's Remediation and PatchedVersions flow
// into the emitted vulnerability.
func TestScanDisplayNameAndFixMetadata(t *testing.T) {
	srv := namedFeedServer(t)
	defer srv.Close()

	d, err := db.Load(namedFeed(t))
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

	var acme, ghost *Finding
	for i := range res.Findings {
		switch res.Findings[i].Slug {
		case "acme-plugin":
			acme = &res.Findings[i]
		case "ghost-plugin":
			ghost = &res.Findings[i]
		}
	}
	if acme == nil {
		t.Fatalf("no finding for acme-plugin, got %+v", res.Findings)
	}
	if acme.Name != "Acme Plugin" {
		t.Errorf("Finding.Name = %q, want %q (database display name)", acme.Name, "Acme Plugin")
	}
	if ghost == nil {
		t.Fatalf("no finding for ghost-plugin, got %+v", res.Findings)
	}
	if ghost.Name != "ghost-plugin" {
		t.Errorf("Finding.Name = %q, want the slug fallback %q", ghost.Name, "ghost-plugin")
	}

	if len(acme.Vulnerabilities) != 1 {
		t.Fatalf("acme vulnerabilities = %d, want 1", len(acme.Vulnerabilities))
	}
	v := acme.Vulnerabilities[0]
	if v.Remediation != "Update to version 2.0.0 or newer." {
		t.Errorf("Remediation = %q, want the feed value", v.Remediation)
	}
	if len(v.PatchedVersions) != 1 || v.PatchedVersions[0] != "2.0.0" {
		t.Errorf("PatchedVersions = %v, want [2.0.0]", v.PatchedVersions)
	}
	if len(acme.Vulnerabilities[0].AffectedLabels) != 1 || acme.Vulnerabilities[0].AffectedLabels[0] != "1.0.0 - 1.9.9" {
		t.Errorf("AffectedLabels = %v, want [1.0.0 - 1.9.9]", acme.Vulnerabilities[0].AffectedLabels)
	}
	// ghost-plugin's record carries no remediation or patched versions:
	// both fields must stay empty on its vulnerability.
	if len(ghost.Vulnerabilities) != 1 {
		t.Fatalf("ghost vulnerabilities = %d, want 1", len(ghost.Vulnerabilities))
	}
	if ghost.Vulnerabilities[0].Remediation != "" || len(ghost.Vulnerabilities[0].PatchedVersions) != 0 {
		t.Errorf("ghost vuln must carry no fix metadata, got %+v", ghost.Vulnerabilities[0])
	}

	// The Detected entry for the readme-probed plugin uses the display name
	// too (scanJob resolves it for every source).
	for _, det := range res.Detected {
		if det.Slug == "acme-plugin" && det.Name != "Acme Plugin" {
			t.Errorf("Detected.Name = %q, want %q", det.Name, "Acme Plugin")
		}
		if det.Slug == "ghost-plugin" && det.Name != "ghost-plugin" {
			t.Errorf("Detected.Name = %q, want slug fallback", det.Name)
		}
	}
}

// TestScanFixMetadataJSONFlow verifies the fix metadata survives the JSON
// round-trip: "remediation" and "patched_versions" keys appear for records
// that carry them, and stay absent (omitempty) for records that do not.
func TestScanFixMetadataJSONFlow(t *testing.T) {
	srv := namedFeedServer(t)
	defer srv.Close()

	d, err := db.Load(namedFeed(t))
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
	if !strings.Contains(js, `"remediation":"Update to version 2.0.0 or newer."`) {
		t.Error("JSON output lost the remediation field")
	}
	if !strings.Contains(js, `"patched_versions":["2.0.0"]`) {
		t.Error("JSON output lost the patched_versions field")
	}
	if !strings.Contains(js, `"name":"Acme Plugin"`) {
		t.Error("JSON output lost the display name")
	}

	// A feed record without fix metadata must not emit the keys at all
	// (omitempty): ghost-plugin is that record in this feed.
	if !strings.Contains(js, `"slug":"ghost-plugin"`) {
		t.Fatal("fixture missing ghost-plugin finding, cannot verify omitempty")
	}
	if strings.Count(js, `"remediation"`) != 1 || strings.Count(js, `"patched_versions"`) != 1 {
		t.Errorf("remediation/patched_versions must appear exactly once (only acme carries them), got %d/%d",
			strings.Count(js, `"remediation"`), strings.Count(js, `"patched_versions"`))
	}
}
