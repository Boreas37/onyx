package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// benchFeedOnce / benchFeedPath cache the prebuilt benchmark feed so the
// one-time file write does not pollute the measured iterations.
var (
	benchFeedOnce sync.Once
	benchFeedPath string
)

// benchFeedFile writes a small Wordfence-shaped feed with a handful of
// records (a few slugs, one with multiple records) and returns its path.
func benchFeedFile() string {
	benchFeedOnce.Do(func() {
		dir, err := os.MkdirTemp("", "onyx-bench")
		if err != nil {
			panic(err)
		}
		benchFeedPath = filepath.Join(dir, "bench-feed.json")
		feed := map[string]any{}
		for i := 1; i <= 3; i++ {
			id := "b0000000-0000-0000-0000-00000000000" + string(rune('0'+i))
			feed[id] = map[string]any{
				"id":    id,
				"title": "Bench Plugin < 2.0.0 - Issue " + string(rune('0'+i)),
				"cvss": map[string]any{
					"score": 9.1, "rating": "critical",
					"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				"software": []any{
					map[string]any{
						"type": "plugin", "name": "Bench Plugin", "slug": "bench-plugin",
						"affected_versions": map[string]any{
							"1.0.0 - 1.9.9": map[string]any{
								"from_version": "1.0.0", "from_inclusive": true,
								"to_version": "1.9.9", "to_inclusive": true,
							},
						},
					},
				},
			}
		}
		data, err := json.Marshal(feed)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(benchFeedPath, data, 0o644); err != nil {
			panic(err)
		}
	})
	return benchFeedPath
}

// BenchmarkMatchDatabase measures the per-component DB matching cost: one
// record list lookup plus version-range comparison per iteration.
func BenchmarkMatchDatabase(b *testing.B) {
	d, err := db.Load(benchFeedFile())
	if err != nil {
		b.Fatal(err)
	}
	sc, err := NewScanner(d, "http://example.test", Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := sc.matchDatabase("bench-plugin", "plugin", "1.5.0")
		if len(f.Vulnerabilities) != 3 {
			b.Fatalf("benchmark fixture broken: got %d vulnerabilities", len(f.Vulnerabilities))
		}
	}
}

// BenchmarkExtractPassiveVersionsIn measures passive ?ver= extraction over
// a typical plugin/theme-heavy homepage body.
func BenchmarkExtractPassiveVersionsIn(b *testing.B) {
	var html strings.Builder
	html.WriteString("<!DOCTYPE html><html><head><meta name=\"generator\" content=\"WordPress 6.4.2\" /></head><body>")
	for i := 0; i < 50; i++ {
		html.WriteString(`<script src="/wp-content/plugins/plugin-` + itoa(i) + `/assets/x.js?ver=1.2.3"></script>`)
		html.WriteString(`<link rel="stylesheet" href="/wp-content/themes/theme-` + itoa(i) + `/style.css?ver=2.0" />`)
	}
	html.WriteString("</body></html>")
	s := html.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := ExtractPassiveVersionsIn(s, "wp-content")
		if len(got) != 100 {
			b.Fatalf("benchmark fixture broken: got %d versions", len(got))
		}
	}
}
