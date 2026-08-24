package db

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Boreas37/onyx/internal/version"
)

// benchFeed builds a synthetic Wordfence-shaped feed with n records, one of
// which is the contact-form-7 record BenchmarkLookup searches for, and
// writes it to a temp file. It is written inline (rather than reusing the
// db_test.go writeFeed/sampleFeed helpers) because those are typed on
// *testing.T, and a benchmark only hands out *testing.B.
func benchFeed(b *testing.B, n int) string {
	b.Helper()
	ranges, err := version.ParseRanges("1.0.0 - 1.9.9")
	if err != nil {
		b.Fatal(err)
	}
	records := make(map[string]Vuln, n)
	for i := 0; i < n; i++ {
		slug := fmt.Sprintf("plugin-%03d", i)
		if i == 0 {
			slug = "contact-form-7"
		}
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1)
		records[id] = Vuln{
			ID:    id,
			Title: fmt.Sprintf("%s < 2.0.0 - Stored XSS", slug),
			Software: []Software{{
				Type: "plugin",
				Name: slug,
				Slug: slug,
				AffectedVersions: map[string]AffectedVersion{
					"1.0.0 - 1.9.9": {Label: "1.0.0 - 1.9.9", Ranges: ranges},
				},
			}},
		}
	}
	path := filepath.Join(b.TempDir(), "feed.json")
	data, err := json.Marshal(records)
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	return path
}

// BenchmarkLoadCached measures the COLD load path of LoadCached: the sidecar
// is removed at the top of every iteration so each one pays the full JSON
// decode plus the best-effort SaveIndex refresh. The steady-state hot sidecar
// path is a cache hit and not what this benchmark measures; -benchtime=1x
// keeps the cold runs cheap while remaining deterministic.
func BenchmarkLoadCached(b *testing.B) {
	b.ReportAllocs()
	path := benchFeed(b, 200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Cold start every iteration: no pre-built index may be present.
		_ = os.Remove(path + ".idx")
		d, err := LoadCached(path)
		if err != nil {
			b.Fatal(err)
		}
		if d.Count() != 200 {
			b.Fatalf("Count() = %d, want 200", d.Count())
		}
	}
}

// BenchmarkLookup measures a slug lookup against a pre-loaded DB. The feed
// is loaded once (outside the timed loop) and the contact-form-7 record is
// looked up on every iteration. Lookup returns defensive copies, so
// allocations are expected and reported.
func BenchmarkLookup(b *testing.B) {
	b.ReportAllocs()
	path := benchFeed(b, 200)
	d, err := Load(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recs := d.Lookup("contact-form-7")
		if len(recs) != 1 {
			b.Fatalf("Lookup(contact-form-7) len = %d, want 1", len(recs))
		}
	}
}
