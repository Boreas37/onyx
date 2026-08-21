package db

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad feeds arbitrary bytes to the streaming feed loader. The loader
// must never panic: malformed records are skipped, malformed files are an
// error, and whatever loads must expose a consistent (non-negative) count.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"id-1": {"id":"id-1","title":"Plugin A < 1.2","software":[{"type":"plugin","slug":"a","affected_versions":{"*":{"from_version":"*","to_version":"1.2"}}}]}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"broken": {"title": 123}}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "feed.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}
		db, err := Load(path)
		if err != nil {
			return
		}
		if db.Count() < 0 || db.Skipped() < 0 {
			t.Fatalf("negative counts: %d records, %d skipped", db.Count(), db.Skipped())
		}
		for i := range db.Records {
			rec := &db.Records[i]
			if len(rec.Title) > maxTitleLen {
				t.Fatalf("record title exceeds cap: %d chars", len(rec.Title))
			}
			for _, r := range rec.Title {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("control char %q in title %q", r, rec.Title)
				}
			}
		}
	})
}
