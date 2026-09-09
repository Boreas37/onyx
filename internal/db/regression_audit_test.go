package db

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRawFeed(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditGhostRecordDropped(t *testing.T) {
	feed := `{"deadbeef-0000-0000-0000-000000000001":{"id":"deadbeef-0000-0000-0000-000000000001","title":"X","software":[{"type":"plugin","slug":"broken","affected_versions":{"garbage range that cannot parse!!!":{"from_version":"","to_version":""}}}]}}`
	d, err := Load(writeRawFeed(t, feed))
	if err != nil {
		t.Fatal(err)
	}
	if d.Count() != 0 {
		t.Errorf("Count = %d, want 0 (all-software-broken record must be dropped)", d.Count())
	}
	if got := len(d.Lookup("broken")); got != 0 {
		t.Errorf("Lookup(broken) = %d, want 0", got)
	}
}

func TestAuditStructuredSlugNormalized(t *testing.T) {
	feed := `{"a":{"id":"a","title":"T","software":[{"type":"plugin","name":"Elementor","slug":"Elementor","affected_versions":{"<= 1.0":{}}}]}}`
	d, err := Load(writeRawFeed(t, feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Lookup("elementor")) != 1 {
		t.Errorf("Lookup(elementor) miss after structured slug Elementor; got %d", len(d.Lookup("elementor")))
	}
	feed2 := `{"a":{"id":"a","title":"T","software":[{"type":"plugin","name":"P","slug":" my-plugin ","affected_versions":{"<= 1.0":{}}}]}}`
	d2, err := Load(writeRawFeed(t, feed2))
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.Lookup("my-plugin")) != 1 {
		t.Errorf("Lookup(my-plugin) miss after spaced slug; got %d", len(d2.Lookup("my-plugin")))
	}
}

func TestAuditLookupDeepCopy(t *testing.T) {
	feed := `{"a":{"id":"a","title":"T","software":[{"type":"plugin","name":"E","slug":"elementor","affected_versions":{"<= 1.0":{}}}]}}`
	d, err := Load(writeRawFeed(t, feed))
	if err != nil {
		t.Fatal(err)
	}
	a := d.Lookup("elementor")
	if len(a) == 0 || len(a[0].Software) == 0 {
		t.Fatal("setup miss")
	}
	a[0].Software[0].Slug = "mutated"
	b := d.Lookup("elementor")
	if b[0].Software[0].Slug == "mutated" {
		t.Errorf("Lookup shares Software slice; mutation leaked into index")
	}
}
