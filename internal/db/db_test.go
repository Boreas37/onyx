package db

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Boreas37/onyx/internal/version"
)

func writeFeed(t *testing.T, records map[string]Vuln) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func sampleFeed() map[string]Vuln {
	rec := func(id, title string, informational bool, soft ...Software) Vuln {
		return Vuln{ID: id, Title: title, Informational: informational, Software: soft}
	}
	plugin := func(slug string, affected map[string]AffectedVersion) Software {
		return Software{
			Type:             "plugin",
			Name:             slug,
			Slug:             slug,
			AffectedVersions: affected,
		}
	}
	ar := func(label string, ranges []version.Range) AffectedVersion {
		return AffectedVersion{Label: label, Ranges: ranges}
	}
	// Elementor vuln: affected < 3.25.0.
	eleRanges, _ := version.ParseRanges("1.0.0 - 3.24.9")
	// A straight-to-version range from the bracket format.
	brRanges, _ := version.ParseRanges("[*, 3.7)")
	// Universal range "*".
	starRanges, _ := version.ParseRanges("*")
	return map[string]Vuln{
		"11111111-0000-0000-0000-000000000001": rec(
			"11111111-0000-0000-0000-000000000001",
			"Elementor < 3.25.0 - SQL Injection",
			false,
			plugin("elementor", map[string]AffectedVersion{
				"1.0.0 - 3.24.9": ar("1.0.0 - 3.24.9", eleRanges),
			}),
		),
		"22222222-0000-0000-0000-000000000002": rec(
			"22222222-0000-0000-0000-000000000002",
			"SomeTheme <= 3.7 - XSS",
			false,
			Software{
				Type: "theme",
				Name: "SomeTheme",
				Slug: "sometheme",
				AffectedVersions: map[string]AffectedVersion{
					"[*, 3.7)": ar("[*, 3.7)", brRanges),
				},
			},
		),
		"33333333-0000-0000-0000-000000000003": rec(
			"33333333-0000-0000-0000-000000000003",
			"Elementor < 3.25.0 - Info only",
			true,
			plugin("elementor", map[string]AffectedVersion{"*": ar("*", starRanges)}),
		),
		"44444444-0000-0000-0000-000000000004": rec(
			"44444444-0000-0000-0000-000000000004",
			"SomePlugin - all versions affected",
			false,
			plugin("someplugin", map[string]AffectedVersion{"*": ar("*", starRanges)}),
		),
	}
}

func TestLoadIndexesBySlug(t *testing.T) {
	path := writeFeed(t, sampleFeed())
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Count() != 4 {
		t.Fatalf("Count()=%d want 4", got.Count())
	}

	ele := got.Lookup("elementor")
	if len(ele) != 1 {
		t.Fatalf("Lookup(elementor) len=%d want 1 (informational must be excluded)", len(ele))
	}
	if ele[0].Title != "Elementor < 3.25.0 - SQL Injection" {
		t.Errorf("unexpected record: %q", ele[0].Title)
	}

	if len(got.Lookup("nope")) != 0 {
		t.Errorf("Lookup(nope) should be empty")
	}

	if len(got.Lookup("sometheme")) != 1 {
		t.Errorf("Lookup(sometheme) len=1")
	}
	if len(got.Lookup("someplugin")) != 1 {
		t.Errorf("Lookup(someplugin) len=1")
	}
}

func TestLoadTopSlugs(t *testing.T) {
	path := writeFeed(t, sampleFeed())
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	top := got.TopSlugs(10)
	// elementor appears twice in the feed but only once non-informational,
	// so all slugs tie at 1; ordering among ties is alphabetical.
	want := []string{"elementor", "someplugin", "sometheme"}
	if len(top) != len(want) {
		t.Fatalf("TopSlugs len=%d want %d (%v)", len(top), len(want), top)
	}
	for i := range want {
		if top[i] != want[i] {
			t.Errorf("TopSlugs[%d]=%q want %q", i, top[i], want[i])
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/feed.json"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoadBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for bad JSON")
	}
}

func TestLoadNonObjectRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(path, []byte("[1,2,3]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for non-object root")
	}
}

func TestDecodeSoftwareStructuredFields(t *testing.T) {
	// The real feed uses structured from/to fields; verify label fallback is
	// not required and the structured range is kept.
	rm := []byte(`{
		"type": "plugin",
		"name": "We're Open!",
		"slug": "opening-hours",
		"affected_versions": {
			"*-1.37": {
				"from_version": "*",
				"from_inclusive": true,
				"to_version": "1.37",
				"to_inclusive": true
			}
		}
	}`)
	s, drop := decodeSoftware(rm)
	if drop {
		t.Fatalf("decodeSoftware dropped valid entry")
	}
	rs, ok := s.AffectedVersions["*-1.37"]
	if !ok || len(rs.Ranges) != 1 {
		t.Fatalf("expected one range for \"*-1.37\"")
	}
	for _, v := range []string{"0.5", "1.0", "1.37"} {
		pv, _ := version.Parse(v)
		if !version.InRanges(rs.Ranges, pv) {
			t.Errorf("version %s should be in *-1.37", v)
		}
	}
	pv, _ := version.Parse("1.38")
	if version.InRanges(rs.Ranges, pv) {
		t.Errorf("version 1.38 should not be in *-1.37")
	}
}

func TestDecodeSoftwareBadRangeSkipped(t *testing.T) {
	rm := []byte(`{
		"type": "plugin",
		"name": "Broken",
		"slug": "broken",
		"affected_versions": {
			"garbage range that cannot parse": {"from_version": "", "to_version": ""}
		}
	}`)
	_, drop := decodeSoftware(rm)
	if !drop {
		t.Fatalf("expected entry to be dropped")
	}
}

func TestLookupReturnsCopies(t *testing.T) {
	path := writeFeed(t, sampleFeed())
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := got.Lookup("elementor")
	b := got.Lookup("elementor")
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("expected records")
	}
	a[0].Title = "mutated"
	if b[0].Title == a[0].Title {
		t.Errorf("Lookup should return copies, not internal pointers")
	}
}