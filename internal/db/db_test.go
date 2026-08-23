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

// scannerFeed writes a minimal scanner-feed JSON document (records carry
// only detection info, no software array).
func scannerFeed(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanner.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustParseV(t *testing.T, s string) version.Version {
	t.Helper()
	v, ok := version.Parse(s)
	if !ok {
		t.Fatalf("version.Parse(%q) failed", s)
	}
	return v
}

func TestLoadScannerFeedTitleBased(t *testing.T) {
	path := scannerFeed(t, `{
		"11111111-0000-0000-0000-000000000001": {
			"id": "11111111-0000-0000-0000-000000000001",
			"title": "Elementor < 3.25.0 - SQL Injection"
		},
		"22222222-0000-0000-0000-000000000002": {
			"id": "22222222-0000-0000-0000-000000000002",
			"title": "WooCommerce <= 7.1.0 - Missing Authorization"
		},
		"33333333-0000-0000-0000-000000000003": {
			"id": "33333333-0000-0000-0000-000000000003",
			"title": "Akismet = 4.0.0 - Stored XSS",
			"software": []
		}
	}`)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Skipped() != 0 {
		t.Errorf("Skipped() = %d, want 0", got.Skipped())
	}
	if got.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", got.Count())
	}

	// "<" — exclusive upper bound, slug lowercased/hyphenated from the name.
	ele := got.Lookup("elementor")
	if len(ele) != 1 {
		t.Fatalf("Lookup(elementor) len = %d, want 1", len(ele))
	}
	if ele[0].Title != "Elementor < 3.25.0 - SQL Injection" {
		t.Errorf("unexpected record: %q", ele[0].Title)
	}
	s := ele[0].Software[0]
	if s.Slug != "elementor" || s.Type != "plugin" || s.Name != "Elementor" {
		t.Errorf("software = %+v, want slug=elementor type=plugin name=Elementor", s)
	}
	ranges := s.AffectedVersions["< 3.25.0"].Ranges
	if len(ranges) != 1 {
		t.Fatalf("AffectedVersions[\"< 3.25.0\"] ranges = %+v, want 1 range", ranges)
	}
	if !version.InRanges(ranges, mustParseV(t, "3.24.9")) {
		t.Error("3.24.9 should be affected by < 3.25.0")
	}
	if version.InRanges(ranges, mustParseV(t, "3.25.0")) {
		t.Error("3.25.0 should not be affected by < 3.25.0")
	}

	// "<=" — inclusive upper bound.
	woo := got.Lookup("woocommerce")
	if len(woo) != 1 {
		t.Fatalf("Lookup(woocommerce) len = %d, want 1", len(woo))
	}
	wooRanges := woo[0].Software[0].AffectedVersions["<= 7.1.0"].Ranges
	if !version.InRanges(wooRanges, mustParseV(t, "7.1.0")) {
		t.Error("7.1.0 should be affected by <= 7.1.0")
	}
	if version.InRanges(wooRanges, mustParseV(t, "7.1.1")) {
		t.Error("7.1.1 should not be affected by <= 7.1.0")
	}

	// "=" — exact version; also covers an explicit empty software array.
	aki := got.Lookup("akismet")
	if len(aki) != 1 {
		t.Fatalf("Lookup(akismet) len = %d, want 1", len(aki))
	}
	akiRanges := aki[0].Software[0].AffectedVersions["= 4.0.0"].Ranges
	if !version.InRanges(akiRanges, mustParseV(t, "4.0.0")) {
		t.Error("4.0.0 should be affected by = 4.0.0")
	}
	if version.InRanges(akiRanges, mustParseV(t, "4.0.1")) {
		t.Error("4.0.1 should not be affected by = 4.0.0")
	}
}

func TestLoadScannerFeedUnparseableSkipped(t *testing.T) {
	path := scannerFeed(t, `{
		"11111111-0000-0000-0000-000000000001": {
			"id": "11111111-0000-0000-0000-000000000001",
			"title": "No version hint here"
		},
		"22222222-0000-0000-0000-000000000002": {
			"id": "22222222-0000-0000-0000-000000000002",
			"title": "Plugin < nope"
		}
	}`)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Skipped() != 2 {
		t.Errorf("Skipped() = %d, want 2", got.Skipped())
	}
	if got.Count() != 0 {
		t.Errorf("Count() = %d, want 0 (unparseable records must be dropped)", got.Count())
	}
	if len(got.Lookup("plugin")) != 0 {
		t.Errorf("Lookup(plugin) = %v, want empty", got.Lookup("plugin"))
	}
}

func TestTitleSoftwareSlugify(t *testing.T) {
	s, ok := titleSoftware("Hello Dolly <= 1.7.2 - XSS")
	if !ok {
		t.Fatal("titleSoftware failed on valid title")
	}
	if s.Slug != "hello-dolly" || s.Name != "Hello Dolly" {
		t.Errorf("slug/name = %q/%q, want hello-dolly/Hello Dolly", s.Slug, s.Name)
	}
}

// TestLoadNormalizesCVSSRating is a table-driven check of the load-time
// rating whitelist: ratings are lowercased, whitelisted values pass
// through, anything else becomes "" and score/vector stay untouched.
func TestLoadNormalizesCVSSRating(t *testing.T) {
	cases := []struct {
		name  string
		rate  string
		score float64
		vec   string
		want  string
	}{
		{"empty", "", 0, "", ""},
		{"critical", "critical", 9.8, "AV:N/AC:L", "critical"},
		{"uppercase", "CRITICAL", 9.8, "AV:N/AC:L", "critical"},
		{"high mixed case", "High", 7.5, "", "high"},
		{"medium uppercase", "MEDIUM", 5.0, "", "medium"},
		{"low", "low", 3.1, "", "low"},
		{"info", "info", 0, "", "info"},
		{"informational", "Informational", 0, "", "informational"},
		{"none", "NONE", 0, "", "none"},
		{"unknown label", "severe", 9.0, "", ""},
		{"near miss", "critcal", 9.0, "", ""},
		{"padded junk", " high ", 7.5, "", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := writeFeed(t, map[string]Vuln{
				"55555555-0000-0000-0000-000000000009": {
					ID:    "55555555-0000-0000-0000-000000000009",
					Title: "Test Plugin < 2.0.0 - X",
					CVSS:  CVSS{Vector: tc.vec, Score: tc.score, Rating: tc.rate},
					Software: []Software{{
						Type: "plugin", Name: "test-plugin", Slug: "test-plugin",
						AffectedVersions: map[string]AffectedVersion{},
					}},
				},
			})
			got, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.Count() != 1 {
				t.Fatalf("Count() = %d, want 1", got.Count())
			}
			rec := got.Records[0]
			if rec.CVSS.Rating != tc.want {
				t.Errorf("rating = %q, want %q", rec.CVSS.Rating, tc.want)
			}
			if rec.CVSS.Score != tc.score {
				t.Errorf("score = %v, want untouched %v", rec.CVSS.Score, tc.score)
			}
			if rec.CVSS.Vector != tc.vec {
				t.Errorf("vector = %q, want untouched %q", rec.CVSS.Vector, tc.vec)
			}
		})
	}
}
