package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// popularFile writes a --popular-file JSON document and returns its path.
func popularFile(t *testing.T, plugins, themes []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "popular.json")
	data, err := json.Marshal(map[string][]string{
		"plugins": plugins,
		"themes":  themes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func countOccurrences(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}

// TestPopularFileReplacesBuiltins verifies a readable --popular-file
// replaces the built-in popular.go lists entirely: only the file's slugs
// join the jobs (deduplicated, in file order), and no built-in seed
// (akismet plugin, astra theme) appears.
func TestPopularFileReplacesBuiltins(t *testing.T) {
	path := popularFile(t, []string{"zz-one", "zz-two", "zz-one"}, []string{"zz-theme"})
	sc := popularScanner(t, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   1000,
		PopularFile:   path,
	})
	jobs := sc.buildJobs()

	plugins := jobSlugs(jobs, "plugin")
	themes := jobSlugs(jobs, "theme")

	if !containsString(plugins, "zz-one") || !containsString(plugins, "zz-two") {
		t.Errorf("custom plugin slugs missing from jobs: %v", plugins)
	}
	if countOccurrences(plugins, "zz-one") != 1 {
		t.Errorf("zz-one must be deduplicated, got %d occurrences", countOccurrences(plugins, "zz-one"))
	}
	if containsString(plugins, "akismet") {
		t.Errorf("built-in seed akismet leaked into jobs: %v", plugins)
	}
	if !containsString(themes, "zz-theme") {
		t.Errorf("custom theme slug missing from jobs: %v", themes)
	}
	if containsString(themes, "astra") {
		t.Errorf("built-in seed astra leaked into jobs: %v", themes)
	}

	// Ordering rules are unchanged: the DB top slugs lead, then the custom
	// list in file order (elementor and twentytwentyfour come from the
	// minimal feed's top-slug list).
	zi, zj := -1, -1
	for i, s := range plugins {
		switch s {
		case "zz-one":
			zi = i
		case "zz-two":
			zj = i
		}
	}
	if zi == -1 || zj == -1 || zi > zj {
		t.Errorf("custom slugs out of file order: %v", plugins)
	}
	if len(jobs) < 2 || jobs[0].slug != "elementor" || jobs[1].slug != "twentytwentyfour" {
		t.Errorf("DB top slugs must still lead the job list, got %+v", jobs)
	}
}

// TestPopularFileMissingFallsBackToBuiltins verifies a missing
// --popular-file is a soft fallback: buildJobs keeps using the built-in
// seed lists and never errors.
func TestPopularFileMissingFallsBackToBuiltins(t *testing.T) {
	sc := popularScanner(t, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   1000,
		PopularFile:   filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	jobs := sc.buildJobs()

	plugins := jobSlugs(jobs, "plugin")
	themes := jobSlugs(jobs, "theme")
	if !containsString(plugins, "akismet") {
		t.Errorf("missing popular file must fall back to built-in plugins, got %v", plugins)
	}
	if !containsString(themes, "astra") {
		t.Errorf("missing popular file must fall back to built-in themes, got %v", themes)
	}
}

// TestPopularFileUnparseableFallsBackToBuiltins verifies an unparseable
// --popular-file (valid JSON shape but wrong types) also falls back to the
// built-ins without error.
func TestPopularFileUnparseableFallsBackToBuiltins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"plugins": 42}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := popularScanner(t, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   1000,
		PopularFile:   path,
	})
	jobs := sc.buildJobs()
	if !containsString(jobSlugs(jobs, "plugin"), "akismet") {
		t.Errorf("unparseable popular file must fall back to built-ins, got %v", jobSlugs(jobs, "plugin"))
	}
}

// TestPopularFileRespectsBudget verifies the custom lists stay budget
// capped exactly like the built-ins: a 2-job budget is consumed by the DB
// top slugs, so no custom slug is appended.
func TestPopularFileRespectsBudget(t *testing.T) {
	path := popularFile(t, []string{"zz-one"}, nil)
	sc := popularScanner(t, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   2,
		PopularFile:   path,
	})
	jobs := sc.buildJobs()
	if len(jobs) != 2 {
		t.Errorf("jobs = %d, want exactly 2 (budget)", len(jobs))
	}
	if containsString(jobSlugs(jobs, "plugin"), "zz-one") {
		t.Errorf("custom slug zz-one appended past the budget: %v", jobSlugs(jobs, "plugin"))
	}
}

// popularFileRaw writes an exact JSON document as the --popular-file and
// returns its path.
func popularFileRaw(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "popular.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanPopularFileCountsAttachToDetections verifies the extended
// --popular-file shape end to end: counts_plugins/counts_themes decorate
// the matching detections after the final dedup. The cap applies (a
// 10-digit count saturates at maxActiveInstalls), type mismatches are
// ignored (the elementor entry under counts_themes, the twentytwentyfour
// entry under counts_plugins) and a detected slug with no count stays 0.
func TestScanPopularFileCountsAttachToDetections(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	path := popularFileRaw(t, `{"plugins":["elementor","akismet"],"themes":["twentytwentyfour"],`+
		`"counts_plugins":{"elementor":9999999999,"twentytwentyfour":99},`+
		`"counts_themes":{"twentytwentyfour":456,"elementor":888}}`)
	sc, err := NewScanner(d, srv.URL, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   1000,
		PopularFile:   path,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	bySlug := make(map[string]Detected)
	for _, det := range res.Detected {
		bySlug[det.Slug] = det
	}
	ele, ok := bySlug["elementor"]
	if !ok {
		t.Fatalf("elementor not detected: %+v", res.Detected)
	}
	if ele.ActiveInstalls != maxActiveInstalls {
		t.Errorf("elementor ActiveInstalls = %d, want capped %d", ele.ActiveInstalls, maxActiveInstalls)
	}
	aka, ok := bySlug["akismet"]
	if !ok {
		t.Fatalf("akismet not detected: %+v", res.Detected)
	}
	if aka.ActiveInstalls != 0 {
		t.Errorf("akismet ActiveInstalls = %d, want 0 (no count in file)", aka.ActiveInstalls)
	}
	ttf, ok := bySlug["twentytwentyfour"]
	if !ok {
		t.Fatalf("twentytwentyfour not detected: %+v", res.Detected)
	}
	if ttf.ActiveInstalls != 456 {
		t.Errorf("twentytwentyfour ActiveInstalls = %d, want 456 (counts_themes, counts_plugins entry ignored)", ttf.ActiveInstalls)
	}
}

// TestScanPopularFilePlainShapeHasNoCounts verifies the plain
// --popular-file shape (no counts maps) leaves every detection at 0.
func TestScanPopularFilePlainShapeHasNoCounts(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	path := popularFile(t, []string{"elementor", "akismet"}, []string{"twentytwentyfour"})
	sc, err := NewScanner(d, srv.URL, Options{
		Enumerate:     "pt",
		PopularSlugs:  true,
		PopularThemes: true,
		MaxRequests:   1000,
		PopularFile:   path,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, det := range res.Detected {
		if det.ActiveInstalls != 0 {
			t.Errorf("%s ActiveInstalls = %d, want 0 (plain file shape)", det.Slug, det.ActiveInstalls)
		}
	}
}

// TestAttachActiveInstalls drives the count-attachment helper directly:
// first match wins per type, unknown slugs stay 0, type mismatches (a
// plugin slug under counts_themes) stay 0, and oversized counts are capped
// at maxActiveInstalls. A scanner with nil count maps is a no-op.
func TestAttachActiveInstalls(t *testing.T) {
	sc := &Scanner{
		popularCountsPlugins: map[string]int{"foo": 5, "huge": 1 << 40},
		popularCountsThemes:  map[string]int{"bar": 7},
	}
	detected := []Detected{
		{Slug: "foo", Type: "plugin"},
		{Slug: "bar", Type: "theme"},
		{Slug: "huge", Type: "plugin"},
		{Slug: "unknown", Type: "plugin"},
		{Slug: "foo", Type: "theme"},  // plugin slug listed under counts_themes
		{Slug: "bar", Type: "plugin"}, // theme slug listed under counts_plugins
	}
	sc.attachActiveInstalls(detected)
	want := []int{5, 7, maxActiveInstalls, 0, 0, 0}
	for i, w := range want {
		if detected[i].ActiveInstalls != w {
			t.Errorf("detected[%d] (%s/%s) ActiveInstalls = %d, want %d",
				i, detected[i].Type, detected[i].Slug, detected[i].ActiveInstalls, w)
		}
	}

	plain := &Scanner{}
	detected = []Detected{{Slug: "foo", Type: "plugin"}}
	plain.attachActiveInstalls(detected)
	if detected[0].ActiveInstalls != 0 {
		t.Errorf("nil count maps changed ActiveInstalls to %d", detected[0].ActiveInstalls)
	}
}

// TestPopularFileCountsDecode verifies popularSeedLists decodes the
// extended counts maps alongside the lists and leaves them nil for the
// plain shape.
func TestPopularFileCountsDecode(t *testing.T) {
	ext := popularFileRaw(t, `{"plugins":["zz-one"],"themes":["zz-theme"],`+
		`"counts_plugins":{"zz-one":123},"counts_themes":{"zz-theme":456}}`)
	sc := popularScanner(t, Options{
		Enumerate:   "pt",
		MaxRequests: 1000,
		PopularFile: ext,
	})
	plugins, themes := sc.popularSeedLists()
	if len(plugins) != 1 || plugins[0] != "zz-one" {
		t.Errorf("plugins = %v, want [zz-one]", plugins)
	}
	if len(themes) != 1 || themes[0] != "zz-theme" {
		t.Errorf("themes = %v, want [zz-theme]", themes)
	}
	if sc.popularCountsPlugins["zz-one"] != 123 {
		t.Errorf("popularCountsPlugins = %v, want zz-one:123", sc.popularCountsPlugins)
	}
	if sc.popularCountsThemes["zz-theme"] != 456 {
		t.Errorf("popularCountsThemes = %v, want zz-theme:456", sc.popularCountsThemes)
	}

	plain := popularFile(t, []string{"zz-one"}, []string{"zz-theme"})
	sc = popularScanner(t, Options{
		Enumerate:   "pt",
		PopularFile: plain,
	})
	_, _ = sc.popularSeedLists()
	if sc.popularCountsPlugins != nil || sc.popularCountsThemes != nil {
		t.Errorf("plain shape must leave count maps nil, got %v / %v",
			sc.popularCountsPlugins, sc.popularCountsThemes)
	}
}
