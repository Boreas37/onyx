package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
		Enumerate:    "pt",
		PopularSlugs: true,
		MaxRequests:  1000,
		PopularFile:  path,
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
		Enumerate:    "pt",
		PopularSlugs: true,
		MaxRequests:  1000,
		PopularFile:  filepath.Join(t.TempDir(), "does-not-exist.json"),
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
		Enumerate:    "pt",
		PopularSlugs: true,
		MaxRequests:  1000,
		PopularFile:  path,
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
		Enumerate:    "pt",
		PopularSlugs: true,
		MaxRequests:  2,
		PopularFile:  path,
	})
	jobs := sc.buildJobs()
	if len(jobs) != 2 {
		t.Errorf("jobs = %d, want exactly 2 (budget)", len(jobs))
	}
	if containsString(jobSlugs(jobs, "plugin"), "zz-one") {
		t.Errorf("custom slug zz-one appended past the budget: %v", jobSlugs(jobs, "plugin"))
	}
}
