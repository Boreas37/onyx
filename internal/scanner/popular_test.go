package scanner

import (
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// popularScanner builds an aggressive-mode scanner against a dummy base URL
// (buildJobs performs no requests). The minimal feed lists only elementor
// (plugin) and twentytwentyfour (theme), so any other slug in the job list
// must come from the popular seed lists.
func popularScanner(t *testing.T, opts Options) *Scanner {
	t.Helper()
	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	opts.DetectionMode = "aggressive"
	sc, err := NewScanner(d, "http://example.test", opts)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func jobSlugs(jobs []job, kind string) []string {
	var out []string
	for _, j := range jobs {
		if j.kind == kind {
			out = append(out, j.slug)
		}
	}
	return out
}

// TestBuildJobsIncludesPopularOnlySlugs verifies aggressive enumeration
// appends popular seed slugs that are NOT in the database (akismet plugin,
// astra theme) after the DB top-slug loop.
func TestBuildJobsIncludesPopularOnlySlugs(t *testing.T) {
	sc := popularScanner(t, Options{Enumerate: "pt", PopularSlugs: true, MaxRequests: 1000})
	jobs := sc.buildJobs()

	plugins := jobSlugs(jobs, "plugin")
	themes := jobSlugs(jobs, "theme")

	if !containsString(plugins, "akismet") {
		t.Errorf("popular plugin akismet missing from jobs (%d plugins)", len(plugins))
	}
	if !containsString(plugins, "elementor-pro") {
		t.Errorf("popular plugin elementor-pro missing from jobs (%d plugins)", len(plugins))
	}
	if !containsString(themes, "astra") {
		t.Errorf("popular theme astra missing from jobs (%d themes)", len(themes))
	}
	// The DB slugs must come first (deterministic order), then the seeds.
	if len(jobs) < 2 || jobs[0].slug != "elementor" || jobs[1].slug != "twentytwentyfour" {
		t.Errorf("DB top slugs must lead the job list, got %+v", jobs)
	}
}

// TestBuildJobsPopularSlugsRespectEnumerate verifies the popular seeds
// respect the --enumerate flags: theme-only enumeration adds no popular
// plugin seeds and vice versa.
func TestBuildJobsPopularSlugsRespectEnumerate(t *testing.T) {
	sc := popularScanner(t, Options{Enumerate: "t", PopularSlugs: true, MaxRequests: 1000})
	jobs := sc.buildJobs()
	if len(jobSlugs(jobs, "plugin")) != 0 {
		t.Errorf("theme-only enumeration added plugin seeds: %v", jobSlugs(jobs, "plugin"))
	}
	if !containsString(jobSlugs(jobs, "theme"), "astra") {
		t.Errorf("theme-only enumeration should include popular theme astra")
	}

	sc = popularScanner(t, Options{Enumerate: "p", PopularSlugs: true, MaxRequests: 1000})
	jobs = sc.buildJobs()
	if len(jobSlugs(jobs, "theme")) != 0 {
		t.Errorf("plugin-only enumeration added theme seeds: %v", jobSlugs(jobs, "theme"))
	}
	if !containsString(jobSlugs(jobs, "plugin"), "akismet") {
		t.Errorf("plugin-only enumeration should include popular plugin akismet")
	}
}

// TestBuildJobsPopularSlugsOff verifies PopularSlugs=false (the --no-popular
// case) excludes every seed: only the DB top slugs remain.
func TestBuildJobsPopularSlugsOff(t *testing.T) {
	sc := popularScanner(t, Options{Enumerate: "pt", PopularSlugs: false, MaxRequests: 1000})
	jobs := sc.buildJobs()
	if containsString(jobSlugs(jobs, "plugin"), "akismet") {
		t.Errorf("--no-popular must exclude popular plugin akismet, got %v", jobSlugs(jobs, "plugin"))
	}
	if containsString(jobSlugs(jobs, "theme"), "astra") {
		t.Errorf("--no-popular must exclude popular theme astra, got %v", jobSlugs(jobs, "theme"))
	}
	if len(jobs) != 2 {
		t.Errorf("jobs = %+v, want only the 2 DB top slugs", jobs)
	}
}

// TestBuildJobsPopularSlugsStopAtBudget verifies the popular append loop
// stops when the aggressive budget is exhausted: with a 2-job budget the DB
// slugs fill it and no seeds are appended.
func TestBuildJobsPopularSlugsStopAtBudget(t *testing.T) {
	sc := popularScanner(t, Options{Enumerate: "pt", PopularSlugs: true, MaxRequests: 2})
	jobs := sc.buildJobs()
	if len(jobs) != 2 {
		t.Errorf("jobs = %d, want exactly 2 (budget)", len(jobs))
	}
	if containsString(jobSlugs(jobs, "plugin"), "akismet") {
		t.Errorf("seed akismet must not be appended past the budget: %v", jobSlugs(jobs, "plugin"))
	}
}

// containsString reports whether list contains s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
