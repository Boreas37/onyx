package pocs

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractLinksFromYearREADME verifies that PoC rows are pulled out of
// the year README table of a fake tracker clone: only rows of the queried
// CVE are returned, star counts come from the Stars column, duplicate
// rows collapse, and foreign-host rows are ignored.
func TestExtractLinksFromYearREADME(t *testing.T) {
	dir := t.TempDir()
	year := filepath.Join(dir, "2026")
	if err := os.MkdirAll(year, 0o755); err != nil {
		t.Fatal(err)
	}
	md := `# 2026 CVE PoCs

**1,114 CVEs · 1,996 PoC repositories**

| CVE | Target repository | Stars | Description |
|---|---:|---|
| [CVE-2026-0073](https://github.com/xqi1337/poc-CVE-2026-0073) | [xqi1337/poc-CVE-2026-0073](https://github.com/xqi1337/poc-CVE-2026-0073) | 1 | ADB bypass |
| [CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | [0xbinder/CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | 26 | automated exploit |
| [CVE-2026-0073](https://github.com/owner/repo-with-dash) | [owner/repo-with-dash](https://github.com/owner/repo-with-dash) | 9 | dash |
| [CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | [0xbinder/CVE-2026-0073](https://github.com/0xbinder/CVE-2026-0073) | 26 | duplicate row, must collapse |
| [CVE-2026-9999](https://github.com/other/unrelated) | [other/unrelated](https://github.com/other/unrelated) | 100 | other CVE, must be ignored |
| [CVE-2026-0073](https://gitlab.com/owner/repo) | [owner/repo](https://gitlab.com/owner/repo) | 5 | foreign host, must be ignored |
`
	if err := os.WriteFile(filepath.Join(year, "README.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExtractLinks(dir, "CVE-2026-0073")
	want := []ExtractedPoC{
		{URL: "https://github.com/xqi1337/poc-CVE-2026-0073", Stars: 1},
		{URL: "https://github.com/0xbinder/CVE-2026-0073", Stars: 26},
		{URL: "https://github.com/owner/repo-with-dash", Stars: 9},
	}
	if len(got) != len(want) {
		t.Fatalf("ExtractLinks = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].URL != want[i].URL || got[i].Stars != want[i].Stars {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	if l := ExtractLinks(dir, "CVE-1999-0001"); l != nil {
		t.Errorf("missing CVE: ExtractLinks = %+v, want nil", l)
	}
}

// TestExtractLinksFindsRowInOtherYearFolder verifies the walk fallback:
// when the CVE's own year folder has no README, the row is still found in
// another year's README.
func TestExtractLinksFindsRowInOtherYearFolder(t *testing.T) {
	dir := t.TempDir()
	year := filepath.Join(dir, "2024")
	if err := os.MkdirAll(year, 0o755); err != nil {
		t.Fatal(err)
	}
	md := `| CVE | Target repository | Stars | Description |
|---|---:|---|
| [CVE-2025-1234](https://github.com/owner/misplaced) | [owner/misplaced](https://github.com/owner/misplaced) | 7 | filed under 2024 |
`
	if err := os.WriteFile(filepath.Join(year, "README.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExtractLinks(dir, "CVE-2025-1234")
	want := []ExtractedPoC{{URL: "https://github.com/owner/misplaced", Stars: 7}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ExtractLinks = %+v, want %+v", got, want)
	}
}

// TestExtractLinksMissingTracker verifies the empty outcome for a tracker
// directory without the year README: nil, no panic, no files created.
func TestExtractLinksMissingTracker(t *testing.T) {
	if l := ExtractLinks(t.TempDir(), "CVE-2026-0073"); l != nil {
		t.Errorf("no tracker: ExtractLinks = %+v, want nil", l)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "2026"), 0o755); err != nil {
		t.Fatal(err)
	}
	if l := ExtractLinks(dir, "CVE-2026-0073"); l != nil {
		t.Errorf("no year README: ExtractLinks = %+v, want nil", l)
	}
}

// TestFetchUsesAPIPriorityTableFallback drives the star lookup against a
// fake GitHub API: the API value wins when the request succeeds, and the
// star count from the tracker table is kept — never 0 — when the API
// fails with a 404 or a rate limit.
func TestFetchUsesAPIPriorityTableFallback(t *testing.T) {
	api := map[string]int{
		"owner/hot":  100,
		"owner/dead": 0,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/repos/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		repo := strings.TrimPrefix(r.URL.Path, "/repos/")
		if strings.HasSuffix(repo, "/rate-limited") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		n, ok := api[repo]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"full_name":%q,"stargazers_count":%d}`, repo, n)
	}))
	defer srv.Close()

	f := &Fetcher{BaseURL: srv.URL, Token: "tok", Client: srv.Client()}
	table := []ExtractedPoC{
		{URL: "https://github.com/owner/hot", Stars: 10},         // API 100 wins
		{URL: "https://github.com/owner/dead", Stars: 5},         // API 0 wins
		{URL: "https://github.com/owner/missing", Stars: 42},     // 404 → table 42
		{URL: "https://github.com/owner/rate-limited", Stars: 7}, // 403 → table 7
	}

	got := f.Fetch(table)
	want := []int{100, 0, 42, 7}
	if len(got) != len(want) {
		t.Fatalf("Fetch returned %d refs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Stars != want[i] {
			t.Errorf("stars %d = %d, want %d (url %s)", i, got[i].Stars, want[i], got[i].URL)
		}
	}
}

// TestTopByStarsWithFakeGitHubAPI drives the whole pipeline against a
// fake GitHub API (httptest): six links resolve to stargazer counts, the
// top five by stars are selected, the Bearer token is sent, and an API
// error (404) keeps the link with its table star count instead of 0.
func TestTopByStarsWithFakeGitHubAPI(t *testing.T) {
	stars := map[string]int{
		"owner/a": 10,
		"owner/b": 500,
		"owner/c": 100,
		"owner/d": 250,
		"owner/e": 900,
		"owner/f": 0,
		"owner/g": 50,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/repos/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		repo := strings.TrimPrefix(r.URL.Path, "/repos/")
		n, ok := stars[repo]
		if !ok {
			// API error (rate limit / 404) → table star count is kept.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"full_name":%q,"stargazers_count":%d}`, repo, n)
	}))
	defer srv.Close()

	f := &Fetcher{BaseURL: srv.URL, Token: "tok", Client: srv.Client()}
	table := []ExtractedPoC{
		{URL: "https://github.com/owner/a", Stars: 1},
		{URL: "https://github.com/owner/b", Stars: 1},
		{URL: "https://github.com/owner/c", Stars: 1},
		{URL: "https://github.com/owner/d", Stars: 1},
		{URL: "https://github.com/owner/e", Stars: 1},
		{URL: "https://github.com/owner/f", Stars: 1},
		{URL: "https://github.com/owner/unknown", Stars: 3}, // API 404 → table 3, still listed
	}

	got := TopByStars(f.Fetch(table))
	if len(got) != 5 {
		t.Fatalf("TopByStars returned %d links, want 5: %+v", len(got), got)
	}
	wantOrder := []string{"owner/e", "owner/b", "owner/d", "owner/c", "owner/a"}
	for i, want := range wantOrder {
		if !strings.Contains(got[i].URL, "/"+want) {
			t.Errorf("rank %d = %s, want %s", i, got[i].URL, want)
		}
	}
	if got[0].Stars != 900 || got[1].Stars != 500 {
		t.Errorf("top stars = %d/%d, want 900/500", got[0].Stars, got[1].Stars)
	}

	fetched := f.Fetch([]ExtractedPoC{{URL: "https://github.com/owner/unknown", Stars: 3}})
	if len(fetched) != 1 || fetched[0].Stars != 3 || fetched[0].URL != "https://github.com/owner/unknown" {
		t.Errorf("API-error link = %+v, want kept with table stars 3", fetched)
	}
}
