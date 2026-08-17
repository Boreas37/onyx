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

// TestExtractLinksFromTrackerMarkdown verifies that GitHub repository URLs
// are pulled out of a fake CVE markdown file in a fake tracker clone:
// duplicates collapse, foreign hosts are ignored, and a missing CVE file
// yields nothing.
func TestExtractLinksFromTrackerMarkdown(t *testing.T) {
	dir := t.TempDir()
	year := filepath.Join(dir, "2026")
	if err := os.MkdirAll(year, 0o755); err != nil {
		t.Fatal(err)
	}
	md := `# CVE-2026-8081

## PoCs
- https://github.com/owner/repo1
- [repo2](https://github.com/owner/repo2)
- https://github.com/owner/repo1 (duplicate, must collapse)
- https://github.com/owner/repo-with-dash/tree/main/exploit
- https://gitlab.com/owner/repo (foreign host, must be ignored)
`
	if err := os.WriteFile(filepath.Join(year, "CVE-2026-8081.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExtractLinks(dir, "CVE-2026-8081")
	want := []string{
		"https://github.com/owner/repo1",
		"https://github.com/owner/repo2",
		"https://github.com/owner/repo-with-dash",
	}
	if len(got) != len(want) {
		t.Fatalf("ExtractLinks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %q, want %q", i, got[i], want[i])
		}
	}

	if l := ExtractLinks(dir, "CVE-1999-0001"); l != nil {
		t.Errorf("missing CVE file: ExtractLinks = %v, want nil", l)
	}
}

// TestTopByStarsWithFakeGitHubAPI drives the star lookup against a fake
// GitHub API (httptest): six links resolve to stargazer counts, the top
// five by stars are selected, the Bearer token is sent, and an API error
// (404) keeps the link with stars 0 instead of dropping it.
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
			// API error (rate limit / 404) → caller keeps the link, stars 0.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"full_name":%q,"stargazers_count":%d}`, repo, n)
	}))
	defer srv.Close()

	f := &Fetcher{BaseURL: srv.URL, Token: "tok", Client: srv.Client()}
	links := []string{
		"https://github.com/owner/a",
		"https://github.com/owner/b",
		"https://github.com/owner/c",
		"https://github.com/owner/d",
		"https://github.com/owner/e",
		"https://github.com/owner/f",
		"https://github.com/owner/unknown", // API error → stars 0, still listed
	}

	got := TopByStars(f.Fetch(links))
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

	fetched := f.Fetch([]string{"https://github.com/owner/unknown"})
	if len(fetched) != 1 || fetched[0].Stars != 0 || fetched[0].URL != "https://github.com/owner/unknown" {
		t.Errorf("API-error link = %+v, want kept with stars 0", fetched)
	}
}
