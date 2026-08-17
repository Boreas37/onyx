// Package pocs finds Proof-of-Concept repositories for a CVE in a local
// clone of Boreas37/CVE-PoC-Tracker and selects the most-starred ones via
// the GitHub REST API. All failures are soft: a missing tracker clone or
// an unknown star count never aborts the scan.
package pocs

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TrackerURL is the canonical URL of the CVE-PoC-Tracker repository,
// appended to every PoC reference output section.
const TrackerURL = "https://github.com/Boreas37/CVE-PoC-Tracker"

// topN caps the number of PoC links reported per CVE.
const topN = 5

// PoCLink is one PoC repository reference for a CVE.
type PoCLink struct {
	URL   string `json:"url"`
	Stars int    `json:"stars"`
	CVE   string `json:"cve"`
}

// repoRe matches GitHub repository URLs (owner/repo) inside markdown.
var repoRe = regexp.MustCompile(`https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`)

// cveYear extracts the 4-digit year of a CVE id (2002-2026), or "" when
// the id does not carry a usable year.
func cveYear(cve string) string {
	if len(cve) < 9 || !strings.HasPrefix(cve, "CVE-") {
		return ""
	}
	y := cve[4:8]
	n, err := strconv.Atoi(y)
	if err != nil || n < 2002 || n > 2026 {
		return ""
	}
	return y
}

// cvePath resolves the tracker markdown file for cve under dir. The
// tracker layout is <year>/<cve>.md; when the year is unusable the whole
// dir is searched for any file named <cve>.md.
func cvePath(dir, cve string) (string, bool) {
	if y := cveYear(cve); y != "" {
		p := filepath.Join(dir, y, cve+".md")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	found := ""
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != cve+".md" {
			return nil
		}
		found = path
		return filepath.SkipAll
	})
	if found != "" {
		return found, true
	}
	return "", false
}

// ExtractLinks returns the unique GitHub repository URLs mentioned in the
// tracker markdown file for cve under dir. It returns nil when the CVE
// file does not exist in the tracker (silently skipped by callers).
func ExtractLinks(dir, cve string) []string {
	path, ok := cvePath(dir, cve)
	if !ok {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var links []string
	for _, m := range repoRe.FindAllString(string(data), -1) {
		if !seen[m] {
			seen[m] = true
			links = append(links, m)
		}
	}
	return links
}

// Fetcher resolves stargazer counts through the GitHub REST API. BaseURL
// and Token are overridable for tests.
type Fetcher struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewFetcher returns a Fetcher against the live GitHub API. When token
// (from $GITHUB_TOKEN) is non-empty it is sent as a Bearer credential.
func NewFetcher(token string) *Fetcher {
	return &Fetcher{
		BaseURL: "https://api.github.com",
		Token:   token,
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// repoPath returns the "owner/repo" path of a GitHub repository URL, or
// "" when the URL is not a GitHub repository.
func repoPath(u string) string {
	p, err := url.Parse(u)
	if err != nil || !strings.EqualFold(p.Host, "github.com") {
		return ""
	}
	segs := strings.Split(strings.Trim(p.Path, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	return segs[0] + "/" + segs[1]
}

// Fetch resolves the stargazer count of every link via
// GET /repos/{owner}/{repo}. A failed request (rate limit, 404, network
// error) keeps the link with Stars 0 — PoC references are never dropped
// because the star count is unknown.
func (f *Fetcher) Fetch(links []string) []PoCLink {
	refs := make([]PoCLink, 0, len(links))
	for _, link := range links {
		refs = append(refs, PoCLink{URL: link, Stars: f.stars(link)})
	}
	return refs
}

func (f *Fetcher) stars(link string) int {
	repo := repoPath(link)
	if repo == "" {
		return 0
	}
	u := strings.TrimSuffix(f.BaseURL, "/") + "/repos/" + repo
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "onyx")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	var repoInfo struct {
		Stars int `json:"stargazers_count"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&repoInfo); err != nil {
		return 0
	}
	return repoInfo.Stars
}

// TopByStars sorts refs by stargazer count descending (URL as a stable
// tiebreak) and keeps at most the top 5. It sorts the slice in place.
func TopByStars(refs []PoCLink) []PoCLink {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Stars != refs[j].Stars {
			return refs[i].Stars > refs[j].Stars
		}
		return refs[i].URL < refs[j].URL
	})
	if len(refs) > topN {
		return refs[:topN]
	}
	return refs
}
