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

// ExtractedPoC is one PoC repository row for a CVE as read from the
// tracker's year README table: the target repository URL and the star
// count from the Stars column.
type ExtractedPoC struct {
	URL   string
	Stars int
}

var (
	// repoRe matches GitHub repository URLs (owner/repo) inside markdown.
	repoRe = regexp.MustCompile(`https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`)
	// cveRe matches a CVE id inside a markdown link cell.
	cveRe = regexp.MustCompile(`CVE-\d{4}-\d+`)
	// yearDirRe matches year folder names (1999-2999) in the tracker.
	yearDirRe = regexp.MustCompile(`^[12][0-9]{3}$`)
)

// cveYear extracts the 4-digit year of a CVE id, or "" when the id does
// not carry a usable year. The lower bound stays at 1999 (the first year
// CVEs were issued); the ceiling floats one year ahead of the wall clock
// so tracker folders for the upcoming year resolve before New Year.
func cveYear(cve string) string {
	if len(cve) < 9 || !strings.HasPrefix(cve, "CVE-") {
		return ""
	}
	y := cve[4:8]
	n, err := strconv.Atoi(y)
	if err != nil || n < 1999 || n > time.Now().Year()+1 {
		return ""
	}
	return y
}

// cvePath resolves the tracker markdown file for cve under dir. The
// tracker layout is <year>/README.md with one markdown table per year;
// when the year is unusable or that README is missing, any
// <year>/README.md under dir is searched for the CVE's row instead.
func cvePath(dir, cve string) (string, bool) {
	if y := cveYear(cve); y != "" {
		p := filepath.Join(dir, y, "README.md")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	found := ""
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "README.md" {
			return nil
		}
		if !yearDirRe.MatchString(filepath.Base(filepath.Dir(path))) {
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

// cveFromRow returns the CVE id in the first cell of a markdown table
// row, or "" when the line is not a tracker row (header, separator,
// prose). Rows look like `| CVE-2026-0073 | [name](url) | 1 | desc |`.
func cveFromRow(line string) string {
	if !strings.HasPrefix(line, "|") {
		return ""
	}
	cells := strings.Split(line, "|")
	if len(cells) < 3 {
		return ""
	}
	return cveRe.FindString(cells[1])
}

// starsFromRow returns the Stars column value of a markdown table row,
// or 0 when the column is missing or not a number.
func starsFromRow(line string) int {
	cells := strings.Split(line, "|")
	if len(cells) < 4 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(cells[3]))
	if err != nil {
		return 0
	}
	return n
}

// ExtractLinks returns the GitHub repository URL and the table star count
// of every row mentioning cve in the tracker README (see cvePath). Only
// rows of the queried CVE are matched; the first GitHub link of a row is
// kept and duplicates collapse. It returns nil when the CVE is not in the
// tracker (silently skipped by callers).
func ExtractLinks(dir, cve string) []ExtractedPoC {
	path, ok := cvePath(dir, cve)
	if !ok {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var refs []ExtractedPoC
	for _, line := range strings.Split(string(data), "\n") {
		got := cveFromRow(line)
		if got == "" || !strings.EqualFold(got, cve) {
			continue
		}
		urls := repoRe.FindAllString(line, -1)
		if len(urls) == 0 || seen[urls[0]] {
			continue
		}
		seen[urls[0]] = true
		refs = append(refs, ExtractedPoC{URL: urls[0], Stars: starsFromRow(line)})
	}
	return refs
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

// Fetch resolves the stargazer count of every PoC via
// GET /repos/{owner}/{repo}. A failed request (rate limit, 404, network
// error) keeps the star count from the tracker table instead of dropping
// it — PoC references are never dropped because the star count is stale.
func (f *Fetcher) Fetch(pocs []ExtractedPoC) []PoCLink {
	refs := make([]PoCLink, 0, len(pocs))
	for _, p := range pocs {
		refs = append(refs, PoCLink{URL: p.URL, Stars: f.stars(p.URL, p.Stars)})
	}
	return refs
}

// stars resolves the current stargazer count of link; fallback (the star
// count from the tracker table) is returned when the API is unreachable,
// rate-limited or the repo does not exist.
func (f *Fetcher) stars(link string, fallback int) int {
	repo := repoPath(link)
	if repo == "" {
		return fallback
	}
	u := strings.TrimSuffix(f.BaseURL, "/") + "/repos/" + repo
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return fallback
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "onyx")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	var repoInfo struct {
		Stars int `json:"stargazers_count"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&repoInfo); err != nil {
		return fallback
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
