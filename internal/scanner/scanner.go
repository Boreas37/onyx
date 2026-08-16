package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/version"
)

// ErrNotWordPress is returned when a scan target shows no WordPress signs.
var ErrNotWordPress = errors.New("target does not appear to be a WordPress site")

// maxBodySize caps response bodies (readme.txt / style.css are small).
const maxBodySize = 1 << 20

// defaultTopSlugs is how many vuln-heavy slugs to brute-force enumerate.
const defaultTopSlugs = 200

// Options tunes the scan behaviour. Zero values fall back to defaults.
type Options struct {
	Threads   int           // concurrent HTTP requests (default 5)
	Timeout   time.Duration // per-request timeout (default 10s)
	Stealth   bool          // throttle to 1 request/second
	RateLimit float64       // max requests per second (0 = unlimited)
	APIOnly   bool          // skip brute-force enumeration, only wp-json/plugins
}

// Scanner drives one scan against a single target.
type Scanner struct {
	db     *db.DB
	base   string
	client *http.Client
	opts   Options
	lim    *rateLimiter
}

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func (r *rateLimiter) wait() {
	if r == nil || r.interval <= 0 {
		return
	}
	for {
		r.mu.Lock()
		now := time.Now()
		if wait := r.last.Add(r.interval).Sub(now); wait > 0 {
			r.mu.Unlock()
			time.Sleep(wait)
			continue
		}
		r.last = now
		r.mu.Unlock()
		return
	}
}

// NewScanner builds a Scanner for base, using the given database and
// options.
func NewScanner(database *db.DB, base string, opts Options) (*Scanner, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL %q", base)
	}
	if opts.Threads <= 0 {
		opts.Threads = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        opts.Threads * 2,
			MaxIdleConnsPerHost: opts.Threads,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	s := &Scanner{
		db:     database,
		base:   strings.TrimRight(base, "/"),
		client: client,
		opts:   opts,
	}
	if opts.Stealth {
		s.lim = &rateLimiter{interval: time.Second}
	}
	if opts.RateLimit > 0 {
		s.lim = &rateLimiter{interval: time.Duration(float64(time.Second) / opts.RateLimit)}
	}
	return s, nil
}

// Detected is a plugin/theme/core component whose presence and version were
// identified on the target.
type Detected struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"installed_version"`
}

// Vulnerability is one matched database record.
type Vulnerability struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	CVE            string   `json:"cve"`
	CVSSScore      float64  `json:"cvss_score"`
	Rating         string   `json:"cvss_rating"`
	Description    string   `json:"description"`
	AffectedLabels []string `json:"affected_versions"`
	PublishedAt    string   `json:"published_at"`
}

// Finding links an installed component to its matching vulnerabilities.
type Finding struct {
	Slug             string          `json:"slug"`
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	InstalledVersion string          `json:"installed_version"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
}

// Result is the output of a scan.
type Result struct {
	Target           string      `json:"target"`
	IsWordPress      bool        `json:"is_wordpress"`
	WordPressVersion string      `json:"wordpress_version,omitempty"`
	Evidence         []string    `json:"evidence,omitempty"`
	Detected         []Detected  `json:"detected,omitempty"`
	Findings         []Finding   `json:"findings,omitempty"`
	Errors           []string    `json:"errors,omitempty"`
}

func (s *Scanner) fetch(path string) (int, []byte, error) {
	s.lim.wait()
	resp, err := s.client.Get(s.base + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return resp.StatusCode, body, err
}

// detectWP checks the homepage, wp-login.php and the REST API root for
// WordPress fingerprints. It returns the detected core version (if any) and
// the list of evidence strings.
func (s *Scanner) detectWP() (coreVersion string, evidence []string) {
	code, body, err := s.fetch("/")
	if err != nil {
		return "", []string{"homepage fetch failed: " + err.Error()}
	}
	if code == 200 {
		html := string(body)
		if v, ok := ExtractWordPressVersion(html); ok {
			coreVersion = v
			evidence = append(evidence, "generator meta tag (WordPress "+v+")")
		}
		if strings.Contains(html, "wp-content") {
			evidence = append(evidence, "wp-content path present in homepage")
		}
		if strings.Contains(html, "wp-json") || strings.Contains(html, "/wp-json/") {
			evidence = append(evidence, "wp-json REST API referenced")
		}
	}

	if code, body, err := s.fetch("/wp-login.php"); err == nil && code == 200 {
		if strings.Contains(string(body), "user_login") {
			evidence = append(evidence, "wp-login.php reachable")
		}
	}

	if code, body, err := s.fetch("/wp-json/"); err == nil && (code == 200 || code == 403) {
		if len(body) > 0 && (body[0] == '{' || body[0] == '[') {
			evidence = append(evidence, "wp-json REST API root responded")
		}
	}
	return coreVersion, evidence
}

// apiPlugins queries the authenticated plugin listing endpoint. Unauthenticated
// servers return 401/403; that is expected and swallowed.
func (s *Scanner) apiPlugins() ([]Detected, []string) {
	var out []Detected
	var errs []string
	code, body, err := s.fetch("/wp-json/wp/v2/plugins")
	if err != nil {
		errs = append(errs, "wp-json/wp/v2/plugins: "+err.Error())
		return nil, errs
	}
	if code == 401 || code == 403 {
		errs = append(errs, "wp-json/wp/v2/plugins requires authentication (skipped)")
		return nil, errs
	}
	if code != 200 {
		return nil, errs
	}
	var items []struct {
		Plugin  string `json:"plugin"`
		Version string `json:"version"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(body, &items); err != nil || len(items) == 0 {
		errs = append(errs, "wp-json/wp/v2/plugins returned no usable plugin list")
		return nil, errs
	}
	for _, it := range items {
		slug := it.Plugin
		if i := strings.IndexByte(slug, '/'); i >= 0 {
			slug = slug[:i]
		}
		if slug == "" {
			continue
		}
		ver := it.Version
		if ver == "" {
			ver = "unknown"
		}
		out = append(out, Detected{Slug: slug, Name: it.Name, Type: "plugin", Version: ver})
	}
	return out, nil
}

// job is one brute-force enumeration request.
type job struct {
	kind string // "plugin" | "theme"
	slug string
	path string
}

func (s *Scanner) buildJobs() []job {
	var jobs []job
	for _, slug := range s.db.TopSlugs(defaultTopSlugs) {
		switch s.db.SlugType(slug) {
		case "plugin":
			jobs = append(jobs, job{kind: "plugin", slug: slug,
				path: "/wp-content/plugins/" + slug + "/readme.txt"})
		case "theme":
			jobs = append(jobs, job{kind: "theme", slug: slug,
				path: "/wp-content/themes/" + slug + "/style.css"})
		}
	}
	return jobs
}

// matchDatabase compares an installed version against every database record
// for slug and returns the matching finding. Non-numeric ("unknown")
// versions never match: no range matching is performed, preventing false
// positives.
func (s *Scanner) matchDatabase(slug, typ, rawVersion string) Finding {
	f := Finding{Slug: slug, Name: slug, Type: typ, InstalledVersion: rawVersion}
	v, ok := version.Parse(rawVersion)
	if !ok {
		return f
	}
	recs := s.db.Lookup(slug)
	seen := make(map[string]bool, len(recs))
	for _, rec := range recs {
		for si := range rec.Software {
			sw := &rec.Software[si]
			if sw.Slug != slug {
				continue
			}
			for label, av := range sw.AffectedVersions {
				if !version.InRanges(av.Ranges, v) {
					continue
				}
				if seen[rec.ID] {
					continue
				}
				seen[rec.ID] = true
				f.Vulnerabilities = append(f.Vulnerabilities, Vulnerability{
					ID:          rec.ID,
					Title:       rec.Title,
					CVE:         rec.CVE,
					CVSSScore:   rec.CVSS.Score,
					Rating:      rec.CVSS.Rating,
					Description: rec.Description,
					PublishedAt: rec.PublishedAt,
					AffectedLabels: []string{label},
				})
				break
			}
		}
	}
	return f
}

// scanJob performs one enumeration request, fingerprinting the installed
// version and matching it against the database.
func (s *Scanner) scanJob(j job) ([]Detected, []Finding) {
	code, body, err := s.fetch(j.path)
	if err != nil {
		return nil, nil
	}
	if code != http.StatusOK {
		return nil, nil
	}

	var ver string
	var found bool
	switch j.kind {
	case "plugin":
		ver, found = ExtractVersionFromReadme(string(body))
	case "theme":
		ver, found = ExtractVersionFromStyleCSS(string(body))
	}
	detected := []Detected{{Slug: j.slug, Name: j.slug, Type: j.kind, Version: "unknown"}}
	if !found {
		return detected, nil
	}
	detected[0].Version = ver
	f := s.matchDatabase(j.slug, j.kind, ver)
	if len(f.Vulnerabilities) > 0 {
		return detected, []Finding{f}
	}
	return detected, nil
}

// Scan runs the full workflow: WordPress detection, enumeration and matching.
func (s *Scanner) Scan() (*Result, error) {
	res := &Result{Target: s.base}

	coreVersion, evidence := s.detectWP()
	res.Evidence = evidence
	res.IsWordPress = coreVersion != "" || len(evidence) > 0
	if !res.IsWordPress {
		res.Errors = append(res.Errors, ErrNotWordPress.Error())
		return res, ErrNotWordPress
	}
	res.WordPressVersion = coreVersion

	var mu sync.Mutex
	addDetected := func(list []Detected) {
		if len(list) == 0 {
			return
		}
		mu.Lock()
		res.Detected = append(res.Detected, list...)
		mu.Unlock()
	}
	addFindings := func(list []Finding) {
		if len(list) == 0 {
			return
		}
		mu.Lock()
		res.Findings = append(res.Findings, list...)
		mu.Unlock()
	}

	// REST API plugin listing is always attempted.
	apiDetected, apiErrs := s.apiPlugins()
	addDetected(apiDetected)
	res.Errors = append(res.Errors, apiErrs...)

	if !s.opts.APIOnly {
		jobs := s.buildJobs()
		sem := make(chan struct{}, s.opts.Threads)
		var wg sync.WaitGroup
		for _, j := range jobs {
			j := j
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				detected, findings := s.scanJob(j)
				addDetected(detected)
				addFindings(findings)
			}()
		}
		wg.Wait()
	}

	// Deduplicate detected components, keeping the first (version-known) entry.
	bySlug := make(map[string]Detected, len(res.Detected))
	for _, d := range res.Detected {
		if prev, ok := bySlug[d.Slug]; ok {
			if prev.Version != "unknown" || d.Version == "unknown" {
				continue
			}
		}
		bySlug[d.Slug] = d
	}
	res.Detected = res.Detected[:0]
	for _, d := range bySlug {
		res.Detected = append(res.Detected, d)
	}
	sort.Slice(res.Detected, func(i, j int) bool { return res.Detected[i].Slug < res.Detected[j].Slug })
	sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].Slug < res.Findings[j].Slug })

	return res, nil
}