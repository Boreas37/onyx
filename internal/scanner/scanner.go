package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/progress"
	"github.com/Boreas37/onyx/internal/version"
)

// ErrNotWordPress is returned when a scan target shows no WordPress signs.
var ErrNotWordPress = errors.New("target does not appear to be a WordPress site")

// maxBodySize caps response bodies (readme.txt / style.css are small).
const maxBodySize = 1 << 20

// defaultTopSlugs is how many vuln-heavy slugs to brute-force enumerate.
const defaultTopSlugs = 200

// defaultMaxRequests caps the brute-force enumeration request budget.
const defaultMaxRequests = 500

// maxAuthorChecks is how many /?author=N redirects to follow at most.
const maxAuthorChecks = 10

// authorSlugRe matches the author archive path the /?author=N redirect
// chain lands on.
var authorSlugRe = regexp.MustCompile(`^/author/([^/]+)`)

// Options tunes the scan behaviour. Zero values fall back to defaults.
type Options struct {
	Threads     int           // concurrent HTTP requests (default 5)
	Timeout     time.Duration // per-request timeout (default 10s)
	Stealth     bool          // throttle to 1 request/second
	RateLimit   float64       // max requests per second (0 = unlimited)
	APIOnly     bool          // skip brute-force enumeration, only wp-json/plugins
	MaxRequests int           // cap on brute-force enumeration requests (default 500)
	Enumerate   string        // what to enumerate: u/p/t, combinable (default "pt")
}

// Scanner drives one scan against a single target.
type Scanner struct {
	db          *db.DB
	base        string
	client      *http.Client
	opts        Options
	lim         *rateLimiter
	enum        string
	maxRequests int
	progress    *progress.Bar
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
	enum := strings.ToLower(strings.TrimSpace(opts.Enumerate))
	if enum == "" {
		enum = "pt"
	}
	for _, c := range enum {
		if c != 'p' && c != 't' && c != 'u' {
			return nil, fmt.Errorf("invalid --enumerate value %q (use p, t and/or u)", opts.Enumerate)
		}
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = defaultMaxRequests
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
		db:          database,
		base:        strings.TrimRight(base, "/"),
		client:      client,
		opts:        opts,
		enum:        enum,
		maxRequests: opts.MaxRequests,
	}
	if opts.Stealth {
		s.lim = &rateLimiter{interval: time.Second}
	}
	if opts.RateLimit > 0 {
		s.lim = &rateLimiter{interval: time.Duration(float64(time.Second) / opts.RateLimit)}
	}
	return s, nil
}

// SetProgress attaches a progress bar to the scanner. A nil bar disables
// progress reporting entirely.
func (s *Scanner) SetProgress(b *progress.Bar) {
	s.progress = b
}

// Progress returns the attached progress bar, or nil.
func (s *Scanner) Progress() *progress.Bar {
	return s.progress
}

// enumeratePlugins reports whether plugins should be enumerated.
func (s *Scanner) enumeratePlugins() bool { return strings.Contains(s.enum, "p") }

// enumerateThemes reports whether themes should be enumerated.
func (s *Scanner) enumerateThemes() bool { return strings.Contains(s.enum, "t") }

// enumerateUsers reports whether users should be enumerated.
func (s *Scanner) enumerateUsers() bool { return strings.Contains(s.enum, "u") }

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

// User is a WordPress user account discovered during enumeration. ID is the
// numeric user id (when known), Slug is the author-archive slug, Name is the
// display name (only the REST API provides it).
type User struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// Result is the output of a scan.
type Result struct {
	Target           string     `json:"target"`
	IsWordPress      bool       `json:"is_wordpress"`
	WordPressVersion string     `json:"wordpress_version,omitempty"`
	Evidence         []string   `json:"evidence,omitempty"`
	Detected         []Detected `json:"detected,omitempty"`
	Findings         []Finding  `json:"findings,omitempty"`
	Users            []User     `json:"users,omitempty"`
	Errors           []string   `json:"errors,omitempty"`
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

// fetchNoRedirect GETs path without following redirects so the raw 30x
// Location header from the author-enumeration redirect chain can be read.
func (s *Scanner) fetchNoRedirect(path string) (int, http.Header, []byte, error) {
	s.lim.wait()
	client := *s.client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(s.base + path)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return resp.StatusCode, resp.Header, body, err
}

// usersFromAPI reads the (usually open) /wp-json/wp/v2/users listing and
// extracts id/slug/name for each account.
func (s *Scanner) usersFromAPI() ([]User, []string) {
	var errs []string
	code, body, err := s.fetch("/wp-json/wp/v2/users")
	if err != nil {
		errs = append(errs, "wp-json/wp/v2/users: "+err.Error())
		return nil, errs
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		errs = append(errs, "wp-json/wp/v2/users requires authentication (skipped)")
		return nil, errs
	}
	if code != http.StatusOK {
		return nil, errs
	}
	var items []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		errs = append(errs, "wp-json/wp/v2/users returned unparseable data")
		return nil, errs
	}
	var out []User
	for _, it := range items {
		if it.Slug == "" {
			continue
		}
		out = append(out, User{ID: it.ID, Slug: it.Slug, Name: it.Name})
	}
	return out, nil
}

// usersFromAuthors walks /?author=1..N following the redirect chain and
// extracting the username from /author/<slug>/ landing pages.
func (s *Scanner) usersFromAuthors(maxN int) ([]User, []string) {
	var out []User
	var errs []string
	for n := 1; n <= maxN; n++ {
		loc, err := s.authorLocation(n)
		if err != nil {
			errs = append(errs, fmt.Sprintf("?author=%d: %v", n, err))
			continue
		}
		if slug := authorSlugFromLocation(loc); slug != "" {
			out = append(out, User{ID: n, Slug: slug})
		}
	}
	return out, nil
}

// authorLocation returns the Location header of the /?author=N redirect.
func (s *Scanner) authorLocation(n int) (string, error) {
	code, hdr, _, err := s.fetchNoRedirect(fmt.Sprintf("/?author=%d", n))
	if err != nil {
		return "", err
	}
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return hdr.Get("Location"), nil
	}
	return "", nil
}

// authorSlugFromLocation extracts the username from any /author/<slug>/
// path in a redirect Location value. Site-relative Locations without a
// leading slash are tolerated.
func authorSlugFromLocation(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if m := authorSlugRe.FindStringSubmatch(u.Path); m != nil {
		return m[1]
	}
	if m := authorSlugRe.FindStringSubmatch("/" + strings.TrimLeft(u.Path, "/")); m != nil {
		return m[1]
	}
	return ""
}

// normalizeUsers merges user lists from the REST API and author redirects,
// de-duplicating by slug and filling missing fields, sorted by slug.
func normalizeUsers(lists ...[]User) []User {
	bySlug := make(map[string]User)
	var order []string
	for _, list := range lists {
		for _, u := range list {
			if u.Slug == "" {
				continue
			}
			prev, ok := bySlug[u.Slug]
			if !ok {
				order = append(order, u.Slug)
				bySlug[u.Slug] = u
				continue
			}
			if prev.Name == "" && u.Name != "" {
				prev.Name = u.Name
			}
			if prev.ID == 0 {
				prev.ID = u.ID
			}
			bySlug[u.Slug] = prev
		}
	}
	out := make([]User, 0, len(order))
	for _, slug := range order {
		out = append(out, bySlug[slug])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
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

// label describes the job for progress output, e.g. "plugin:elementor
// readme.txt". When version is non-empty it is appended in parentheses.
func (j job) label(version string) string {
	where := "readme.txt"
	switch j.kind {
	case "theme":
		where = "style.css"
	case "plugin":
		where = "readme.txt"
	}
	l := j.kind + ":" + j.slug + " " + where
	if version != "" {
		l += " (" + version + ")"
	}
	return l
}

func (s *Scanner) buildJobs() []job {
	var jobs []job
	for _, slug := range s.db.TopSlugs(defaultTopSlugs) {
		switch s.db.SlugType(slug) {
		case "plugin":
			if !s.enumeratePlugins() {
				continue
			}
			jobs = append(jobs, job{kind: "plugin", slug: slug,
				path: "/wp-content/plugins/" + slug + "/readme.txt"})
		case "theme":
			if !s.enumerateThemes() {
				continue
			}
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
					ID:             rec.ID,
					Title:          rec.Title,
					CVE:            rec.CVE,
					CVSSScore:      rec.CVSS.Score,
					Rating:         rec.CVSS.Rating,
					Description:    rec.Description,
					PublishedAt:    rec.PublishedAt,
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
	pr := s.progress
	if pr != nil {
		defer pr.Finish()
	}

	coreVersion, evidence := s.detectWP()
	res.Evidence = evidence
	res.IsWordPress = coreVersion != "" || len(evidence) > 0
	if !res.IsWordPress {
		res.Errors = append(res.Errors, ErrNotWordPress.Error())
		if pr != nil {
			pr.LogInf("target %s does not appear to be WordPress", s.base)
		}
		return res, ErrNotWordPress
	}
	res.WordPressVersion = coreVersion
	if pr != nil {
		ver := ""
		if coreVersion != "" {
			ver = " " + coreVersion
		}
		pr.LogInf("detected WordPress%s at %s", ver, s.base)
	}

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
		n := int64(len(res.Findings))
		mu.Unlock()
		if pr != nil {
			pr.SetFindings(n)
		}
	}

	// REST API plugin listing is always attempted when plugins are enabled.
	if s.enumeratePlugins() {
		apiDetected, apiErrs := s.apiPlugins()
		addDetected(apiDetected)
		res.Errors = append(res.Errors, apiErrs...)
	}

	jobs := s.buildJobs()
	if s.opts.APIOnly {
		jobs = nil
	}
	// --max-requests caps the brute-force request budget. Jobs keep their
	// share first; whatever is left funds user enumeration.
	if len(jobs) > s.maxRequests {
		jobs = jobs[:s.maxRequests]
	}
	remaining := s.maxRequests - len(jobs)

	userPlan := 0
	authorPlan := 0
	if s.enumerateUsers() && remaining > 0 {
		userPlan = 1 // wp-json/wp/v2/users
		rem := remaining - 1
		if !s.opts.APIOnly && rem > 0 {
			authorPlan = rem
			if authorPlan > maxAuthorChecks {
				authorPlan = maxAuthorChecks
			}
			userPlan += authorPlan
		}
	}

	if pr != nil {
		if len(jobs) > 0 {
			plugins, themes := countKinds(jobs)
			pr.LogInf("enumerating %d plugin(s) and %d theme(s)", plugins, themes)
		}
		if userPlan > 0 {
			pr.LogInf("enumerating users (REST API + up to %d author id(s))", authorPlan)
		}
		pr.SetTotal(int64(len(jobs) + userPlan))
	}

	if len(jobs) > 0 {
		sem := make(chan struct{}, s.opts.Threads)
		var wg sync.WaitGroup
		for _, j := range jobs {
			j := j
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if pr != nil {
					pr.SetCurrent(j.label(""))
				}
				detected, findings := s.scanJob(j)
				addDetected(detected)
				addFindings(findings)
				if pr != nil {
					ver := ""
					if len(detected) == 1 && detected[0].Version != "unknown" {
						ver = detected[0].Version
					}
					pr.SetCurrent(j.label(ver))
					pr.AddDone(1)
				}
			}()
		}
		wg.Wait()
	}

	if userPlan > 0 {
		if pr != nil {
			pr.SetCurrent("user:wp-json/users")
		}
		apiUsers, userErrs := s.usersFromAPI()
		res.Errors = append(res.Errors, userErrs...)
		if pr != nil {
			pr.AddDone(1)
		}
		var authorUsers []User
		if authorPlan > 0 {
			if pr != nil {
				pr.SetCurrent(fmt.Sprintf("user:author=1..%d", authorPlan))
			}
			authorUsers, userErrs = s.usersFromAuthors(authorPlan)
			res.Errors = append(res.Errors, userErrs...)
			if pr != nil {
				pr.AddDone(int64(authorPlan))
			}
		}
		res.Users = normalizeUsers(apiUsers, authorUsers)
		if pr != nil && len(res.Users) > 0 {
			pr.LogInf("found %d user(s)", len(res.Users))
		}
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

// countKinds tallies job kinds for progress logging.
func countKinds(jobs []job) (plugins, themes int) {
	for _, j := range jobs {
		switch j.kind {
		case "plugin":
			plugins++
		case "theme":
			themes++
		}
	}
	return
}
