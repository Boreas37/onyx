// Package intel enriches scan findings with third-party threat
// intelligence: EPSS exploitation-probability scores and CISA KEV (Known
// Exploited Vulnerabilities) membership. Feeds are downloaded once, parsed
// into in-memory maps and cached on disk with a TTL, so a fresh cache makes
// repeated scans work fully offline.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/scanner"
)

// Feed source URLs and cache lifetimes. Exported so callers and tests can
// reference them without drift.
const (
	EpssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	KevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	EpssTTL = 24 * time.Hour
	KevTTL  = 12 * time.Hour
)

const (
	// maxEntries caps each parsed feed so a hostile or corrupted download
	// cannot exhaust memory building unbounded maps.
	maxEntries = 500_000
	// maxLineLen bounds one CSV line while parsing; longer lines are
	// treated as hostile input and abort the scan of that feed.
	maxLineLen = 1 << 20
	// maxBodyBytes bounds a downloaded feed body.
	maxBodyBytes = 64 << 20
	// maxCVELen bounds normalized CVE keys.
	maxCVELen = 64
)

// Intel holds the parsed EPSS scores and KEV membership, keyed by
// uppercase-normalized CVE id. Build one with Load.
type Intel struct {
	epss   map[string]float64
	kev    map[string]bool
	loaded bool
}

// epssCache is the on-disk cache format for EPSS scores.
type epssCache struct {
	FetchedAt int64              `json:"fetched_at"`
	Scores    map[string]float64 `json:"scores"`
}

// kevCache is the on-disk cache format for KEV membership.
type kevCache struct {
	FetchedAt int64    `json:"fetched_at"`
	CVEs      []string `json:"cves"`
}

// Load returns threat intelligence built from the EPSS and KEV feeds,
// using and maintaining a JSON cache under cacheDir. now is injected for
// testability; client may be nil for a default 60s-timeout client.
//
// Per feed: a fresh cache (younger than its TTL) is used without any
// network traffic; otherwise the feed is downloaded and re-cached. A failed
// or unparsable download falls back to stale cache if one exists, adding a
// message to the returned warnings; when neither download nor cache yields
// data, Load fails with an error.
func Load(cacheDir string, client *http.Client, now time.Time) (*Intel, []string, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	in := &Intel{
		epss:   make(map[string]float64),
		kev:    make(map[string]bool),
		loaded: true,
	}
	var warnings []string

	scores, err := refreshEpss(cacheDir, client, now, &warnings)
	if err != nil {
		return nil, warnings, err
	}
	in.epss = scores

	cves, err := refreshKev(cacheDir, client, now, &warnings)
	if err != nil {
		return nil, warnings, err
	}
	for _, cve := range cves {
		in.kev[cve] = true
	}
	return in, warnings, nil
}

// refreshEpss resolves the current EPSS score map via cache-then-network.
func refreshEpss(cacheDir string, client *http.Client, now time.Time, warnings *[]string) (map[string]float64, error) {
	path := filepath.Join(cacheDir, "epss.json")
	var cached epssCache
	fresh := readCache(path, EpssTTL, now, &cached)
	if fresh {
		return cached.Scores, nil
	}

	body, err := fetch(client, EpssURL)
	if err == nil {
		parsed, perr := parseEPSS(body)
		if perr == nil {
			cached.Scores = parsed
			if werr := writeCache(path, epssCache{FetchedAt: now.Unix(), Scores: cached.Scores}); werr != nil {
				warn(warnings, "epss: caching failed: %v", werr)
			}
			return cached.Scores, nil
		}
		err = fmt.Errorf("parsing feed: %w", perr)
	}
	if len(cached.Scores) > 0 {
		warn(warnings, "epss: %v; using stale cache", err)
		return cached.Scores, nil
	}
	return nil, fmt.Errorf("intel: epss: %w", err)
}

// refreshKev resolves the current KEV CVE list via cache-then-network.
func refreshKev(cacheDir string, client *http.Client, now time.Time, warnings *[]string) ([]string, error) {
	path := filepath.Join(cacheDir, "kev.json")
	var cached kevCache
	fresh := readCache(path, KevTTL, now, &cached)
	if fresh {
		return cached.CVEs, nil
	}

	body, err := fetch(client, KevURL)
	if err == nil {
		parsed, perr := parseKEV(body)
		if perr == nil {
			cached.CVEs = parsed
			if werr := writeCache(path, kevCache{FetchedAt: now.Unix(), CVEs: cached.CVEs}); werr != nil {
				warn(warnings, "kev: caching failed: %v", werr)
			}
			return cached.CVEs, nil
		}
		err = fmt.Errorf("parsing feed: %w", perr)
	}
	if len(cached.CVEs) > 0 {
		warn(warnings, "kev: %v; using stale cache", err)
		return cached.CVEs, nil
	}
	return nil, fmt.Errorf("intel: kev: %w", err)
}

// readCache unmarshals path into v and reports whether the payload is
// present and younger than ttl. Missing or corrupt files count as absent;
// stale payloads are still decoded into v for fallback use.
func readCache(path string, ttl time.Duration, now time.Time, v any) bool {
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, v) != nil {
		return false
	}
	type stamped struct {
		FetchedAt int64 `json:"fetched_at"`
	}
	var st stamped
	if json.Unmarshal(data, &st) != nil || st.FetchedAt <= 0 {
		return false
	}
	ft := time.Unix(st.FetchedAt, 0)
	return now.Sub(ft) >= 0 && now.Sub(ft) < ttl
}

// writeCache stores v as compact JSON under path, creating cacheDir as
// needed.
func writeCache(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// fetch GETs url and returns the body, capped at maxBodyBytes.
func fetch(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// warn appends a formatted, non-fatal message to warnings.
func warn(warnings *[]string, format string, args ...any) {
	*warnings = append(*warnings, fmt.Sprintf(format, args...))
}

// normalizeCVE uppercases and sanitizes a CVE id for use as a map key.
func normalizeCVE(cve string) string {
	return strings.ToUpper(sanitize.Text(strings.TrimSpace(cve), maxCVELen))
}

// parseEPSS decodes the gzipped Cyentia EPSS CSV: comment lines start with
// '#', followed by a "cve,epss,..." header, then one row per CVE. Malformed
// rows are skipped; parsing only fails when no usable rows exist.
func parseEPSS(body []byte) (map[string]float64, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	scores := make(map[string]float64)
	sc := bufioScanner(gz)
	headerSeen := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 2 {
			continue
		}
		cve := normalizeCVE(cols[0])
		if !headerSeen {
			// The first non-comment line is the header row.
			headerSeen = true
			continue
		}
		if !strings.HasPrefix(cve, "CVE-") || len(scores) >= maxEntries {
			continue
		}
		score, perr := strconv.ParseFloat(strings.TrimSpace(cols[1]), 64)
		if perr != nil || score < 0 || score > 1 {
			continue
		}
		scores[cve] = score
	}
	if !headerSeen || len(scores) == 0 {
		return nil, fmt.Errorf("no usable EPSS rows")
	}
	return scores, nil
}

// kevFeed mirrors the CISA known_exploited_vulnerabilities.json shape.
type kevFeed struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// parseKEV decodes the CISA KEV JSON feed into a deduplicated,
// uppercase-normalized CVE list.
func parseKEV(body []byte) ([]string, error) {
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(feed.Vulnerabilities))
	out := make([]string, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cve := normalizeCVE(v.CveID)
		if !strings.HasPrefix(cve, "CVE-") || seen[cve] || len(out) >= maxEntries {
			continue
		}
		seen[cve] = true
		out = append(out, cve)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no vulnerabilities in KEV feed")
	}
	return out, nil
}

// bufioScanner returns a scanner tolerant of long lines up to maxLineLen;
// anything longer aborts iteration instead of panicking or growing forever.
func bufioScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineLen)
	return sc
}

// EPSS returns the exploitation-probability score (0..1) for cve and
// whether the CVE is present in the loaded feed.
func (i *Intel) EPSS(cve string) (float64, bool) {
	if i == nil {
		return 0, false
	}
	s, ok := i.epss[normalizeCVE(cve)]
	return s, ok
}

// KEV reports whether cve is listed in the CISA Known Exploited
// Vulnerabilities catalog.
func (i *Intel) KEV(cve string) bool {
	if i == nil {
		return false
	}
	return i.kev[normalizeCVE(cve)]
}

// rankKey is the sort key shared by findings and individual
// vulnerabilities: KEV entries first, then higher EPSS, then higher CVSS,
// with tie as the final alphabetical tiebreaker.
type rankKey struct {
	kev  bool
	epss float64
	cvss float64
	tie  string
}

// rankOf reduces a vulnerability to its sort key.
func rankOf(v *scanner.Vulnerability) rankKey {
	return rankKey{kev: v.Kev, epss: v.Epss, cvss: v.CVSSScore, tie: v.CVE + "\x00" + v.ID}
}

// rankOfFinding aggregates a finding's vulnerabilities into one sort key:
// KEV if any entry is listed, worst (highest) EPSS and CVSS overall.
func rankOfFinding(f *scanner.Finding) rankKey {
	k := rankKey{tie: f.Slug}
	for i := range f.Vulnerabilities {
		v := &f.Vulnerabilities[i]
		k.kev = k.kev || v.Kev
		if v.Epss > k.epss {
			k.epss = v.Epss
		}
		if v.CVSSScore > k.cvss {
			k.cvss = v.CVSSScore
		}
	}
	return k
}

// lessRank orders two sort keys according to the enrichment priority.
func lessRank(a, b rankKey) bool {
	switch {
	case a.kev != b.kev:
		return a.kev
	case a.epss != b.epss:
		return a.epss > b.epss
	case a.cvss != b.cvss:
		return a.cvss > b.cvss
	default:
		return a.tie < b.tie
	}
}

// Enrich stamps every vulnerability in findings with EPSS scores and KEV
// membership from in (a nil Intel leaves the fields untouched), then sorts
// findings — and the vulnerabilities within each finding — by KEV first,
// higher EPSS, higher CVSS, and finally slug/CVE alphabetically.
func Enrich(findings []scanner.Finding, in *Intel) {
	for i := range findings {
		f := &findings[i]
		for j := range f.Vulnerabilities {
			v := &f.Vulnerabilities[j]
			if in == nil {
				continue
			}
			if s, ok := in.EPSS(v.CVE); ok {
				v.Epss = s
			}
			v.Kev = in.KEV(v.CVE)
		}
		sort.SliceStable(f.Vulnerabilities, func(a, b int) bool {
			return lessRank(rankOf(&f.Vulnerabilities[a]), rankOf(&f.Vulnerabilities[b]))
		})
	}
	sort.SliceStable(findings, func(a, b int) bool {
		return lessRank(rankOfFinding(&findings[a]), rankOfFinding(&findings[b]))
	})
}
