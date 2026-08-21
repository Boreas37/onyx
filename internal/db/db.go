// Package db loads the local Wordfence Intelligence feed and indexes it
// by software slug for fast lookup during scans.
//
// The feed is a 151MB JSON object keyed by vulnerability UUID. It is
// decoded record-by-record with a streaming decoder so the whole file is
// never held in memory as one giant map.
package db

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/version"
)

// Render-safety caps for feed-sourced strings. The mirror is semi-trusted;
// these bounds keep a corrupted or poisoned feed from producing absurd or
// control-character-laden report lines.
const (
	maxTitleLen       = 300
	maxDescriptionLen = 2000
	maxCVENLen        = 64
	maxLabelLen       = 128
	maxNameLen        = 200
	maxSlugLen        = 200
)

// AffectedVersion is a single affected-version entry for a piece of
// software. Wordfence always includes structured from/to fields; when they
// are absent the human-readable label is parsed instead.
type AffectedVersion struct {
	Label         string
	Ranges        []version.Range
}

type rawAffectedVersion struct {
	FromVersion   string `json:"from_version"`
	FromInclusive *bool  `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   *bool  `json:"to_inclusive"`
}

// Software describes one plugin/theme/core product affected by a
// vulnerability.
type Software struct {
	Type             string                     `json:"type"`
	Name             string                     `json:"name"`
	Slug             string                     `json:"slug"`
	AffectedVersions map[string]AffectedVersion `json:"-"`
	Patched          bool                       `json:"patched"`
	PatchedVersions  []string                   `json:"patched_versions"`
	Remediation      string                     `json:"remediation"`
}

// CVSS holds the CVSS score for a vulnerability.
type CVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

// Vuln is one Wordfence vulnerability record.
type Vuln struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Software    []Software `json:"software"`
	Informational bool     `json:"informational"`
	Description string     `json:"description"`
	CVE         string     `json:"cve"`
	CVSS        CVSS       `json:"cvss"`
	PublishedAt string     `json:"published_at"`
}

// DB is an indexed view of the Wordfence feed.
type DB struct {
	Path    string
	Records []Vuln
	// bySlug indexes non-informational records by software slug.
	bySlug map[string][]*Vuln
	// topSlugs is the list of slugs with the most vulnerable records.
	topSlugs []string
	// skipped counts records that could not be decoded (e.g. unparseable
	// version labels). They are logged but do not abort the load.
	skipped int
}

// Skipped returns the number of records dropped while loading.
func (d *DB) Skipped() int { return d.skipped }

// Count returns the total number of loaded vulnerability records.
func (d *DB) Count() int { return len(d.Records) }

// TopSlugs returns the n slugs with the most vulnerability records.
func (d *DB) TopSlugs(n int) []string {
	if n > len(d.topSlugs) {
		n = len(d.topSlugs)
	}
	return d.topSlugs[:n]
}

// Lookup returns all vulnerable records affecting the given slug.
func (d *DB) Lookup(slug string) []Vuln {
	recs, ok := d.bySlug[slug]
	if !ok {
		return nil
	}
	out := make([]Vuln, 0, len(recs))
	for _, r := range recs {
		out = append(out, *r)
	}
	return out
}

// SlugType returns the dominant software type ("plugin", "theme", "core")
// for a slug, or "" when the slug is unknown.
func (d *DB) SlugType(slug string) string {
	recs := d.bySlug[slug]
	counts := make(map[string]int)
	for _, r := range recs {
		for i := range r.Software {
			if r.Software[i].Slug == slug {
				counts[r.Software[i].Type]++
			}
		}
	}
	for _, t := range []string{"plugin", "theme", "core"} {
		if counts[t] > 0 {
			return t
		}
	}
	return ""
}

// titleVersionRe matches the version hint inside a scanner-feed record
// title, e.g. "Plugin Name < 4.0.1": name, operator and version.
var titleVersionRe = regexp.MustCompile(`(.+) (<|<=|=) ([0-9.]+)`)

// titleSoftware derives a software entry from a minimal scanner-feed
// record whose title embeds the affected version, e.g. "Plugin Name <
// 4.0.1". The slug is the lowercased, hyphenated name. It reports ok=false
// when the title carries no parseable version hint.
func titleSoftware(title string) (Software, bool) {
	m := titleVersionRe.FindStringSubmatch(title)
	if len(m) != 4 {
		return Software{}, false
	}
	name := strings.TrimSpace(m[1])
	label := m[2] + " " + m[3]
	slug := slugify(name)
	if slug == "" {
		return Software{}, false
	}
	ranges, err := version.ParseRanges(label)
	if err != nil {
		return Software{}, false
	}
	av := AffectedVersion{Label: label, Ranges: ranges}
	return Software{
		Type:             "plugin",
		Name:             name,
		Slug:             slug,
		AffectedVersions: map[string]AffectedVersion{label: av},
	}, true
}

// slugify lowercases s and replaces every run of characters outside
// [a-z0-9] with a single hyphen, matching the WordPress slug convention.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// Load opens path and streams the feed, building the slug index and the
// top-slug list.
func Load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := &DB{Path: path, bySlug: make(map[string][]*Vuln)}
	dec := json.NewDecoder(f)
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("reading feed: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("unexpected feed root: %v (want object)", tok)
	}

	// Consume the outer object: {"<uuid>": {...}, ...}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("reading record key: %w", err)
		}
		key, _ := keyTok.(string)

		var raw struct {
			ID          string           `json:"id"`
			Title       string           `json:"title"`
			Software    []json.RawMessage `json:"software"`
			Informational bool           `json:"informational"`
			Description string           `json:"description"`
			CVE         string           `json:"cve"`
			CVSS        CVSS             `json:"cvss"`
			PublishedAt string           `json:"published_at"`
		}
		if err := dec.Decode(&raw); err != nil {
			db.skipped++
			continue
		}
		if raw.ID == "" {
			raw.ID = key
		}
		// Feed data is semi-trusted (mirrored from Wordfence): strip control
		// characters and cap the strings that get rendered into reports so a
		// corrupted or poisoned mirror cannot forge output lines.
		raw.Title = sanitize.Text(raw.Title, maxTitleLen)
		raw.CVE = sanitize.Text(raw.CVE, maxCVENLen)
		rec := Vuln{
			ID:            raw.ID,
			Title:         raw.Title,
			Informational: raw.Informational,
			Description:   sanitize.Text(raw.Description, maxDescriptionLen),
			CVE:           raw.CVE,
			CVSS:          raw.CVSS,
			PublishedAt:   raw.PublishedAt,
		}
		if len(raw.Software) == 0 {
			// Scanner-feed tolerance: minimal records carry only detection
			// info, so the software slug and version range are extracted
			// from the title ("Plugin Name < X.Y.Z"). Records that parse
			// to nothing are dropped.
			if s, ok := titleSoftware(raw.Title); ok {
				rec.Software = []Software{s}
			} else {
				db.skipped++
				continue
			}
		} else {
			for _, sm := range raw.Software {
				s, drop := decodeSoftware(sm)
				if drop {
					db.skipped++
					continue
				}
				rec.Software = append(rec.Software, s)
			}
		}
		db.Records = append(db.Records, rec)

		// Index non-informational records by slug.
		if rec.Informational {
			continue
		}
		for i := range rec.Software {
			s := &rec.Software[i]
			if s.Slug == "" {
				continue
			}
			db.bySlug[s.Slug] = append(db.bySlug[s.Slug], &rec)
		}
	}

	// Build top-slug ordering by number of vulnerable records.
	type slugCount struct {
		slug  string
		count int
	}
	counts := make(map[string]int, len(db.bySlug))
	for slug, recs := range db.bySlug {
		counts[slug] = len(recs)
	}
	ordered := make([]slugCount, 0, len(counts))
	for slug, c := range counts {
		ordered = append(ordered, slugCount{slug, c})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].slug < ordered[j].slug
	})
	db.topSlugs = make([]string, 0, len(ordered))
	for _, sc := range ordered {
		db.topSlugs = append(db.topSlugs, sc.slug)
	}
	return db, nil
}

// decodeSoftware decodes one software entry, normalizing its
// affected_versions into parsed version ranges. It returns drop=true when
// the entry is unusable (e.g. an unparseable version range).
func decodeSoftware(rm json.RawMessage) (Software, bool) {
	var raw struct {
		Type             string                     `json:"type"`
		Name             string                     `json:"name"`
		Slug             string                     `json:"slug"`
		AffectedVersions map[string]rawAffectedVersion `json:"affected_versions"`
		Patched          bool                       `json:"patched"`
		PatchedVersions  []string                   `json:"patched_versions"`
		Remediation      string                     `json:"remediation"`
	}
	if err := json.Unmarshal(rm, &raw); err != nil {
		return Software{}, true
	}
	out := Software{
		Type:            sanitize.Text(raw.Type, 32),
		Name:            sanitize.Text(raw.Name, maxNameLen),
		Slug:            sanitize.Text(raw.Slug, maxSlugLen),
		Patched:         raw.Patched,
		PatchedVersions: raw.PatchedVersions,
		Remediation:     sanitize.Text(raw.Remediation, maxDescriptionLen),
		AffectedVersions: make(map[string]AffectedVersion, len(raw.AffectedVersions)),
	}
	for label, ra := range raw.AffectedVersions {
		label = sanitize.Text(label, maxLabelLen)
		st := ra.FromVersion != "" || ra.ToVersion != ""
		av := AffectedVersion{Label: label}
		if st {
			// Structured fields are authoritative.
			fromIncl, toIncl := true, true
			if ra.FromInclusive != nil {
				fromIncl = *ra.FromInclusive
			}
			if ra.ToInclusive != nil {
				toIncl = *ra.ToInclusive
			}
			rng, ok := structRange(ra.FromVersion, ra.ToVersion, fromIncl, toIncl)
			if !ok {
				// Fall back to parsing the label.
				rs, err := version.ParseRanges(label)
				if err != nil {
					return Software{}, true
				}
				av.Ranges = rs
			} else {
				av.Ranges = []version.Range{rng}
			}
		} else {
			rs, err := version.ParseRanges(label)
			if err != nil {
				return Software{}, true
			}
			av.Ranges = rs
		}
		out.AffectedVersions[label] = av
	}
	return out, false
}

// structRange builds a version.Range from structured feed fields, where "*"
// means unbounded.
func structRange(from, to string, fromIncl, toIncl bool) (version.Range, bool) {
	r := version.Range{FromIncl: fromIncl, ToIncl: toIncl}
	if from != "" && from != "*" {
		v, ok := version.Parse(from)
		if !ok {
			return version.Range{}, false
		}
		r.From = &v
	}
	if to != "" && to != "*" {
		v, ok := version.Parse(to)
		if !ok {
			return version.Range{}, false
		}
		r.To = &v
	}
	return r, true
}
