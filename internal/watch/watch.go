// Package watch implements recurring-scan diffing ("watch mode"): it stores
// the set of vulnerabilities observed on a target during the last scan and
// compares later scans against that baseline, reporting new and resolved
// vulnerabilities. State persists as JSON on disk and changes can be pushed
// to a webhook.
package watch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/scanner"
)

// Field length caps applied to target-controlled strings before they are
// stored or rendered.
const (
	maxSlugLen   = 200
	maxTitleLen  = 300
	maxCVELen    = 64
	maxRatingLen = 32
)

// cveLess marks the slug-level presence of a vulnerability that carries no
// CVE id, so such slugs still participate in diffing.
const cveLess = "-"

// ErrNoState is returned by LoadState when no previous state file exists
// (first run for a target).
var ErrNoState = errors.New("no previous watch state")

// State is the persisted result of one scan: which vulnerabilities (by CVE
// id, keyed per component slug) were considered present at scan time.
type State struct {
	Target    string                     `json:"target"`
	ScannedAt time.Time                  `json:"scanned_at"`
	Baseline  map[string]map[string]bool `json:"baseline"`
}

// Change is one vulnerability-level difference between two scans.
type Change struct {
	Slug   string `json:"slug"`
	Type   string `json:"type"`
	CVE    string `json:"cve"`
	Title  string `json:"title"`
	Rating string `json:"rating"`
}

// Diff is the outcome of comparing a scan against a previous state.
type Diff struct {
	Target    string    `json:"target"`
	ScannedAt time.Time `json:"scanned_at"`
	New       []Change  `json:"new"`      // vulnerabilities present now, absent in baseline
	Resolved  []Change  `json:"resolved"` // in baseline, absent now
	Unchanged int       `json:"unchanged"`
}

// LoadState reads a previously saved state file. When the file does not
// exist it returns an error wrapping ErrNoState.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNoState, path)
		}
		return nil, fmt.Errorf("watch: read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("watch: parse state %s: %w", path, err)
	}
	return &st, nil
}

// BuildState derives the baseline for target from a scan result: a map of
// component slug to the set of CVE ids considered vulnerable. Vulnerabilities
// without a CVE id are tracked under the "-" key so their slug-level presence
// still diffs correctly.
func BuildState(target string, res *scanner.Result, now time.Time) *State {
	st := &State{
		Target:    target,
		ScannedAt: now.UTC(),
		Baseline:  make(map[string]map[string]bool),
	}
	if res == nil {
		return st
	}
	for _, f := range res.Findings {
		slug := sanitize.Text(f.Slug, maxSlugLen)
		if slug == "" {
			continue
		}
		set, ok := st.Baseline[slug]
		if !ok {
			set = make(map[string]bool)
			st.Baseline[slug] = set
		}
		for _, v := range f.Vulnerabilities {
			cve := sanitize.Text(v.CVE, maxCVELen)
			if cve == "" {
				cve = cveLess
			}
			set[cve] = true
		}
	}
	return st
}

// DiffStates compares res against the previous state prev and reports which
// vulnerabilities are new, which resolved, and how many are unchanged. A nil
// prev behaves like an empty baseline (everything reported as new).
func DiffStates(prev *State, res *scanner.Result, now time.Time) *Diff {
	d := &Diff{ScannedAt: now.UTC()}
	if prev != nil {
		d.Target = prev.Target
	}
	current := make(map[string]map[string]bool)
	if res != nil {
		if res.Target != "" {
			d.Target = res.Target
		}
		for _, f := range res.Findings {
			slug := sanitize.Text(f.Slug, maxSlugLen)
			typ := sanitize.Text(f.Type, maxSlugLen)
			if slug == "" {
				continue
			}
			set, ok := current[slug]
			if !ok {
				set = make(map[string]bool)
				current[slug] = set
			}
			for _, v := range f.Vulnerabilities {
				cve := sanitize.Text(v.CVE, maxCVELen)
				if cve == "" {
					cve = cveLess
				}
				set[cve] = true
				was := false
				if prev != nil {
					was = prev.Baseline[slug][cve]
				}
				if was {
					d.Unchanged++
					continue
				}
				d.New = append(d.New, Change{
					Slug:   slug,
					Type:   typ,
					CVE:    cve,
					Title:  sanitize.Text(v.Title, maxTitleLen),
					Rating: sanitize.Text(v.Rating, maxRatingLen),
				})
			}
		}
	}
	if prev != nil {
		for slug, cves := range prev.Baseline {
			for cve := range cves {
				if current[slug][cve] {
					continue
				}
				d.Resolved = append(d.Resolved, Change{Slug: slug, CVE: cve})
			}
		}
	}
	sort.Slice(d.Resolved, func(i, j int) bool {
		if d.Resolved[i].Slug != d.Resolved[j].Slug {
			return d.Resolved[i].Slug < d.Resolved[j].Slug
		}
		return d.Resolved[i].CVE < d.Resolved[j].CVE
	})
	return d
}

// DiffToJSON returns the compact JSON encoding of d for JSONL output. A nil
// diff encodes as the empty object so callers can always print the result.
func DiffToJSON(d *Diff) ([]byte, error) {
	if d == nil {
		return []byte("{}"), nil
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("watch: encode diff: %w", err)
	}
	return data, nil
}

// SaveState atomically writes st to path: the parent directory is created if
// needed, the JSON is written to a temporary file in the same directory and
// renamed over path, so readers never observe a partial state file. The
// state directory is 0700 and the file is 0600 so vulnerability data is not
// world-readable on multi-user hosts (mirroring the HTTP cache permissions).
func SaveState(path string, st *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("watch: create state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("watch: encode state: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("watch: create temp state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("watch: write temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("watch: write temp state: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("watch: chmod temp state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("watch: replace state: %w", err)
	}
	return nil
}

// Empty reports whether the diff contains any new or resolved
// vulnerabilities.
func (d *Diff) Empty() bool {
	return d == nil || (len(d.New) == 0 && len(d.Resolved) == 0)
}

// Summary renders the diff as a single line, e.g. "3 new, 1 resolved,
// 12 unchanged".
func (d *Diff) Summary() string {
	if d == nil {
		return "0 new, 0 resolved, 0 unchanged"
	}
	return fmt.Sprintf("%d new, %d resolved, %d unchanged", len(d.New), len(d.Resolved), d.Unchanged)
}

// PrintDiff renders d in human-readable form to stdout: a summary line
// followed by "New vulnerabilities:" and "Resolved:" sections when non-empty.
// Severity ratings are plain text.
func PrintDiff(d *Diff) {
	if d == nil {
		return
	}
	fmt.Printf("Watch diff for %s (scanned %s): %s\n",
		d.Target, d.ScannedAt.UTC().Format(time.RFC3339), d.Summary())
	if len(d.New) > 0 {
		fmt.Println("New vulnerabilities:")
		for _, c := range d.New {
			fmt.Printf("  [%s] %s/%s %s: %s\n", c.Rating, c.Type, c.Slug, c.CVE, c.Title)
		}
	}
	if len(d.Resolved) > 0 {
		fmt.Println("Resolved:")
		for _, c := range d.Resolved {
			fmt.Printf("  [%s] %s/%s %s\n", c.Rating, c.Type, c.Slug, c.CVE)
		}
	}
}

// notifyPayload is the JSON body posted to the webhook.
type notifyPayload struct {
	Target    string    `json:"target"`
	ScannedAt time.Time `json:"scanned_at"`
	Summary   string    `json:"summary"`
	New       []Change  `json:"new"`
	Resolved  []Change  `json:"resolved"`
}

// notifyFormatSlack selects the Slack webhook payload shape in Notify. Any
// other format value (including the empty default) posts the generic JSON
// payload.
const notifyFormatSlack = "slack"

// renderSlackText renders d as a compact multi-line summary suitable for a
// Slack webhook message body: a header line, then "- " prefixed lines for
// each new and resolved vulnerability.
func renderSlackText(d *Diff) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Watch diff for %s (scanned %s): %s\n",
		d.Target, d.ScannedAt.UTC().Format(time.RFC3339), d.Summary())
	if len(d.New) > 0 {
		b.WriteString("New vulnerabilities:\n")
		for _, c := range d.New {
			fmt.Fprintf(&b, "- [%s] %s/%s %s: %s\n", c.Rating, c.Type, c.Slug, c.CVE, c.Title)
		}
	}
	if len(d.Resolved) > 0 {
		b.WriteString("Resolved:\n")
		for _, c := range d.Resolved {
			fmt.Fprintf(&b, "- [%s] %s/%s %s\n", c.Rating, c.Type, c.Slug, c.CVE)
		}
	}
	return b.String()
}

// Notify posts d to webhookURL. format selects the payload shape:
// "slack" wraps the rendered summary as a Slack webhook message
// ({"text": ...}) posted to the same URL; any other value (including the
// empty default) posts the generic JSON payload. A nil client falls back
// to an http.Client with a 15s timeout. A non-2xx response is an error
// carrying the status.
func Notify(webhookURL string, d *Diff, format string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var body []byte
	var err error
	if format == notifyFormatSlack {
		body, err = json.Marshal(struct {
			Text string `json:"text"`
		}{Text: renderSlackText(d)})
	} else {
		body, err = json.Marshal(notifyPayload{
			Target:    d.Target,
			ScannedAt: d.ScannedAt,
			Summary:   d.Summary(),
			New:       d.New,
			Resolved:  d.Resolved,
		})
	}
	if err != nil {
		return fmt.Errorf("watch: encode webhook payload: %w", err)
	}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("watch: webhook post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("watch: webhook returned status %s", resp.Status)
	}
	return nil
}
