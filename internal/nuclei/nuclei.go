// Package nuclei verifies scan findings with projectdiscovery/nuclei:
// it locates the matching template file for a CVE and runs the nuclei
// binary to confirm the vulnerability against the target.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// runTimeout caps a single nuclei invocation (templates may take a long
// time against hostile or slow targets). Each template batch gets a fresh
// budget, so one hostile template cannot consume the whole verification
// window and discard every result.
const runTimeout = 60 * time.Second

// templatesPerBatch caps how many templates a single nuclei invocation
// carries. Templates are executed in batches of this size, each with its
// own runTimeout.
const templatesPerBatch = 10

// ErrBinaryNotFound is returned by Run when no usable nuclei binary can be
// resolved (neither $NUCLEI_BIN nor `nuclei` on PATH). The pipeline treats
// it as a soft failure and skips verification.
var ErrBinaryNotFound = errors.New("nuclei binary not found")

// NucleiResult is one verified match emitted by nuclei (JSON Lines).
type NucleiResult struct {
	TemplateID  string `json:"template_id"`
	CVE         string `json:"cve,omitempty"`
	MatchedAt   string `json:"matched_at"`
	Severity    string `json:"severity"`
	Name        string `json:"name"`
	MatcherName string `json:"matcher_name,omitempty"`
}

// jsonLine mirrors the nuclei -json -silent output for one match.
type jsonLine struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Matcher    string `json:"matcher-name"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification *struct {
			CVEID string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
}

// FindTemplate resolves the evidence template for cve under dir:
// first <dir>/http/cves/<year>/<cve>.yaml (year = the CVE's 4-digit year,
// when it is within 2002..time.Now().Year()+1), then a recursive search
// below <dir>/http/cves/ for any file named <cve>.yaml.
func FindTemplate(dir, cve string) (string, bool) {
	if y := cveYear(cve); y != "" {
		p := filepath.Join(dir, "http", "cves", y, cve+".yaml")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	found := ""
	root := filepath.Join(dir, "http", "cves")
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != cve+".yaml" {
			return nil
		}
		found = path
		return fs.SkipAll
	})
	if found != "" {
		return found, true
	}
	return "", false
}

// cveYear extracts the 4-digit year of a CVE id, or "" when the id does
// not carry a usable year. The lower bound stays at 2002 (nuclei's template
// tree starts there); the ceiling floats one year ahead of the wall clock
// so templates published for the upcoming year resolve before New Year.
func cveYear(cve string) string {
	if len(cve) < 9 || !strings.HasPrefix(cve, "CVE-") {
		return ""
	}
	y := cve[4:8]
	n, err := strconv.Atoi(y)
	if err != nil || n < 2002 || n > time.Now().Year()+1 {
		return ""
	}
	return y
}

// NucleiBinary resolves the nuclei binary: $NUCLEI_BIN when set, otherwise
// `nuclei` looked up on PATH.
func NucleiBinary() (string, error) {
	if bin := os.Getenv("NUCLEI_BIN"); bin != "" {
		if fi, err := os.Stat(bin); err == nil && !fi.IsDir() {
			return bin, nil
		}
		return "", ErrBinaryNotFound
	}
	p, err := exec.LookPath("nuclei")
	if err != nil {
		return "", ErrBinaryNotFound
	}
	return p, nil
}

// Run executes
//
//	nuclei -target <target> -t <t1> -t <t2> ... -json -silent [extra args...]
//
// once per batch of templatesPerBatch templates, and parses the JSON Lines
// stdout into stable NucleiResults, merged in template order.
//
// Error semantics: a failing batch (timeout, non-zero exit) is recorded and
// the next batch still runs. The call returns nil error whenever at least
// one batch produced results or no batch failed — partial coverage is
// better than nothing, so the caller can show whatever matched and only
// loses the batches that never ran. An error is returned only when every
// batch failed (the first batch error is surfaced). ErrBinaryNotFound is
// returned unchanged when no nuclei binary can be resolved.
func Run(target string, templates []string, extraArgs []string) ([]NucleiResult, error) {
	bin, err := NucleiBinary()
	if err != nil {
		return nil, err
	}

	var results []NucleiResult
	var firstErr error
	batches, failed := 0, 0
	for start := 0; start < len(templates); start += templatesPerBatch {
		end := start + templatesPerBatch
		if end > len(templates) {
			end = len(templates)
		}
		batches++
		rs, err := runBatch(bin, target, templates[start:end], extraArgs)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("batch %d: %w", batches, err)
			}
			continue
		}
		results = append(results, rs...)
	}

	// Every batch failed: nothing to report, surface the first batch error
	// so the caller knows verification did not run at all. Empty template
	// lists run no batch and succeed vacuously.
	if batches > 0 && failed == batches {
		return nil, firstErr
	}
	// At least one batch succeeded (or none failed): return the merged
	// matches. Batches that failed are skipped; partial coverage beats
	// dropping everything because one hostile template blew its budget.
	return results, nil
}

// runBatch executes one nuclei invocation for a single template batch with
// a fresh runTimeout and parses the JSON Lines stdout into NucleiResults.
func runBatch(bin, target string, batch []string, extraArgs []string) ([]NucleiResult, error) {
	args := []string{"-target", target}
	for _, t := range batch {
		args = append(args, "-t", t)
	}
	args = append(args, "-json", "-silent")
	args = append(args, extraArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting nuclei: %w", err)
	}

	var results []NucleiResult
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if r, err := ParseLine(line); err == nil {
			results = append(results, r)
		}
	}
	err = cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("nuclei timed out after %s", runTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("nuclei failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return results, nil
}

// ParseLine decodes one JSON Lines match into a NucleiResult. The CVE
// field is filled from info.classification.cve-id when present, falling
// back to the template-id itself when it looks like a CVE id.
func ParseLine(line string) (NucleiResult, error) {
	var raw jsonLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return NucleiResult{}, err
	}
	r := NucleiResult{
		TemplateID:  raw.TemplateID,
		MatchedAt:   raw.MatchedAt,
		Severity:    raw.Info.Severity,
		Name:        raw.Info.Name,
		MatcherName: raw.Matcher,
	}
	if raw.Info.Classification != nil && raw.Info.Classification.CVEID != "" {
		r.CVE = raw.Info.Classification.CVEID
	} else if cveYear(raw.TemplateID) != "" {
		r.CVE = raw.TemplateID
	}
	return r, nil
}
