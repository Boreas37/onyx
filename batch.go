// RM6 additive batch scanning. Everything in this file is additive: a
// single-target scan still goes through runScan in main.go untouched, and
// runMulti keeps its historical single-target path and exit-code aggregation.
// When runMulti is handed more than one target it calls runBatch, which loads
// the vulnerability database and the PoC tracker index ONCE for the whole
// batch, scans hosts with a bounded worker pool, and renders either compact
// per-host progress (default) or the legacy per-target section headers under
// --verbose.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/intel"
	"github.com/Boreas37/onyx/internal/pocs"
	"github.com/Boreas37/onyx/internal/report"
	"github.com/Boreas37/onyx/internal/scanner"
)

// hostLabel returns the host[:port] of a target URL for compact per-host
// output, falling back to the raw string when it cannot be parsed.
func hostLabel(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

// countSeverities tallies a finding list by rating: critical, high, medium,
// low and the total number of vulnerabilities.
func countSeverities(findings []scanner.Finding) (critical, high, medium, low, total int) {
	for i := range findings {
		for _, v := range findings[i].Vulnerabilities {
			total++
			switch strings.ToLower(v.Rating) {
			case "critical":
				critical++
			case "high":
				high++
			case "medium":
				medium++
			case "low":
				low++
			}
		}
	}
	return
}

// batchResult is one host's outcome inside a batch run.
type batchResult struct {
	target string
	host   string
	ok     bool
	errMsg string
	res    *scanner.Result
	code   int
	dur    time.Duration
}

// batchTargetDoc is the pinned JSON shape of one host in the aggregate doc.
type batchTargetDoc struct {
	Target   string            `json:"target"`
	Ok       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Findings []scanner.Finding `json:"findings"`
	Stats    *scanner.Summary  `json:"stats,omitempty"`
}

// batchSummary is the pinned aggregate summary shape.
type batchSummary struct {
	Targets            int            `json:"targets"`
	Ok                 int            `json:"ok"`
	Failed             int            `json:"failed"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	DurationS          float64        `json:"duration_s"`
}

// batchDoc is the pinned `--format json` batch document.
type batchDoc struct {
	Targets []batchTargetDoc `json:"targets"`
	Summary batchSummary     `json:"summary"`
}

// batchJSONLFinding is one JSON Lines record in batch mode: the regular
// finding object plus the target it belongs to.
type batchJSONLFinding struct {
	Target string `json:"target"`
	scanner.Finding
}

// loadBatchDatabase resolves the vulnerability database exactly once for the
// whole batch (the single-target runScan loads it per invocation). It mirrors
// runScan's missing-database handling and returns a non-nil exit code only on
// failure.
func loadBatchDatabase(o scanOptions) (*db.DB, int) {
	if _, err := os.Stat(o.dbPath); err != nil {
		if o.noUpdate {
			fmt.Fprintf(os.Stderr, "error: database not found at %s (--no-update given — run 'onyx update' first)\n", o.dbPath)
			return nil, 2
		}
		fmt.Fprintf(os.Stderr, "database not found at %s — fetching it first...\n", o.dbPath)
		if err := update(o.dbPath, feedProduction, false); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			return nil, 2
		}
	}
	database, err := db.LoadCached(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return nil, 2
	}
	return database, 0
}

// loadBatchIntel loads the EPSS/KEV intelligence once for the whole batch, so
// enrichment does not re-read or re-download the feeds per host. All failure
// modes are soft: a nil *Intel disables enrichment without failing the batch.
func loadBatchIntel(o scanOptions) *intel.Intel {
	if o.noIntel {
		return nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	cacheDir := filepath.Join(base, "onyx", "intel")
	in, warns, err := intel.Load(cacheDir, http.DefaultClient, time.Now())
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "[WARN] intel: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] intel unavailable (%v) — findings are not EPSS/KEV-annotated\n", err)
		return nil
	}
	return in
}

// scanHostOnce scans a single target as part of a batch, without printing the
// per-target report (the batch renderer owns stdout). A hard failure yields
// ok=false with a reason; a reachable target — WordPress or not — yields
// ok=true and its result. Exit codes come from the same scanExitCode used by
// single-target scans, so runMulti's aggregation is preserved.
func scanHostOnce(ctx context.Context, database *db.DB, target string, o scanOptions, pocIdx *batchPocIndex, in *intel.Intel) batchResult {
	start := time.Now()
	r := batchResult{target: target, host: hostLabel(target)}

	sc, err := scanner.NewScanner(database, target, scannerOptionsForRun(o, nil, ctx))
	if err != nil {
		r.errMsg = err.Error()
		r.code = 2
		r.dur = time.Since(start)
		return r
	}
	res, serr := sc.Scan()
	r.dur = time.Since(start)
	if res == nil {
		if serr != nil {
			r.errMsg = serr.Error()
		} else {
			r.errMsg = "scan failed"
		}
		r.code = 2
		return r
	}

	// EPSS/KEV enrichment (shared intelligence), then --nuclei verification
	// and PoC enrichment — same order as the single-target runScan.
	if in != nil && len(res.Findings) > 0 {
		intel.Enrich(res.Findings, in)
	}
	if o.nuclei {
		verifyWithNuclei(res, o)
		if !o.noPocs {
			pocIdx.collect(res, o)
		}
	}

	r.res = res
	r.ok = true
	r.code = scanExitCode(res, serr, o.strictWP, o.failOn, o.failOnRateLimited)
	return r
}

// runHostPool scans targets with at most jobs workers. Dispatch stops when ctx
// is cancelled (Ctrl-C) while in-flight hosts finish normally. Results are
// indexed by target position; undispatched entries (empty target) are dropped
// and the survivors are returned in target order.
func runHostPool(ctx context.Context, targets []string, jobs int, bp *batchProgress, scan func(i int) batchResult) []batchResult {
	results := make([]batchResult, len(targets))
	if jobs < 1 {
		jobs = 1
	}
	work := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				r := scan(i)
				mu.Lock()
				results[i] = r
				done++
				n := done
				mu.Unlock()
				if bp != nil {
					bp.hostDone(n, r)
				}
			}
		}()
	}

dispatch:
	for i := range targets {
		select {
		case <-ctx.Done():
			break dispatch
		case work <- i:
		}
	}
	close(work)
	wg.Wait()

	out := make([]batchResult, 0, len(results))
	for _, r := range results {
		if r.target != "" {
			out = append(out, r)
		}
	}
	return out
}

// runBatch is the entry point for a multi-target scan. rank is runMulti's
// existing exit-code rank function; the per-host codes are aggregated with it
// so the exit-code contract is unchanged.
func runBatch(targets []string, o scanOptions, rank func(int) int) int {
	start := time.Now()

	database, code := loadBatchDatabase(o)
	if database == nil {
		return code
	}
	if !o.noUpdateCheck {
		if days := dbAgeDays(o.dbPath); days > 14 {
			fmt.Fprintf(os.Stderr, "[WARN] database is %d days old (%s feed) — run 'onyx update' for fresh data\n", days, dbFeedType(o.dbPath))
		}
	}

	in := loadBatchIntel(o)
	pocIdx := newBatchPocIndex(o)

	ctx, cancel := scanSignalContext()
	defer cancel()

	// --verbose restores the legacy per-target section headers and suppresses
	// the compact live output; --silent suppresses both.
	bp := newBatchProgress(os.Stderr, o.silent || o.verbose, len(targets), start)

	results := runHostPool(ctx, targets, o.jobs, bp, func(i int) batchResult {
		return scanHostOnce(ctx, database, targets[i], o, pocIdx, in)
	})
	bp.finish()

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "[WARN] batch interrupted — results may be incomplete")
	}

	worst := 0
	for _, r := range results {
		if rank(r.code) > rank(worst) {
			worst = r.code
		}
	}

	writeBatchOutput(results, o, start)
	if o.verbose {
		printVerboseBatch(results, o)
	}
	return worst
}

// buildBatchDoc aggregates per-host results into the pinned batch document.
func buildBatchDoc(results []batchResult, start time.Time) batchDoc {
	doc := batchDoc{
		Targets: make([]batchTargetDoc, 0, len(results)),
		Summary: batchSummary{FindingsBySeverity: map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0,
		}},
	}
	for _, r := range results {
		var findings []scanner.Finding
		var stats *scanner.Summary
		if r.res != nil {
			findings = r.res.Findings
			stats = r.res.Summary
		}
		if findings == nil {
			findings = []scanner.Finding{}
		}
		doc.Targets = append(doc.Targets, batchTargetDoc{
			Target:   r.target,
			Ok:       r.ok,
			Error:    r.errMsg,
			Findings: findings,
			Stats:    stats,
		})
		if r.ok {
			doc.Summary.Ok++
		} else {
			doc.Summary.Failed++
		}
		c, h, m, l, _ := countSeverities(findings)
		doc.Summary.FindingsBySeverity["critical"] += c
		doc.Summary.FindingsBySeverity["high"] += h
		doc.Summary.FindingsBySeverity["medium"] += m
		doc.Summary.FindingsBySeverity["low"] += l
	}
	doc.Summary.Targets = len(results)
	doc.Summary.DurationS = math.Round(time.Since(start).Seconds()*10) / 10
	return doc
}

// writeBatchOutput renders the aggregate result. It writes to --output-dir
// first, then the selected --format to stdout, then --output FILE.
func writeBatchOutput(results []batchResult, o scanOptions, start time.Time) {
	doc := buildBatchDoc(results, start)

	if o.outputDir != "" {
		if err := writeBatchDir(o.outputDir, results, doc.Summary); err != nil {
			fmt.Fprintln(os.Stderr, "error writing output dir:", err)
		}
	}

	switch o.format {
	case "json":
		printBatchJSON(doc)
	case "sarif":
		report.WriteMultiSARIF(os.Stdout, onyxVersion, batchSARIFResults(results))
	case "jsonl":
		printBatchJSONL(results)
	case "csv":
		if err := writeBatchCSV(os.Stdout, results); err != nil {
			fmt.Fprintln(os.Stderr, "csv output:", err)
		}
	default: // table, cli-no-colour
		printBatchTable(doc)
	}

	if o.output != "" {
		if err := writeBatchOutputFile(o.output, o.format, doc, results); err != nil {
			fmt.Fprintln(os.Stderr, "error writing output:", err)
		}
	}
	if len(o.outputs) > 0 {
		fmt.Fprintln(os.Stderr, "[WARN] --outputs is not supported in multi-target mode — ignoring")
	}
}

func printBatchJSON(doc batchDoc) {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json output:", err)
		return
	}
	fmt.Println(string(b))
}

// batchSARIFResults maps per-host outcomes onto scanner results; a failed host
// contributes an empty run so the SARIF run count still equals the host count.
func batchSARIFResults(results []batchResult) []*scanner.Result {
	out := make([]*scanner.Result, 0, len(results))
	for _, r := range results {
		if r.res != nil {
			out = append(out, r.res)
		} else {
			out = append(out, &scanner.Result{Target: r.target})
		}
	}
	return out
}

// printBatchJSONL emits one JSON object per finding, each tagged with its
// target, in target order (deterministic across runs).
func printBatchJSONL(results []batchResult) {
	enc := json.NewEncoder(os.Stdout)
	for _, r := range results {
		for i := range r.res.Findings {
			_ = enc.Encode(batchJSONLFinding{Target: r.target, Finding: r.res.Findings[i]})
		}
	}
}

// batchCSVHeader mirrors report's single-target columns with the target
// prepended.
var batchCSVHeader = []string{
	"target", "slug", "type", "installed_version", "cve", "severity", "title", "affected_versions",
}

// writeBatchCSV writes one row per vulnerability across all hosts, with the
// target as the first column. Values are passed through encoding/csv (which
// quotes) and formula-neutralised to match report.WriteCSV's hardening.
func writeBatchCSV(w io.Writer, results []batchResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(batchCSVHeader); err != nil {
		return err
	}
	for _, r := range results {
		for i := range r.res.Findings {
			f := &r.res.Findings[i]
			for _, v := range f.Vulnerabilities {
				if err := cw.Write([]string{
					batchCSVSafe(r.target),
					batchCSVSafe(f.Slug),
					f.Type,
					batchCSVSafe(f.InstalledVersion),
					batchCSVSafe(v.CVE),
					batchCSVSafe(strings.ToLower(v.Rating)),
					batchCSVSafe(v.Title),
					batchCSVSafe(strings.Join(v.AffectedLabels, "; ")),
				}); err != nil {
					return err
				}
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// batchCSVSafe neutralises spreadsheet formula injection by prefixing values
// that begin with a formula trigger with a single quote.
func batchCSVSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// printBatchTable renders the end-of-batch human summary (table formats).
func printBatchTable(doc batchDoc) {
	s := doc.Summary
	fmt.Println("Batch summary:")
	fmt.Printf("  %-12s %d (%d ok, %d failed)\n", "Targets:", s.Targets, s.Ok, s.Failed)

	sev := s.FindingsBySeverity
	total := sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
	fmt.Printf("  %-12s %d (critical %d, high %d, medium %d, low %d)\n",
		"Findings:", total, sev["critical"], sev["high"], sev["medium"], sev["low"])
	fmt.Printf("  %-12s %.1fs\n", "Duration:", s.DurationS)

	// Worst hosts by critical then total vulnerability count.
	type worst struct {
		host     string
		critical int
		total    int
	}
	var hosts []worst
	for _, t := range doc.Targets {
		if !t.Ok {
			continue
		}
		c, _, _, _, tot := countSeverities(t.Findings)
		if tot == 0 {
			continue
		}
		hosts = append(hosts, worst{host: hostLabel(t.Target), critical: c, total: tot})
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].critical != hosts[j].critical {
			return hosts[i].critical > hosts[j].critical
		}
		return hosts[i].total > hosts[j].total
	})
	if len(hosts) > 5 {
		hosts = hosts[:5]
	}
	if len(hosts) > 0 {
		fmt.Println("  Worst hosts:")
		for i, h := range hosts {
			fmt.Printf("    %d. %s  critical %d  total %d\n", i+1, h.host, h.critical, h.total)
		}
	}
}

// printVerboseBatch restores the legacy per-target section headers plus each
// host's own report, printed after the pool in target order (never interleaved
// by concurrency).
func printVerboseBatch(results []batchResult, o scanOptions) {
	for i, r := range results {
		fmt.Fprintf(os.Stderr, "\n=== [%d/%d] %s ===\n", i+1, len(results), r.target)
		if r.res == nil {
			fmt.Fprintf(os.Stderr, "scan failed: %s\n", r.errMsg)
			continue
		}
		if o.format == "table" || o.format == "cli-no-colour" {
			report.PrintTable(r.res, true, o.minSeverity)
			if !o.noSummary {
				report.PrintSummary(r.res)
			}
		}
	}
}

// hostFileName derives a stable file name for a target: its host[:port] with
// characters that are unsafe in a path replaced by '_'.
func hostFileName(target string) string {
	h := hostLabel(target)
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}

// writeBatchDir writes one <host>.json (single-target JSON shape) per host
// that produced a result, plus DIR/batch-summary.json.
func writeBatchDir(dir string, results []batchResult, summary batchSummary) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	used := make(map[string]bool)
	for _, r := range results {
		if r.res == nil {
			continue
		}
		name := hostFileName(r.target)
		for used[name] {
			name = name + "_"
		}
		used[name] = true
		b, err := json.MarshalIndent(r.res, "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
			return err
		}
	}
	sb, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	sb = append(sb, '\n')
	return os.WriteFile(filepath.Join(dir, "batch-summary.json"), sb, 0o644)
}

// writeBatchOutputFile writes the aggregate document to --output FILE in the
// selected format.
func writeBatchOutputFile(path, format string, doc batchDoc, results []batchResult) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var buf strings.Builder
	switch format {
	case "json":
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	case "csv":
		if err := writeBatchCSV(&buf, results); err != nil {
			return err
		}
	case "sarif":
		report.WriteMultiSARIF(&buf, onyxVersion, batchSARIFResults(results))
	case "jsonl":
		for _, r := range results {
			for i := range r.res.Findings {
				b, err := json.Marshal(batchJSONLFinding{Target: r.target, Finding: r.res.Findings[i]})
				if err != nil {
					return err
				}
				buf.Write(b)
				buf.WriteByte('\n')
			}
		}
	default:
		buf.WriteString(batchSummaryText(doc))
	}
	return os.WriteFile(path, []byte(buf.String()), 0o644)
}

// batchSummaryText renders the table summary to a string (for --output FILE).
func batchSummaryText(doc batchDoc) string {
	s := doc.Summary
	sev := s.FindingsBySeverity
	total := sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
	var b strings.Builder
	fmt.Fprintf(&b, "Batch summary:\n")
	fmt.Fprintf(&b, "  Targets:     %d (%d ok, %d failed)\n", s.Targets, s.Ok, s.Failed)
	fmt.Fprintf(&b, "  Findings:    %d (critical %d, high %d, medium %d, low %d)\n",
		total, sev["critical"], sev["high"], sev["medium"], sev["low"])
	fmt.Fprintf(&b, "  Duration:    %.1fs\n", s.DurationS)
	return b.String()
}

// batchIsTTY reports whether progress may be drawn to w. It is a variable so
// tests can force a TTY-like writer.
var batchIsTTY = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// batchProgress renders the batch progress bar and the one-line-per-host
// completion lines. The live bar writes nothing when the output is not a
// terminal; both the bar and the compact lines are suppressed by --silent and
// by --verbose (which uses the legacy section headers instead).
type batchProgress struct {
	out   io.Writer
	tty   bool
	quiet bool // silent or verbose: no live bar and no compact lines
	total int
	start time.Time

	mu    sync.Mutex
	done  int
	drawn int       // width of the last drawn bar line
	last  time.Time // last throttle window start
}

func newBatchProgress(out io.Writer, quiet bool, total int, start time.Time) *batchProgress {
	p := &batchProgress{out: out, tty: batchIsTTY(out), quiet: quiet, total: total, start: start}
	p.render()
	return p
}

// hostLine is the compact per-host completion line, e.g.
// "[4/10] example.com  ok  7 findings (2 critical)  12.3s".
func (p *batchProgress) hostLine(n int, r batchResult) string {
	if r.ok {
		c, _, _, _, tot := countSeverities(r.res.Findings)
		return fmt.Sprintf("[%d/%d] %s  ok  %d findings (%d critical)  %.1fs\n",
			n, p.total, r.host, tot, c, r.dur.Seconds())
	}
	return fmt.Sprintf("[%d/%d] %s  failed  %s  %.1fs\n",
		n, p.total, r.host, r.errMsg, r.dur.Seconds())
}

// barLine is the single live status line, e.g. "[####------] 40% 4/10 hosts 38s".
func (p *batchProgress) barLine() string {
	const width = 10
	frac := 0.0
	if p.total > 0 {
		frac = float64(p.done) / float64(p.total)
		if frac > 1 {
			frac = 1
		}
	}
	filled := int(frac * width)
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	return fmt.Sprintf("[%s] %d%% %d/%d hosts %s",
		bar, int(frac*100), p.done, p.total, time.Since(p.start).Round(time.Second))
}

// drawLocked draws the live bar line, padding over any longer previous line.
func (p *batchProgress) drawLocked() {
	line := p.barLine()
	if p.drawn > len(line) {
		fmt.Fprintf(p.out, "\r%s%s", line, strings.Repeat(" ", p.drawn-len(line)))
	} else {
		fmt.Fprint(p.out, "\r"+line)
	}
	p.drawn = len(line)
}

// render draws the initial live bar, throttled like the single-target bar. It
// is a no-op off a terminal, when quiet.
func (p *batchProgress) render() {
	if p.quiet || !p.tty {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.last) < 80*time.Millisecond {
		return
	}
	p.last = time.Now()
	p.drawLocked()
}

// hostDone records a finished host: it clears the live bar, prints the compact
// completion line and (on a terminal) redraws the bar underneath.
func (p *batchProgress) hostDone(n int, r batchResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = n
	if p.quiet {
		return
	}
	if p.drawn > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.drawn))
		p.drawn = 0
	}
	fmt.Fprint(p.out, p.hostLine(n, r))
	p.last = time.Now()
	if p.tty {
		p.drawLocked()
	}
}

// finish erases the live bar line when the batch ends.
func (p *batchProgress) finish() {
	if p.quiet || !p.tty {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = p.total
	if p.drawn > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.drawn))
		p.drawn = 0
	}
}

// batchPocIndex is the per-batch PoC tracker index: the tracker directory is
// resolved once and every CVE's links are computed once, so enrichment is not
// repeated per host. A missing tracker warns exactly once.
type batchPocIndex struct {
	o       scanOptions
	once    sync.Once
	mu      sync.Mutex
	ok      bool
	dir     string
	fetcher *pocs.Fetcher
	cache   map[string][]pocs.PoCLink
}

// newBatchPocIndex prepares the shared index (directory resolution is lazy and
// happens on first use).
func newBatchPocIndex(o scanOptions) *batchPocIndex {
	return &batchPocIndex{o: o, cache: make(map[string][]pocs.PoCLink)}
}

// collect enriches res with the top PoC links per CVE, using the batch-wide
// cache so each CVE is resolved at most once across all hosts.
func (idx *batchPocIndex) collect(res *scanner.Result, o scanOptions) {
	if len(res.Nuclei) == 0 {
		return
	}
	idx.once.Do(func() {
		dir := resolvePocTrackerDir(o)
		if dir == "" {
			return
		}
		if _, err := os.Stat(dir); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] CVE-PoC-Tracker not found at %s — skipping PoC lookup\n", dir)
			return
		}
		idx.dir = dir
		idx.fetcher = pocs.NewFetcher(os.Getenv("GITHUB_TOKEN"))
		idx.ok = true
	})
	if !idx.ok {
		return
	}

	seen := make(map[string]bool)
	for _, n := range res.Nuclei {
		cve := n.CVE
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true

		idx.mu.Lock()
		links, cached := idx.cache[cve]
		idx.mu.Unlock()
		if !cached {
			found := pocs.ExtractLinks(idx.dir, cve)
			links = pocs.TopByStars(idx.fetcher.Fetch(found))
			for i := range links {
				links[i].CVE = cve
			}
			idx.mu.Lock()
			idx.cache[cve] = links
			idx.mu.Unlock()
		}
		res.PoCs = append(res.PoCs, links...)
	}
}
