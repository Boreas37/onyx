// RM6 — batch / multi-target scanning. Everything in this file is additive:
// single-target scans keep going through runScan in main.go untouched. When
// the resolved target list holds more than one target, main() hands it to
// runBatch, which loads the vulnerability database exactly once, scans hosts
// with a bounded worker pool, and writes one aggregate document.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/pocs"
	"github.com/Boreas37/onyx/internal/report"
	"github.com/Boreas37/onyx/internal/scanner"
)

const (
	// maxTargets is the hard cap on the resolved (deduplicated) target list.
	maxTargets = 5000
	// hostConcurrency bounds for --host-concurrency.
	minHostConcurrency = 1
	maxHostConcurrency = 16
)

// loadTargetList merges the positional targets with the --input file (if
// any) into a normalized, deduplicated list. Positional targets come first,
// so they win a dedupe collision. It returns a usage error for an unreadable
// --input file or a list above the hard cap.
func loadTargetList(o scanOptions) ([]string, error) {
	raw := append([]string{}, o.targets...)

	if o.input != "" {
		lines, err := readTargetFile(o.input)
		if err != nil {
			return nil, err
		}
		raw = append(raw, lines...)
	}

	var out []string
	seen := make(map[string]bool, len(raw))
	for _, r := range raw {
		target, key, ok := normalizeTarget(r)
		if !ok {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	if len(out) > maxTargets {
		return nil, fmt.Errorf("too many targets (%d) — the hard limit is %d", len(out), maxTargets)
	}
	return out, nil
}

// readTargetFile reads an --input target list: one target per line, CRLF
// tolerated, leading/trailing whitespace trimmed, blank lines and # comment
// lines ignored (a '#' starts a comment anywhere on the line).
func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}

// normalizeTarget turns a raw target line into the URL that will be scanned
// and the dedupe key. Bare hostnames get an https:// scheme; explicit
// http:// / https:// are respected; a trailing slash is dropped. The dedupe
// key is the lowercased host[:port], so example.com, EXAMPLE.COM/ and
// https://example.com collapse onto the same target (first occurrence wins).
func normalizeTarget(raw string) (target, key string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	target = strings.TrimRight(s, "/")
	if target == "" {
		return "", "", false
	}
	key = strings.ToLower(target)
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		key = strings.ToLower(u.Host)
	}
	return target, key, true
}

// hostLabel returns the host[:port] of a target for compact per-host output,
// falling back to the raw target when it cannot be parsed.
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

// batchTargetResult is one host's outcome inside a batch run.
type batchTargetResult struct {
	Target   string
	Host     string
	Ok       bool
	Error    string
	Findings []scanner.Finding
	Stats    *scanner.Summary
	Result   *scanner.Result
	Duration time.Duration
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

// batchJSONLFinding is a single JSON Lines record in batch mode: the regular
// finding object plus the host it belongs to.
type batchJSONLFinding struct {
	Target string `json:"target"`
	scanner.Finding
}

// scanOptionsToScanner builds the scanner.Options shared by single-target
// runScan and every per-host scan in a batch.
func scanOptionsToScanner(o scanOptions) scanner.Options {
	reqTimeout := o.requestTimeout
	if reqTimeout == 0 {
		reqTimeout = o.timeout
	}
	return scanner.Options{
		Threads:             o.threads,
		Timeout:             time.Duration(o.timeout) * time.Second,
		ConnectTimeout:      time.Duration(o.connectTimeout) * time.Second,
		RequestTimeout:      time.Duration(reqTimeout) * time.Second,
		APIOnly:             o.apiOnly,
		Stealth:             o.stealth,
		RateLimit:           o.rateLimit,
		MaxRequests:         o.maxReq,
		Enumerate:           o.enumerate,
		UserAgent:           o.userAgent,
		RandomUA:            o.randomUA,
		DetectionMode:       o.detectionMode,
		Proxy:               o.proxy,
		ProxyAuth:           o.proxyAuth,
		ProxyTargetOnly:     o.proxyTargetOnly,
		TLSFingerprint:      o.tlsFingerprint,
		PerHostRateLimit:    o.perHostRateLimit,
		NoXMLRPC:            o.noXMLRPC,
		Checks:              o.checks,
		ContentDir:          o.contentDir,
		PluginsDir:          o.pluginsDir,
		ExcludeContentBased: o.excludeContentBased,
		Scope:               o.scope,
		PluginsList:         o.pluginsList,
		ThemesList:          o.themesList,
		MaxScanDuration:     o.maxScanDuration,
		CacheTTL:            o.cacheTTL,
		PasswordsFile:       o.passwordsFile,
		UsernamesFile:       o.usernamesFile,
		User:                o.user,
		XMLRPCBrute:         o.xmlrpcBrute,
		MCPerRequest:        o.mcMaxPasswords,
		WPAuth:              o.wpAuth,
		NoBrute:             o.noBrute,
		NoSummary:           o.noSummary,
	}
}

// scanOneHost scans a single target as part of a batch. A hard failure
// (unreachable, out of scope, blocked) yields Ok=false with a reason; a
// reachable target — WordPress or not — yields Ok=true and its result.
func scanOneHost(database *db.DB, target string, o scanOptions, pocIdx *pocIndex) batchTargetResult {
	start := time.Now()
	r := batchTargetResult{Target: target, Host: hostLabel(target)}

	sc, err := scanner.NewScanner(database, target, scanOptionsToScanner(o))
	if err != nil {
		r.Error = err.Error()
		r.Duration = time.Since(start)
		return r
	}
	res, serr := sc.Scan()
	r.Duration = time.Since(start)
	if res == nil {
		if serr != nil {
			r.Error = serr.Error()
		} else {
			r.Error = "scan failed"
		}
		return r
	}

	// --nuclei verification and PoC enrichment, once per host (the tracker
	// index itself is shared across the whole batch through pocIdx).
	if o.nuclei {
		verifyWithNuclei(res, o)
		if !o.noPocs {
			pocIdx.collect(res, o)
		}
	}
	r.Ok = true
	r.Result = res
	r.Findings = res.Findings
	r.Stats = res.Summary
	return r
}

// runHostPool scans targets with at most concurrency workers. jobs are
// dispatched in order; stop aborts further dispatch (Ctrl-C) while in-flight
// hosts finish normally. Results are indexed by target position; hosts that
// were never dispatched keep a zero value (empty Target).
func runHostPool(targets []string, concurrency int, stop <-chan struct{}, scan func(i int) batchTargetResult, bp *batchProgress) []batchTargetResult {
	results := make([]batchTargetResult, len(targets))
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
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
		case <-stop:
			break dispatch
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// runBatch is the entry point for multi-target scans (see batch.go header).
func runBatch(targets []string, o scanOptions) int {
	start := time.Now()

	// The ~151 MB database is loaded exactly once for the whole batch.
	if _, err := os.Stat(o.dbPath); err != nil {
		if o.noUpdate {
			fmt.Fprintf(os.Stderr, "error: database not found at %s (--no-update given — run 'onyx update' first)\n", o.dbPath)
			return 2
		}
		fmt.Fprintf(os.Stderr, "database not found at %s — fetching it first...\n", o.dbPath)
		if err := update(o.dbPath, feedProduction, false); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			return 2
		}
	}
	database, err := db.Load(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return 2
	}
	if !o.noUpdateCheck {
		if days := dbAgeDays(o.dbPath); days > 14 {
			fmt.Fprintf(os.Stderr, "[WARN] database is %d days old (%s feed) — run 'onyx update' for fresh data\n", days, dbFeedType(o.dbPath))
		}
	}

	// PoC tracker index is resolved (and its per-CVE reads cached) once.
	pocIdx := newPocIndex(o)

	bp := &batchProgress{
		out:    os.Stderr,
		tty:    batchIsTTY(os.Stderr),
		silent: o.silent,
		total:  len(targets),
		start:  start,
	}
	bp.render()

	// Ctrl-C: stop dispatching new hosts, let in-flight ones finish, then
	// still print the summary of everything that completed.
	stop := make(chan struct{})
	var once sync.Once
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	go func() {
		select {
		case <-sigc:
			once.Do(func() { close(stop) })
		case <-stop:
		}
	}()

	results := runHostPool(targets, o.hostConcurrency, stop, func(i int) batchTargetResult {
		return scanOneHost(database, targets[i], o, pocIdx)
	}, bp)
	bp.finish()

	return writeBatchOutput(results, o, start)
}

// scannedResults keeps only the hosts that were actually dispatched (a
// Ctrl-C can leave trailing zero-value entries behind).
func scannedResults(results []batchTargetResult) []batchTargetResult {
	out := make([]batchTargetResult, 0, len(results))
	for _, r := range results {
		if r.Target != "" {
			out = append(out, r)
		}
	}
	return out
}

// buildBatchDoc aggregates per-host results into the pinned batch document.
func buildBatchDoc(results []batchTargetResult, start time.Time) batchDoc {
	doc := batchDoc{
		Targets: make([]batchTargetDoc, 0, len(results)),
		Summary: batchSummary{FindingsBySeverity: map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0,
		}},
	}
	for _, r := range results {
		findings := r.Findings
		if findings == nil {
			findings = []scanner.Finding{}
		}
		doc.Targets = append(doc.Targets, batchTargetDoc{
			Target:   r.Target,
			Ok:       r.Ok,
			Error:    r.Error,
			Findings: findings,
			Stats:    r.Stats,
		})
		if r.Ok {
			doc.Summary.Ok++
		} else {
			doc.Summary.Failed++
		}
		c, h, m, l, _ := countSeverities(r.Findings)
		doc.Summary.FindingsBySeverity["critical"] += c
		doc.Summary.FindingsBySeverity["high"] += h
		doc.Summary.FindingsBySeverity["medium"] += m
		doc.Summary.FindingsBySeverity["low"] += l
	}
	doc.Summary.Targets = len(results)
	doc.Summary.DurationS = math.Round(time.Since(start).Seconds()*10) / 10
	return doc
}

// writeBatchOutput renders the aggregate result and returns the batch exit
// code (0 when at least one target was scanned, 1 when every target failed).
func writeBatchOutput(results []batchTargetResult, o scanOptions, start time.Time) int {
	results = scannedResults(results)
	doc := buildBatchDoc(results, start)

	if o.outputDir != "" {
		if err := writeBatchDir(o.outputDir, results, doc.Summary); err != nil {
			fmt.Fprintln(os.Stderr, "error writing output dir:", err)
		}
	}

	switch o.format {
	case "json":
		printBatchJSON(doc)
	case "csv":
		writeBatchCSV(os.Stdout, results)
	case "sarif":
		printBatchSARIF(results)
	case "jsonl":
		printBatchJSONL(results)
	default: // table, cli-no-colour
		printBatchSummary(doc)
	}

	if o.output != "" {
		if err := writeBatchOutputFile(o.output, o.format, doc, results); err != nil {
			fmt.Fprintln(os.Stderr, "error writing output:", err)
		}
	}

	if doc.Summary.Ok >= 1 {
		return 0
	}
	return 1
}

// batchExitCode maps ok/failed counts onto the batch exit codes: 0 when at
// least one target scanned successfully, 1 when every target failed.
func batchExitCode(ok, failed int) int {
	if ok >= 1 {
		return 0
	}
	return 1
}

func printBatchJSON(doc batchDoc) {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json output:", err)
		return
	}
	fmt.Println(string(b))
}

// batchCSVHeader prepends the target column to the single-target header.
var batchCSVHeader = append([]string{"target"}, csvHeaderColumns...)

// csvHeaderColumns mirrors report.csvHeader without importing an unexported
// symbol (kept in lock-step with report.WriteCSV).
var csvHeaderColumns = []string{
	"slug", "type", "installed_version", "cve", "severity", "title", "affected_versions",
}

// writeBatchCSV writes one row per vulnerability across all hosts, with the
// target as the first column.
func writeBatchCSV(w io.Writer, results []batchTargetResult) {
	cw := csv.NewWriter(w)
	if err := cw.Write(batchCSVHeader); err != nil {
		fmt.Fprintln(os.Stderr, "csv output:", err)
		return
	}
	for _, r := range results {
		for i := range r.Findings {
			f := &r.Findings[i]
			for _, v := range f.Vulnerabilities {
				if err := cw.Write([]string{
					r.Target,
					f.Slug,
					f.Type,
					f.InstalledVersion,
					v.CVE,
					strings.ToLower(v.Rating),
					v.Title,
					strings.Join(v.AffectedLabels, "; "),
				}); err != nil {
					fmt.Fprintln(os.Stderr, "csv output:", err)
					return
				}
			}
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "csv output:", err)
	}
}

// printBatchJSONL emits one JSON object per finding, each tagged with its
// host, in target order (deterministic across runs).
func printBatchJSONL(results []batchTargetResult) {
	enc := json.NewEncoder(os.Stdout)
	for _, r := range results {
		for i := range r.Findings {
			_ = enc.Encode(batchJSONLFinding{Target: r.Target, Finding: r.Findings[i]})
		}
	}
}

// printBatchSARIF emits one SARIF log with one run per dispatched host.
func printBatchSARIF(results []batchTargetResult) {
	report.WriteMultiSARIF(os.Stdout, onyxVersion, batchSARIFResults(results))
}

// writeBatchSARIF writes the batch SARIF log to w.
func writeBatchSARIF(w io.Writer, results []batchTargetResult) {
	report.WriteMultiSARIF(w, onyxVersion, batchSARIFResults(results))
}

// batchSARIFResults maps per-host outcomes onto scanner results (a failed
// host contributes an empty run so the run count still equals the host count).
func batchSARIFResults(results []batchTargetResult) []*scanner.Result {
	res := make([]*scanner.Result, 0, len(results))
	for _, r := range results {
		if r.Result != nil {
			res = append(res, r.Result)
		} else {
			res = append(res, &scanner.Result{Target: r.Target})
		}
	}
	return res
}

// printBatchSummary renders the end-of-batch human summary (table formats).
func printBatchSummary(doc batchDoc) {
	s := doc.Summary
	fmt.Println("Batch summary:")
	fmt.Printf("  %-12s %d (%d ok, %d failed)\n", "Targets:", s.Targets, s.Ok, s.Failed)

	sev := s.FindingsBySeverity
	total := sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
	fmt.Printf("  %-12s %d (critical %d, high %d, medium %d, low %d)\n",
		"Findings:", total, sev["critical"], sev["high"], sev["medium"], sev["low"])
	fmt.Printf("  %-12s %.1fs\n", "Duration:", s.DurationS)

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
func writeBatchDir(dir string, results []batchTargetResult, summary batchSummary) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	used := make(map[string]bool)
	for _, r := range results {
		if r.Result == nil {
			continue
		}
		name := hostFileName(r.Target)
		if used[name] {
			name = name + "_" + strconvI(len(used))
		}
		used[name] = true
		b, err := json.MarshalIndent(r.Result, "", "  ")
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
func writeBatchOutputFile(path, format string, doc batchDoc, results []batchTargetResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
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
		writeBatchCSV(&buf, results)
	case "sarif":
		writeBatchSARIF(&buf, results)
	case "jsonl":
		for _, r := range results {
			for i := range r.Findings {
				b, err := json.Marshal(batchJSONLFinding{Target: r.Target, Finding: r.Findings[i]})
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

func strconvI(n int) string { return fmt.Sprintf("%d", n) }

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
// completion lines. It writes nothing when silent or when the output is not
// a terminal — a piped batch leaves stderr completely clean.
type batchProgress struct {
	out    io.Writer
	tty    bool
	silent bool
	total  int
	start  time.Time

	mu    sync.Mutex
	done  int
	drawn int       // width of the last drawn bar line
	last  time.Time // last throttle window start
}

// hostLine is the compact per-host completion line, e.g.
// "[4/10] example.com  ok  7 findings (2 critical)  12.3s".
func hostLine(n, total int, r batchTargetResult) string {
	if r.Ok {
		c, _, _, _, tot := countSeverities(r.Findings)
		return fmt.Sprintf("[%d/%d] %s  ok  %d findings (%d critical)  %.1fs\n",
			n, total, r.Host, tot, c, r.Duration.Seconds())
	}
	return fmt.Sprintf("[%d/%d] %s  failed  %s  %.1fs\n",
		n, total, r.Host, r.Error, r.Duration.Seconds())
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

// render draws (or redraws) the live status line, throttled like the
// single-target bar. It is a no-op off a terminal or when silent.
func (p *batchProgress) render() {
	if p.silent || !p.tty {
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

func (p *batchProgress) drawLocked() {
	line := p.barLine()
	if p.drawn >= len(line) {
		fmt.Fprintf(p.out, "\r%s%s", line, strings.Repeat(" ", p.drawn-len(line)))
	} else {
		fmt.Fprint(p.out, "\r"+line)
	}
	p.drawn = len(line)
}

// hostDone records a finished host: it clears the live bar, prints the
// compact completion line and redraws the bar underneath.
func (p *batchProgress) hostDone(n int, r batchTargetResult) {
	p.mu.Lock()
	p.done = n
	if p.silent || !p.tty {
		p.mu.Unlock()
		return
	}
	if p.drawn > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.drawn))
		p.drawn = 0
	}
	fmt.Fprint(p.out, hostLine(n, p.total, r))
	p.last = time.Now()
	p.drawLocked()
	p.mu.Unlock()
}

// finish erases the live bar line when the batch ends.
func (p *batchProgress) finish() {
	if p.silent || !p.tty {
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

// pocIndex is the per-batch PoC tracker index: the tracker directory is
// resolved once and every CVE's links are computed once, so enrichment is
// not repeated per host. A missing tracker warns exactly once.
type pocIndex struct {
	o       scanOptions
	once    sync.Once
	mu      sync.Mutex
	ok      bool
	dir     string
	fetcher *pocs.Fetcher
	cache   map[string][]pocs.PoCLink
}

// newPocIndex prepares the shared index (directory resolution is lazy and
// happens on first use).
func newPocIndex(o scanOptions) *pocIndex {
	return &pocIndex{o: o, cache: make(map[string][]pocs.PoCLink)}
}

// collect enriches res with the top PoC links per CVE, using the batch-wide
// cache so each CVE is resolved at most once across all hosts.
func (idx *pocIndex) collect(res *scanner.Result, o scanOptions) {
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
