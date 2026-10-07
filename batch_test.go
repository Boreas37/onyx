package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

// writeTargets writes lines (joined with \n) into a temp file and returns
// its path.
func writeTargets(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/targets.txt"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadTargetListParsing covers the --input grammar: comments, blank
// lines, CRLF, whitespace, scheme defaulting and host dedupe.
func TestLoadTargetListParsing(t *testing.T) {
	path := writeTargets(t, "# comment line\r\n"+
		"\r\n"+
		"  example.com  \r\n"+
		"http://plain.example/\r\n"+
		"https://secure.example\r\n"+
		"EXAMPLE.com/   # dup of example.com (case + trailing slash)\r\n"+
		"   \r\n")

	list, err := loadTargetList(scanOptions{input: path})
	if err != nil {
		t.Fatalf("loadTargetList: %v", err)
	}
	want := []string{
		"https://example.com",    // bare hostname -> https, trailing slash dropped
		"http://plain.example",   // explicit http respected
		"https://secure.example", // explicit https respected
	}
	if strings.Join(list, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", list, want)
	}
}

// TestLoadTargetListCombinesPositionalAndInput verifies positional targets
// and --input entries merge, with positional entries winning a collision.
func TestLoadTargetListCombinesPositionalAndInput(t *testing.T) {
	path := writeTargets(t, "input-only.example\nhttp://dup.example\n")
	list, err := loadTargetList(scanOptions{
		targets: []string{"http://dup.example", "pos.example"},
		input:   path,
	})
	if err != nil {
		t.Fatalf("loadTargetList: %v", err)
	}
	want := []string{"http://dup.example", "https://pos.example", "https://input-only.example"}
	if strings.Join(list, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v (positionals first, dup dropped)", list, want)
	}
}

// TestLoadTargetListCap verifies the 5000-target hard cap is a usage error.
func TestLoadTargetListCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxTargets+1; i++ {
		b.WriteString("host")
		b.WriteString(itoa(i))
		b.WriteString(".example\n")
	}
	path := writeTargets(t, b.String())
	_, err := loadTargetList(scanOptions{input: path})
	if err == nil {
		t.Fatalf("loadTargetList accepted %d targets, want an error above %d", maxTargets+1, maxTargets)
	}
	if !strings.Contains(err.Error(), "too many targets") {
		t.Fatalf("error = %v, want a 'too many targets' usage error", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestParseScanArgsBatchFlags verifies the new flags and the default.
func TestParseScanArgsBatchFlags(t *testing.T) {
	_, o := parseScanArgs([]string{"a.example", "b.example", "--input", "/tmp/x", "--host-concurrency", "4", "--output-dir", "/tmp/out"})
	if o.hostConcurrency != 4 || o.input != "/tmp/x" || o.outputDir != "/tmp/out" {
		t.Fatalf("flags: hostConcurrency=%d input=%q outputDir=%q", o.hostConcurrency, o.input, o.outputDir)
	}
	if len(o.targets) != 2 || o.targets[0] != "a.example" || o.targets[1] != "b.example" {
		t.Fatalf("targets = %v, want [a.example b.example]", o.targets)
	}
	_, o = parseScanArgs([]string{"a.example"})
	if o.hostConcurrency != 2 {
		t.Fatalf("default hostConcurrency = %d, want 2", o.hostConcurrency)
	}
}

// TestRunHostPoolConcurrencyBound verifies no more than N hosts are ever
// scanned at once.
func TestRunHostPoolConcurrencyBound(t *testing.T) {
	const n, conc = 12, 3
	targets := make([]string, n)
	var inflight, maxInflight int32
	var mu sync.Mutex

	fn := func(i int) batchTargetResult {
		cur := atomic.AddInt32(&inflight, 1)
		mu.Lock()
		if cur > maxInflight {
			maxInflight = cur
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		return batchTargetResult{Target: targets[i], Ok: true}
	}

	results := runHostPool(targets, conc, make(chan struct{}), fn, nil)
	if len(results) != n {
		t.Fatalf("got %d results, want %d", len(results), n)
	}
	if maxInflight > conc {
		t.Fatalf("max hosts in flight = %d, want <= %d", maxInflight, conc)
	}
	if maxInflight < 2 {
		t.Fatalf("max hosts in flight = %d, want the pool to actually run in parallel", maxInflight)
	}
}

// TestRunHostPoolStopDropsRemaining verifies a closed stop channel prevents
// further hosts from being dispatched.
func TestRunHostPoolStopDropsRemaining(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	results := runHostPool([]string{"a", "b", "c"}, 2, stop, func(i int) batchTargetResult {
		return batchTargetResult{Target: "x", Ok: true}
	}, nil)
	for i, r := range results {
		if r.Target != "" {
			t.Fatalf("result %d was dispatched (%q) despite a closed stop channel", i, r.Target)
		}
	}
}

// TestBatchExitCodeRules covers the exit-code mapping: mixed (>=1 ok) is 0,
// all-failed is 1.
func TestBatchExitCodeRules(t *testing.T) {
	if got := batchExitCode(1, 3); got != 0 {
		t.Errorf("mixed batchExitCode(1,3) = %d, want 0", got)
	}
	if got := batchExitCode(0, 4); got != 1 {
		t.Errorf("all-failed batchExitCode(0,4) = %d, want 1", got)
	}
}

// TestRunBatchIsolationAndExitCodes runs a real batch against a live
// WordPress server and a dead port: the dead host must not stop the batch,
// the finding must be attributed to the right host, and the exit code is 0.
func TestRunBatchIsolationAndExitCodes(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()
	dead := "http://127.0.0.1:1"

	out := captureStdout(t, func() {
		code := runBatch([]string{srv.URL, dead}, scanOptions{
			dbPath: elementorFeedDB(t), silent: true, format: "json", hostConcurrency: 2,
		})
		if code != 0 {
			t.Errorf("mixed batch exit code = %d, want 0", code)
		}
	})

	var doc struct {
		Targets []struct {
			Target   string            `json:"target"`
			Ok       bool              `json:"ok"`
			Error    string            `json:"error"`
			Findings []scanner.Finding `json:"findings"`
			Stats    *scanner.Summary  `json:"stats"`
		} `json:"targets"`
		Summary struct {
			Targets            int            `json:"targets"`
			Ok                 int            `json:"ok"`
			Failed             int            `json:"failed"`
			FindingsBySeverity map[string]int `json:"findings_by_severity"`
			DurationS          float64        `json:"duration_s"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("batch json is not valid JSON: %v\n%s", err, out)
	}
	if doc.Summary.Targets != 2 || doc.Summary.Ok != 1 || doc.Summary.Failed != 1 {
		t.Fatalf("summary = %+v, want targets=2 ok=1 failed=1", doc.Summary)
	}
	if doc.Summary.FindingsBySeverity["critical"] != 1 {
		t.Errorf("findings_by_severity = %v, want critical=1", doc.Summary.FindingsBySeverity)
	}
	if doc.Summary.DurationS < 0 {
		t.Errorf("duration_s = %v, want >= 0", doc.Summary.DurationS)
	}

	var okHost, deadHost *struct {
		Target   string            `json:"target"`
		Ok       bool              `json:"ok"`
		Error    string            `json:"error"`
		Findings []scanner.Finding `json:"findings"`
		Stats    *scanner.Summary  `json:"stats"`
	}
	for i := range doc.Targets {
		switch doc.Targets[i].Target {
		case srv.URL:
			okHost = &doc.Targets[i]
		case dead:
			deadHost = &doc.Targets[i]
		}
	}
	if okHost == nil || deadHost == nil {
		t.Fatalf("batch targets = %+v, want both hosts present", doc.Targets)
	}
	if !okHost.Ok {
		t.Errorf("live WordPress host Ok = false, want true")
	}
	if okHost.Stats == nil || okHost.Stats.Findings != 1 {
		t.Errorf("live host stats = %+v, want findings=1", okHost.Stats)
	}
	if len(okHost.Findings) != 1 || okHost.Findings[0].Slug != "elementor" {
		t.Errorf("live host findings = %+v, want the elementor finding", okHost.Findings)
	}
	if deadHost.Ok || deadHost.Error == "" {
		t.Errorf("dead host = %+v, want Ok=false with an error reason", deadHost)
	}
}

// TestRunBatchAllFailedExitCode verifies every target failing yields exit 1.
func TestRunBatchAllFailedExitCode(t *testing.T) {
	code := runBatch([]string{"http://127.0.0.1:1", "http://127.0.0.1:2"}, scanOptions{
		dbPath: emptyDB(t), silent: true, format: "json", hostConcurrency: 2,
	})
	if code != 1 {
		t.Fatalf("all-failed batch exit code = %d, want 1", code)
	}
}

// TestRunBatchCSVTargetColumn verifies the batch CSV prepends the target
// column and carries the finding of the WordPress host.
func TestRunBatchCSVTargetColumn(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()

	out := captureStdout(t, func() {
		if code := runBatch([]string{srv.URL, "http://127.0.0.1:1"}, scanOptions{
			dbPath: elementorFeedDB(t), silent: true, format: "csv", hostConcurrency: 2,
		}); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("batch csv is not parseable: %v\n%s", err, out)
	}
	if len(recs) != 2 {
		t.Fatalf("expected header + 1 row, got %d: %v", len(recs), recs)
	}
	wantHeader := "target,slug,type,installed_version,cve,severity,title,affected_versions"
	if got := strings.Join(recs[0], ","); got != wantHeader {
		t.Errorf("csv header = %q, want %q", got, wantHeader)
	}
	if recs[1][0] != srv.URL || recs[1][1] != "elementor" || recs[1][5] != "critical" {
		t.Errorf("csv row = %v, want the elementor finding tagged with the host", recs[1])
	}
}

// TestRunBatchSARIFRunCount verifies one SARIF run per host.
func TestRunBatchSARIFRunCount(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()

	out := captureStdout(t, func() {
		if code := runBatch([]string{srv.URL, "http://127.0.0.1:1"}, scanOptions{
			dbPath: elementorFeedDB(t), silent: true, format: "sarif", hostConcurrency: 2,
		}); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("batch sarif is not valid JSON: %v\n%s", err, out)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("sarif runs = %d, want 2 (one per host)", len(doc.Runs))
	}
}

// TestRunBatchOutputDir verifies --output-dir writes one <host>.json per host
// plus batch-summary.json.
func TestRunBatchOutputDir(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()
	dir := t.TempDir() + "/batch"

	captureStdout(t, func() {
		if code := runBatch([]string{srv.URL, "http://127.0.0.1:1"}, scanOptions{
			dbPath: elementorFeedDB(t), silent: true, format: "json", hostConcurrency: 2, outputDir: dir,
		}); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading output dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "batch-summary.json") {
		t.Errorf("output dir %v missing batch-summary.json", names)
	}
	if !strings.Contains(joined, "127.0.0.1_"+portOf(t, srv.URL)+".json") {
		t.Errorf("output dir %v missing the per-host file", names)
	}
}

func portOf(t *testing.T, raw string) string {
	t.Helper()
	i := strings.LastIndexByte(raw, ':')
	if i < 0 {
		t.Fatalf("no port in %q", raw)
	}
	return raw[i+1:]
}
