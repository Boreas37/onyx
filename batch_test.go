package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

// aggDoc mirrors the pinned aggregate JSON document for test decoding.
type aggDoc struct {
	Targets []struct {
		Target   string            `json:"target"`
		Ok       bool              `json:"ok"`
		Error    string            `json:"error"`
		Findings []json.RawMessage `json:"findings"`
		Stats    json.RawMessage   `json:"stats"`
	} `json:"targets"`
	Summary struct {
		Targets            int            `json:"targets"`
		Ok                 int            `json:"ok"`
		Failed             int            `json:"failed"`
		FindingsBySeverity map[string]int `json:"findings_by_severity"`
		DurationS          float64        `json:"duration_s"`
	} `json:"summary"`
}

// batchTestServer serves a plain (non-WordPress) site.
func batchTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain site"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBatchAggregateJSONShape drives runMulti in json mode over two live
// targets and one dead target, then checks the pinned document shape,
// per-host attribution and the exit-code contract.
func TestBatchAggregateJSONShape(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := batchTestServer(t)
	dead := "http://127.0.0.1:1"

	o := scanOptions{dbPath: dbPath, threads: 4, format: "json", silent: true, noIntel: true, jobs: 3}
	var code int
	out := captureStdout(t, func() {
		code = runMulti([]string{wpSrv.URL, clean.URL, dead}, o)
	})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (dead target wins the aggregation)", code)
	}
	var doc aggDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("aggregate json: %v\n%s", err, out)
	}
	if doc.Summary.Targets != 3 || doc.Summary.Ok != 2 || doc.Summary.Failed != 1 {
		t.Fatalf("summary = %+v, want targets=3 ok=2 failed=1", doc.Summary)
	}
	if len(doc.Targets) != 3 {
		t.Fatalf("len(targets) = %d, want 3", len(doc.Targets))
	}
	if doc.Summary.FindingsBySeverity["critical"] < 1 {
		t.Errorf("findings_by_severity = %v, want >=1 critical", doc.Summary.FindingsBySeverity)
	}

	type hostOutcome struct {
		ok  bool
		err string
		n   int
	}
	byTarget := map[string]hostOutcome{}
	for _, tg := range doc.Targets {
		byTarget[tg.Target] = hostOutcome{tg.Ok, tg.Error, len(tg.Findings)}
	}
	wp := byTarget[wpSrv.URL]
	if !wp.ok || wp.n == 0 {
		t.Errorf("wp target = %+v, want ok with findings", wp)
	}
	cleanT := byTarget[clean.URL]
	if !cleanT.ok || cleanT.n != 0 || cleanT.err != "" {
		t.Errorf("clean target = %+v, want ok with no findings and no error", cleanT)
	}
	d := byTarget[dead]
	if d.ok || d.err == "" {
		t.Errorf("dead target = %+v, want ok=false with an error (isolation)", d)
	}
}

// TestBatchSARIFRunCountEqualsTargets proves the aggregate SARIF log carries
// exactly one run per host, named after the host.
func TestBatchSARIFRunCountEqualsTargets(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := batchTestServer(t)
	dead := "http://127.0.0.1:1"

	o := scanOptions{dbPath: dbPath, threads: 4, format: "sarif", silent: true, noIntel: true, jobs: 3}
	out := captureStdout(t, func() {
		runMulti([]string{wpSrv.URL, clean.URL, dead}, o)
	})

	var doc struct {
		Runs []struct {
			Name    string `json:"name"`
			Results []any  `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif json: %v\n%s", err, out)
	}
	if len(doc.Runs) != 3 {
		t.Fatalf("runs = %d, want 3 (one per host)", len(doc.Runs))
	}
	named := 0
	for _, r := range doc.Runs {
		if strings.TrimSpace(r.Name) != "" {
			named++
		}
	}
	if named != 3 {
		t.Errorf("named runs = %d, want 3 (host in the run name)", named)
	}
}

// TestBatchOutputDirFileSet proves --output-dir writes one <host>.json per
// reachable target plus batch-summary.json.
func TestBatchOutputDirFileSet(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := batchTestServer(t)
	dead := "http://127.0.0.1:1"
	dir := t.TempDir()

	o := scanOptions{dbPath: dbPath, threads: 4, format: "json", silent: true, noIntel: true, jobs: 3, outputDir: dir}
	captureStdout(t, func() {
		runMulti([]string{wpSrv.URL, clean.URL, dead}, o)
	})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var hostFiles, summaries int
	for _, e := range entries {
		switch {
		case e.Name() == "batch-summary.json":
			summaries++
		case strings.HasSuffix(e.Name(), ".json"):
			hostFiles++
		}
	}
	if hostFiles != 2 || summaries != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("output dir = %v, want 2 host files + batch-summary.json", names)
	}
	sb, err := os.ReadFile(filepath.Join(dir, "batch-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Targets int `json:"targets"`
		Ok      int `json:"ok"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(sb, &s); err != nil {
		t.Fatalf("batch-summary.json: %v", err)
	}
	if s.Targets != 3 || s.Ok != 2 || s.Failed != 1 {
		t.Errorf("batch-summary = %+v, want targets=3 ok=2 failed=1", s)
	}
}

// TestBatchPipedStderrHasNoCarriageReturn verifies the live progress bar is
// TTY-only: a piped batch emits compact per-host lines with no control chars.
func TestBatchPipedStderrHasNoCarriageReturn(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := batchTestServer(t)

	o := scanOptions{dbPath: dbPath, threads: 4, format: "table", noIntel: true, jobs: 2}
	var errOut string
	captureStdout(t, func() {
		errOut = captureStderr(t, func() {
			runMulti([]string{wpSrv.URL, clean.URL}, o)
		})
	})
	if strings.Contains(errOut, "\r") {
		t.Errorf("piped stderr contains a carriage return: %q", errOut)
	}
	if !strings.Contains(errOut, "ok") {
		t.Errorf("piped stderr missing compact per-host lines: %q", errOut)
	}
}

// TestBatchSilentStderrEmpty verifies --silent suppresses both the bar and the
// compact lines.
func TestBatchSilentStderrEmpty(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := batchTestServer(t)

	o := scanOptions{dbPath: dbPath, threads: 4, format: "table", silent: true, noIntel: true, jobs: 2}
	errOut := captureStderr(t, func() {
		captureStdout(t, func() {
			runMulti([]string{wpSrv.URL, clean.URL}, o)
		})
	})
	if errOut != "" {
		t.Errorf("silent stderr = %q, want empty", errOut)
	}
}

// TestBatchProgressTTYRender forces TTY rendering and checks the live bar and
// the compact completion line.
func TestBatchProgressTTYRender(t *testing.T) {
	old := batchIsTTY
	batchIsTTY = func(io.Writer) bool { return true }
	defer func() { batchIsTTY = old }()

	var buf bytes.Buffer
	p := newBatchProgress(&buf, false, 3, time.Now())
	p.hostDone(1, batchResult{
		target: "http://example.com/",
		host:   "example.com",
		ok:     true,
		res: &scanner.Result{Findings: []scanner.Finding{{
			Slug:            "elementor",
			Vulnerabilities: []scanner.Vulnerability{{Rating: "critical"}},
		}}},
		dur: 12300 * time.Millisecond,
	})
	out := buf.String()
	if !strings.Contains(out, "\r") {
		t.Errorf("TTY output has no carriage-return progress: %q", out)
	}
	if !strings.Contains(out, "[#") && !strings.Contains(out, "[---") {
		t.Errorf("TTY output has no bar: %q", out)
	}
	if !strings.Contains(out, "[1/3] example.com  ok  1 findings (1 critical)  12.3s") {
		t.Errorf("compact line missing/incorrect: %q", out)
	}
}

// TestBatchInputAliasParses verifies --input is accepted as an alias for -T.
func TestBatchInputAliasParses(t *testing.T) {
	tf := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(tf, []byte("# comment\nhttp://a.test\nhttp://b.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, o := parseScanArgs([]string{"--input", tf})
	if o.targetsFile != tf {
		t.Fatalf("targetsFile = %q, want %q", o.targetsFile, tf)
	}
	if len(o.targets) != 2 || o.targets[0] != "http://a.test" || o.targets[1] != "http://b.test" {
		t.Fatalf("targets from --input = %v, want [http://a.test http://b.test]", o.targets)
	}
}
