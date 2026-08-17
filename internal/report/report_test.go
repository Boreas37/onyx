package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

// sampleResult builds a small Result with two findings for output tests.
func sampleResult() *scanner.Result {
	return &scanner.Result{
		Target:      "https://example.test",
		IsWordPress: true,
		Findings: []scanner.Finding{
			{
				Slug: "elementor", Name: "Elementor", Type: "plugin", InstalledVersion: "3.24.0",
				Vulnerabilities: []scanner.Vulnerability{
					{ID: "aaaaaaaa-0000-0000-0000-000000000001", CVE: "CVE-2024-0001",
						Title: "Elementor < 3.25.0 - SQL Injection", CVSSScore: 9.1, Rating: "critical"},
				},
			},
			{
				Slug: "akismet", Name: "Akismet", Type: "plugin", InstalledVersion: "4.0.0",
				Vulnerabilities: []scanner.Vulnerability{
					{ID: "bbbbbbbb-0000-0000-0000-000000000002", CVE: "CVE-2024-0002",
						Title: "Akismet < 5.0 - Stored XSS", CVSSScore: 6.1, Rating: "medium"},
				},
			},
		},
	}
}

// captureStdout runs fn with stdout redirected to a pipe and returns what
// was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestPrintTableShowsXMLRPCWhenEnabled(t *testing.T) {
	res := sampleResult()
	res.XMLRPC = true
	out := captureStdout(t, func() { PrintTable(res, false, "") })
	if !strings.Contains(out, "XML-RPC: enabled") {
		t.Errorf("table output missing XML-RPC line:\n%s", out)
	}
}

func TestPrintTableOmitsXMLRPCWhenDisabled(t *testing.T) {
	out := captureStdout(t, func() { PrintTable(sampleResult(), false, "") })
	if strings.Contains(out, "XML-RPC") {
		t.Errorf("table output should not mention XML-RPC when disabled:\n%s", out)
	}
}

func TestPrintTableShowsValidCredentials(t *testing.T) {
	res := sampleResult()
	res.LoginBrutes = []scanner.LoginBrute{
		{User: "admin", Password: "hunter2", URL: "https://example.test/wp-login.php"},
	}
	out := captureStdout(t, func() { PrintTable(res, false, "") })
	if !strings.Contains(out, "Valid credentials:") {
		t.Errorf("table output missing Valid credentials section:\n%s", out)
	}
	if !strings.Contains(out, "admin:hunter2") {
		t.Errorf("table output missing credential pair:\n%s", out)
	}
}

func TestPrintTableShowsAuthStatus(t *testing.T) {
	res := sampleResult()
	res.AuthStatus = "authenticated"
	out := captureStdout(t, func() { PrintTable(res, false, "") })
	if !strings.Contains(out, "REST auth: authenticated") {
		t.Errorf("table output missing auth status:\n%s", out)
	}
}

func TestPrintJSONLWritesOneLinePerFinding(t *testing.T) {
	out := captureStdout(t, func() { PrintJSONL(sampleResult()) })

	sc := bufio.NewScanner(strings.NewReader(out))
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d: %q", len(lines), out)
	}
	for i, ln := range lines {
		var f scanner.Finding
		if err := json.Unmarshal([]byte(ln), &f); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if f.Slug == "" {
			t.Fatalf("line %d missing slug: %s", i, ln)
		}
	}
}

func TestPrintSARIFMinimalStructure(t *testing.T) {
	out := captureStdout(t, func() { PrintSARIF("0.1.0", sampleResult()) })

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif output is not valid JSON: %v\n%s", err, out)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "onyx" {
		t.Errorf("driver name = %q, want onyx", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver version = %q, want 0.1.0", run.Tool.Driver.Version)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "CVE-2024-0001" || run.Results[0].Level != "error" {
		t.Errorf("result[0] = %+v, want CVE-2024-0001/error", run.Results[0])
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("result[1] level = %q, want warning", run.Results[1].Level)
	}
}

// TestPrintCSVQuotesCommasAndRowsPerVulnerability verifies --format csv:
// one row per vulnerability (not per finding), the header columns, and
// encoding/csv quoting for titles containing commas.
func TestPrintCSVQuotesCommasAndRowsPerVulnerability(t *testing.T) {
	res := &scanner.Result{
		IsWordPress: true,
		Findings: []scanner.Finding{
			{
				Slug: "elementor", Type: "plugin", InstalledVersion: "3.24.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: "CVE-2024-0001", Rating: "critical",
						Title:          "Elementor, Website Builder < 3.25.0 - SQL Injection",
						AffectedLabels: []string{"1.0.0 - 3.24.9"}},
					{CVE: "CVE-2024-0002", Rating: "high",
						Title:          "Elementor < 3.24.0 - Stored XSS",
						AffectedLabels: []string{"1.0.0 - 3.23.9", "1.0.0 - 3.22.4"}},
				},
			},
		},
	}
	out := captureStdout(t, func() { PrintCSV(res) })

	if !strings.Contains(out, `"Elementor, Website Builder < 3.25.0 - SQL Injection"`) {
		t.Errorf("csv output must quote the comma-containing title:\n%s", out)
	}

	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv output is not parseable: %v\n%s", err, out)
	}
	wantHeader := []string{"slug", "type", "installed_version", "cve", "severity", "title", "affected_versions"}
	if len(recs) != 3 {
		t.Fatalf("expected header + 2 rows (one per vulnerability), got %d records: %v", len(recs), recs)
	}
	for i := range wantHeader {
		if recs[0][i] != wantHeader[i] {
			t.Errorf("header[%d] = %q, want %q", i, recs[0][i], wantHeader[i])
		}
	}
	if recs[1][0] != "elementor" || recs[1][1] != "plugin" || recs[1][2] != "3.24.0" {
		t.Errorf("row 1 component columns = %v, want elementor/plugin/3.24.0", recs[1][:3])
	}
	if recs[1][3] != "CVE-2024-0001" || recs[1][4] != "critical" {
		t.Errorf("row 1 cve/severity = %v, want CVE-2024-0001/critical", recs[1][3:5])
	}
	if recs[1][5] != "Elementor, Website Builder < 3.25.0 - SQL Injection" {
		t.Errorf("row 1 title = %q, comma value must round-trip", recs[1][5])
	}
	if recs[1][6] != "1.0.0 - 3.24.9" {
		t.Errorf("row 1 affected_versions = %q, want 1.0.0 - 3.24.9", recs[1][6])
	}
	if recs[2][3] != "CVE-2024-0002" || recs[2][5] != "Elementor < 3.24.0 - Stored XSS" {
		t.Errorf("row 2 = %v, want the second vulnerability", recs[2])
	}
}

// TestCliNoColourSuppressesANSI verifies the cli-no-colour behavior: with
// NoColor set the table never emits ESC (ANSI) codes even when stdout
// looks like a terminal (useColor forced on).
func TestCliNoColourSuppressesANSI(t *testing.T) {
	oldColor, oldNoColor := useColor, NoColor
	t.Cleanup(func() { useColor, NoColor = oldColor, oldNoColor })

	useColor = true
	NoColor = false
	colorOut := captureStdout(t, func() { PrintTable(sampleResult(), false, "") })
	if !strings.Contains(colorOut, "\x1b[") {
		t.Fatalf("sanity: with ANSI enabled the table must carry escape codes:\n%s", colorOut)
	}

	NoColor = true
	plainOut := captureStdout(t, func() { PrintTable(sampleResult(), false, "") })
	if strings.Contains(plainOut, "\x1b") {
		t.Errorf("cli-no-colour output must contain 0 ESC characters, got:\n%s", plainOut)
	}
}

// TestPrintSummarySection verifies the exact summary layout of the spec,
// including the rate-limited note and the severity breakdown.
func TestPrintSummarySection(t *testing.T) {
	res := sampleResult()
	res.Summary = &scanner.Summary{
		DurationMS: 42300, Requests: 512, RateLimited: 42,
		Detected: 2, Findings: 104, Critical: 2, High: 7, Medium: 95, Users: 3,
	}
	out := captureStdout(t, func() { PrintSummary(res) })
	for _, want := range []string{
		"Scan summary:",
		"  Duration:    42.3s",
		"  Requests:    512 (42 rate-limited)",
		"  Detected:    2 components",
		"  Findings:    104 vulnerabilities (2 critical, 7 high, 95 medium)",
		"  Users found: 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary output missing %q:\n%s", want, out)
		}
	}
}

// TestPrintSummaryOmitsZeroSeveritiesAndRateLimit verifies the compact
// summary lines: no rate-limited note and no severity breakdown when the
// counters are zero.
func TestPrintSummaryOmitsZeroSeveritiesAndRateLimit(t *testing.T) {
	res := sampleResult()
	res.Summary = &scanner.Summary{
		DurationMS: 1500, Requests: 4, Detected: 1, Findings: 1, Critical: 1,
	}
	out := captureStdout(t, func() { PrintSummary(res) })
	if strings.Contains(out, "rate-limited") {
		t.Errorf("no rate-limited note expected when RateLimited is 0:\n%s", out)
	}
	if !strings.Contains(out, "  Duration:    1.5s") {
		t.Errorf("duration line missing:\n%s", out)
	}
	if !strings.Contains(out, "  Requests:    4\n") {
		t.Errorf("requests line missing:\n%s", out)
	}
	if !strings.Contains(out, "  Findings:    1 vulnerabilities (1 critical)") {
		t.Errorf("findings line missing:\n%s", out)
	}
	if !strings.Contains(out, "\n  Users found: 0") {
		t.Errorf("users line missing:\n%s", out)
	}
}

// TestPrintSummaryNilSummaryPrintsNothing verifies a scan without summary
// statistics prints no summary section.
func TestPrintSummaryNilSummaryPrintsNothing(t *testing.T) {
	out := captureStdout(t, func() { PrintSummary(sampleResult()) })
	if out != "" {
		t.Errorf("nil summary must print nothing, got:\n%s", out)
	}
}
