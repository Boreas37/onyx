package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/nuclei"
	"github.com/Boreas37/onyx/internal/scanner"
)

// emptyDB writes a valid-but-empty feed file.
func emptyDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseScanArgsNewFlags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--user-agent", "my-ua",
		"--random-user-agent",
		"--detection-mode", "Passive",
		"--format", "jsonl",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.userAgent != "my-ua" {
		t.Errorf("userAgent = %q, want my-ua", o.userAgent)
	}
	if !o.randomUA {
		t.Error("randomUA = false, want true")
	}
	if o.detectionMode != "passive" {
		t.Errorf("detectionMode = %q, want passive", o.detectionMode)
	}
	if o.format != "jsonl" {
		t.Errorf("format = %q, want jsonl", o.format)
	}
}

func TestJSONFlagAliasesFormatJSON(t *testing.T) {
	target, o := parseScanArgs([]string{"--json", "http://example.test"})
	if target != "http://example.test" || o.format != "json" {
		t.Errorf("--json: target=%q format=%q, want http://example.test/json", target, o.format)
	}

	_, o = parseScanArgs([]string{})
	if o.format != "table" {
		t.Errorf("default format = %q, want table", o.format)
	}
}

func TestParseScanArgsPart2Flags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--proxy", "http://127.0.0.1:8080",
		"--no-xmlrpc",
		"--check", "CB,dbe",
		"--connect-timeout", "5",
		"--request-timeout", "30",
		"--wp-content-dir", "custom-content",
		"--wp-plugins-dir", "custom-plugins",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.proxy != "http://127.0.0.1:8080" {
		t.Errorf("proxy = %q", o.proxy)
	}
	if !o.noXMLRPC {
		t.Error("noXMLRPC = false, want true")
	}
	if o.checks != "cb,dbe" {
		t.Errorf("checks = %q, want cb,dbe", o.checks)
	}
	if o.connectTimeout != 5 {
		t.Errorf("connectTimeout = %d, want 5", o.connectTimeout)
	}
	if o.requestTimeout != 30 {
		t.Errorf("requestTimeout = %d, want 30", o.requestTimeout)
	}
	if o.contentDir != "custom-content" {
		t.Errorf("contentDir = %q, want custom-content", o.contentDir)
	}
	if o.pluginsDir != "custom-plugins" {
		t.Errorf("pluginsDir = %q, want custom-plugins", o.pluginsDir)
	}
}

func TestParseScanArgsPart2Defaults(t *testing.T) {
	_, o := parseScanArgs([]string{"http://example.test"})
	if o.connectTimeout != 10 {
		t.Errorf("default connectTimeout = %d, want 10", o.connectTimeout)
	}
	if o.requestTimeout != 0 {
		t.Errorf("default requestTimeout = %d, want 0 (falls back to --timeout)", o.requestTimeout)
	}
	if o.contentDir != "wp-content" {
		t.Errorf("default contentDir = %q, want wp-content", o.contentDir)
	}
	if o.pluginsDir != "wp-content/plugins" {
		t.Errorf("default pluginsDir = %q, want wp-content/plugins", o.pluginsDir)
	}
	if o.checks != "" || o.proxy != "" {
		t.Errorf("defaults: checks=%q proxy=%q, want empty", o.checks, o.proxy)
	}
	if o.noXMLRPC {
		t.Error("default noXMLRPC = true, want false")
	}
}

func TestTimeoutFlagAliasesRequestTimeout(t *testing.T) {
	_, o := parseScanArgs([]string{"--timeout", "20", "http://example.test"})
	if o.timeout != 20 || o.requestTimeout != 0 {
		t.Errorf("--timeout: timeout=%d requestTimeout=%d, want 20/0", o.timeout, o.requestTimeout)
	}
}

func TestParseScanArgsPart3Flags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--exclude-content-based", "Access Denied",
		"--scope", `^https://example\.com`,
		"--no-update-check",
		"--enumerate", "m",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.excludeContentBased != "Access Denied" {
		t.Errorf("excludeContentBased = %q, want Access Denied", o.excludeContentBased)
	}
	if o.scope != `^https://example\.com` {
		t.Errorf("scope = %q", o.scope)
	}
	if !o.noUpdateCheck {
		t.Error("noUpdateCheck = false, want true")
	}
	if o.enumerate != "m" {
		t.Errorf("enumerate = %q, want m", o.enumerate)
	}
}

func TestEnumerateMediaModeAllowed(t *testing.T) {
	target, o := parseScanArgs([]string{"http://example.test", "--enumerate", "ptum"})
	if target != "http://example.test" || o.enumerate != "ptum" {
		t.Errorf("--enumerate ptum: target=%q enumerate=%q", target, o.enumerate)
	}
}

// staticSite serves a non-WordPress page (scan exits 0, quick to run).
func staticSite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>static</body></html>"))
	}))
}

func TestRunScanOutOfScopeExitCode(t *testing.T) {
	srv := staticSite()
	defer srv.Close()

	opts := scanOptions{dbPath: emptyDB(t), scope: `^https://allowed\.example/`, silent: true}
	if code := runScan(srv.URL, opts); code != 2 {
		t.Errorf("out-of-scope exit code = %d, want 2", code)
	}
}

func TestRunScanExcludeContentBasedExitCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><h1>Access Denied</h1></body></html>`))
	}))
	defer srv.Close()

	opts := scanOptions{dbPath: emptyDB(t), excludeContentBased: `Access Denied`, silent: true}
	if code := runScan(srv.URL, opts); code != 2 {
		t.Errorf("exclude-content-based exit code = %d, want 2", code)
	}
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// everything written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out)
}

// staleDatabase writes an empty DB whose mtime is 21 days in the past.
func staleDatabase(t *testing.T) string {
	t.Helper()
	path := emptyDB(t)
	old := time.Now().AddDate(0, 0, -21)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStaleDatabaseWarning(t *testing.T) {
	path := staleDatabase(t)
	srv := staticSite()
	defer srv.Close()

	out := captureStderr(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: path, silent: true, format: "json"}); code != 0 {
			t.Errorf("exit code = %d, want 0 (warning is informational)", code)
		}
	})
	want := fmt.Sprintf("[WARN] database is %d days old — run 'onyx update' for fresh data",
		int(time.Since(mustModTime(t, path)).Hours()/24))
	if !strings.Contains(out, want) {
		t.Errorf("stderr = %q, want %q", out, want)
	}
}

func TestNoUpdateCheckSuppressesStaleWarning(t *testing.T) {
	path := staleDatabase(t)
	srv := staticSite()
	defer srv.Close()

	out := captureStderr(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: path, noUpdateCheck: true, silent: true, format: "json"}); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if strings.Contains(out, "[WARN] database is") {
		t.Errorf("stale warning printed despite --no-update-check: %q", out)
	}
}

func TestFreshDatabaseNoWarning(t *testing.T) {
	srv := staticSite()
	defer srv.Close()

	out := captureStderr(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: emptyDB(t), silent: true, format: "json"}); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	})
	if strings.Contains(out, "[WARN] database is") {
		t.Errorf("stale warning printed for a fresh database: %q", out)
	}
}

func mustModTime(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

func TestScanExitCodes(t *testing.T) {
	someRes := &scanner.Result{IsWordPress: true}
	findings := &scanner.Result{Findings: []scanner.Finding{{Slug: "x"}}}
	cases := []struct {
		name string
		res  *scanner.Result
		err  error
		want int
	}{
		{"clean scan", someRes, nil, 0},
		{"not wordpress", &scanner.Result{IsWordPress: false}, scanner.ErrNotWordPress, 0},
		{"findings", findings, nil, 5},
		{"nuclei only", &scanner.Result{Nuclei: []nuclei.NucleiResult{{TemplateID: "x"}}}, nil, 5},
		{"network failure", nil, scanner.ErrNotWordPress, 2},
	}
	for _, c := range cases {
		if got := scanExitCode(c.res, c.err); got != c.want {
			t.Errorf("%s: scanExitCode = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestRunScanInvalidTargetExitCode(t *testing.T) {
	code := runScan("not a url", scanOptions{dbPath: emptyDB(t)})
	if code != 2 {
		t.Errorf("invalid URL exit code = %d, want 2", code)
	}
}

func TestRunScanNonWordPressExitCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>static</body></html>"))
	}))
	defer srv.Close()

	code := runScan(srv.URL, scanOptions{dbPath: emptyDB(t)})
	if code != 0 {
		t.Errorf("non-WordPress exit code = %d, want 0", code)
	}
}

// TestRunScanFatalFetchExitCode verifies a fetch failure (dead proxy, no
// listener) exits 2 with a "cannot reach target" error instead of a false
// "not WordPress" result.
func TestRunScanFatalFetchExitCode(t *testing.T) {
	out := captureStderr(t, func() {
		if code := runScan("http://example.test", scanOptions{
			dbPath: emptyDB(t),
			proxy:  "http://127.0.0.1:1",
			silent: true,
		}); code != 2 {
			t.Errorf("dead-proxy exit code = %d, want 2", code)
		}
	})
	if !strings.Contains(out, "cannot reach target") {
		t.Errorf("stderr = %q, want contains %q", out, "cannot reach target")
	}
}

func TestRunScanFindingsExitCode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><link rel="https://api.w.org/" href="/wp-json/" /></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.24.0\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	feed := map[string]any{
		"aaaaaaaa-0000-0000-0000-000000000001": map[string]any{
			"id":    "aaaaaaaa-0000-0000-0000-000000000001",
			"title": "Elementor < 3.25.0 - SQL Injection",
			"software": []any{map[string]any{
				"type": "plugin", "name": "Elementor", "slug": "elementor",
				"affected_versions": map[string]any{
					"1.0.0 - 3.24.9": map[string]any{
						"from_version": "1.0.0", "from_inclusive": true,
						"to_version": "3.24.9", "to_inclusive": true,
					},
				},
			}},
		},
	}
	path := filepath.Join(t.TempDir(), "feed.json")
	data, _ := json.Marshal(feed)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	code := runScan(srv.URL, scanOptions{dbPath: path, silent: true})
	if code != 5 {
		t.Errorf("findings exit code = %d, want 5", code)
	}
}

// TestNucleiPipelineVerification drives the whole --nuclei pipeline with a
// mock nuclei binary and a template directory in t.TempDir: minimal
// findings with CVE ids resolve to templates, nuclei is invoked once, and
// every match lands in res.Nuclei.
func TestNucleiPipelineVerification(t *testing.T) {
	tmp := t.TempDir()

	templateDir := filepath.Join(tmp, "templates")
	tpl := filepath.Join(templateDir, "http", "cves", "2026", "CVE-2026-8081.yaml")
	if err := os.MkdirAll(filepath.Dir(tpl), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tpl, []byte("id: CVE-2026-8081\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := filepath.Join(tmp, "nuclei-mock")
	script := `#!/bin/sh
printf '%s\n' '{"template-id":"CVE-2026-8081","info":{"name":"Elementor File Read","severity":"critical"},"matched-at":"https://host/wp-admin/","matcher-name":"y-word"}'
`
	if err := os.WriteFile(mock, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_BIN", mock)

	res := &scanner.Result{
		Target:      "https://host/",
		IsWordPress: true,
		Findings: []scanner.Finding{
			{Slug: "elementor", Type: "plugin", InstalledVersion: "3.24.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: "CVE-2026-8081"},
					{CVE: "CVE-2026-8081"}, // duplicate — must be collected once
				}},
			{Slug: "akismet", Type: "plugin", InstalledVersion: "4.0.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: ""}, // no CVE id — must be skipped
				}},
		},
	}

	verifyWithNuclei(res, scanOptions{nuclei: true, nucleiTemplateDir: templateDir, nucleiArgs: `-H "X-Api-Key: x"`})

	if len(res.Nuclei) != 1 {
		t.Fatalf("len(res.Nuclei) = %d, want 1: %+v", len(res.Nuclei), res.Nuclei)
	}
	got := res.Nuclei[0]
	if got.TemplateID != "CVE-2026-8081" || got.CVE != "CVE-2026-8081" {
		t.Errorf("TemplateID/CVE = %q/%q, want CVE-2026-8081", got.TemplateID, got.CVE)
	}
	if got.Severity != "critical" || got.Name != "Elementor File Read" {
		t.Errorf("Severity/Name = %q/%q", got.Severity, got.Name)
	}
	if got.MatchedAt != "https://host/wp-admin/" || got.MatcherName != "y-word" {
		t.Errorf("MatchedAt/MatcherName = %q/%q", got.MatchedAt, got.MatcherName)
	}
}

// TestNucleiMissingBinaryWarns verifies the soft-fail path: no nuclei
// binary anywhere → WARN on stderr, res.Nuclei untouched, no error.
func TestNucleiMissingBinaryWarns(t *testing.T) {
	t.Setenv("NUCLEI_BIN", "")
	t.Setenv("PATH", filepath.Dir(t.TempDir()))

	res := &scanner.Result{
		Target:   "https://host/",
		Findings: []scanner.Finding{{Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2026-8081"}}}},
	}
	out := captureStderr(t, func() {
		verifyWithNuclei(res, scanOptions{nuclei: true, nucleiTemplateDir: t.TempDir()})
	})
	if len(res.Nuclei) != 0 {
		t.Errorf("res.Nuclei = %+v, want empty on soft fail", res.Nuclei)
	}
	if !strings.Contains(out, "[WARN] nuclei not found in PATH — skipping verification") {
		t.Errorf("stderr = %q, want nuclei-not-found WARN", out)
	}
}

// TestNucleiMissingTemplateWarns verifies the per-CVE soft fail: no
// matching template file → WARN, other CVEs still verified.
func TestNucleiMissingTemplateWarns(t *testing.T) {
	mock := filepath.Join(t.TempDir(), "nuclei-mock")
	if err := os.WriteFile(mock, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_BIN", mock)

	res := &scanner.Result{
		Target:   "https://host/",
		Findings: []scanner.Finding{{Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2026-8081"}}}},
	}
	out := captureStderr(t, func() {
		verifyWithNuclei(res, scanOptions{nuclei: true, nucleiTemplateDir: t.TempDir()})
	})
	if len(res.Nuclei) != 0 {
		t.Errorf("res.Nuclei = %+v, want empty when no template resolves", res.Nuclei)
	}
	if !strings.Contains(out, "[WARN] no nuclei template for CVE-2026-8081") {
		t.Errorf("stderr = %q, want no-template WARN", out)
	}
}
