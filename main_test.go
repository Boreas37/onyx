package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/dbupdate"
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

func TestParseScanArgsExploitFlags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--passwords", "pw.txt",
		"--usernames", "users.txt",
		"--user", "admin",
		"--xmlrpc-brute", "xpw.txt",
		"--multicall-max-passwords", "5",
		"--wp-auth", "superadmin:password",
		"--no-brute",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.passwordsFile != "pw.txt" || o.usernamesFile != "users.txt" {
		t.Errorf("wordlists = %q/%q, want pw.txt/users.txt", o.passwordsFile, o.usernamesFile)
	}
	if o.user != "admin" {
		t.Errorf("user = %q, want admin", o.user)
	}
	if o.xmlrpcBrute != "xpw.txt" {
		t.Errorf("xmlrpcBrute = %q, want xpw.txt", o.xmlrpcBrute)
	}
	if o.mcMaxPasswords != 5 {
		t.Errorf("mcMaxPasswords = %d, want 5", o.mcMaxPasswords)
	}
	if o.wpAuth != "superadmin:password" {
		t.Errorf("wpAuth = %q, want superadmin:password", o.wpAuth)
	}
	if !o.noBrute {
		t.Error("noBrute = false, want true")
	}
}

func TestParseScanArgsExploitFlagDefaults(t *testing.T) {
	_, o := parseScanArgs([]string{"http://example.test"})
	if o.passwordsFile != "" || o.usernamesFile != "" || o.user != "" || o.xmlrpcBrute != "" || o.wpAuth != "" {
		t.Errorf("defaults must be empty: %+v", o)
	}
	if o.noBrute {
		t.Error("default noBrute = true, want false")
	}
	if o.mcMaxPasswords != 0 {
		t.Errorf("default mcMaxPasswords = %d, want 0 (scanner falls back to 3)", o.mcMaxPasswords)
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

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written to it.
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
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out)
}

// gzBytes compresses data into a gzip payload, mimicking the production
// feed asset.
func gzBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// feedServer serves the given payload for every request.
func feedServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
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
	want := fmt.Sprintf("[WARN] database is %d days old (production feed) — run 'onyx update' for fresh data",
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
	findings := &scanner.Result{Findings: []scanner.Finding{{
		Slug: "x",
		Vulnerabilities: []scanner.Vulnerability{
			{CVE: "CVE-2026-0001", Rating: "medium"},
			{CVE: "CVE-2026-0002", Rating: "low"},
		},
	}}}
	high := &scanner.Result{Findings: []scanner.Finding{{
		Slug:            "y",
		Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2026-0003", Rating: "High"}},
	}}}
	notWP := &scanner.Result{IsWordPress: false}
	cases := []struct {
		name     string
		res      *scanner.Result
		err      error
		strictWP bool
		failOn   string
		want     int
	}{
		{"clean scan", someRes, nil, false, "", 0},
		{"not wordpress", notWP, scanner.ErrNotWordPress, false, "", 0},
		{"not wordpress strict", notWP, scanner.ErrNotWordPress, true, "", 3},
		{"findings", findings, nil, false, "", 5},
		{"fail-on below max", findings, nil, false, "high", 0},
		{"fail-on at max", findings, nil, false, "medium", 5},
		{"fail-on low catches all", findings, nil, false, "low", 5},
		{"high finding passes gate", high, nil, false, "high", 5},
		{"nuclei only", &scanner.Result{Nuclei: []nuclei.NucleiResult{{TemplateID: "x"}}}, nil, false, "high", 5},
		{"network failure", nil, scanner.ErrNotWordPress, true, "", 2},
	}
	for _, c := range cases {
		if got := scanExitCode(c.res, c.err, c.strictWP, c.failOn, false); got != c.want {
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

func TestParseScanArgsPocFlags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--poc-tracker-dir", "/srv/tracker",
		"--no-pocs",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.pocTrackerDir != "/srv/tracker" {
		t.Errorf("pocTrackerDir = %q, want /srv/tracker", o.pocTrackerDir)
	}
	if !o.noPocs {
		t.Error("noPocs = false, want true")
	}

	_, o = parseScanArgs([]string{"http://example.test"})
	if o.pocTrackerDir != "" || o.noPocs {
		t.Errorf("defaults: pocTrackerDir=%q noPocs=%v, want empty/false", o.pocTrackerDir, o.noPocs)
	}
}

// TestCollectPoCsSoftFails verifies the soft-fail behavior of the PoC
// pipeline: a missing tracker clone warns on stderr and leaves res.PoCs
// empty; a CVE absent from an existing tracker is skipped silently. No
// crash in either case.
func TestCollectPoCsSoftFails(t *testing.T) {
	res := &scanner.Result{
		Target:      "https://host/",
		IsWordPress: true,
		Nuclei: []nuclei.NucleiResult{
			{TemplateID: "CVE-2026-8081", CVE: "CVE-2026-8081", Severity: "critical"},
		},
	}

	missing := filepath.Join(t.TempDir(), "no-such-tracker")
	out := captureStderr(t, func() {
		collectPoCs(res, scanOptions{pocTrackerDir: missing})
	})
	if len(res.PoCs) != 0 {
		t.Errorf("res.PoCs = %+v, want empty when tracker is missing", res.PoCs)
	}
	wantWarn := fmt.Sprintf("[WARN] CVE-PoC-Tracker not found at %s — skipping PoC lookup", missing)
	if !strings.Contains(out, wantWarn) {
		t.Errorf("stderr = %q, want %q", out, wantWarn)
	}

	empty := t.TempDir()
	res.PoCs = nil
	out = captureStderr(t, func() {
		collectPoCs(res, scanOptions{pocTrackerDir: empty})
	})
	if len(res.PoCs) != 0 {
		t.Errorf("res.PoCs = %+v, want empty when CVE file is absent", res.PoCs)
	}
	if strings.Contains(out, "[WARN]") {
		t.Errorf("stderr = %q, want no WARN for a CVE missing from the tracker", out)
	}
}

func TestParseScanArgsWAFFlags(t *testing.T) {
	target, o := parseScanArgs([]string{
		"http://example.test",
		"--proxy", "socks5://127.0.0.1:1080",
		"--proxy-auth", "user:pass",
		"--proxy-target-only",
		"--tls-fingerprint", "Chrome",
		"--per-host-rate-limit", "7.5",
	})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://127.0.0.1:1080", o.proxy)
	}
	if o.proxyAuth != "user:pass" {
		t.Errorf("proxyAuth = %q, want user:pass", o.proxyAuth)
	}
	if !o.proxyTargetOnly {
		t.Error("proxyTargetOnly = false, want true")
	}
	if o.tlsFingerprint != "chrome" {
		t.Errorf("tlsFingerprint = %q, want chrome (lowercased)", o.tlsFingerprint)
	}
	if o.perHostRateLimit != 7.5 {
		t.Errorf("perHostRateLimit = %v, want 7.5", o.perHostRateLimit)
	}

	_, o = parseScanArgs([]string{"http://example.test"})
	if o.proxyAuth != "" || o.tlsFingerprint != "" || o.perHostRateLimit != 0 || o.proxyTargetOnly {
		t.Errorf("defaults must be empty/false/0: %+v", o)
	}

	// A non-numeric or non-positive per-host rate falls back to 0.
	for _, bad := range []string{"abc", "0", "-3"} {
		_, o = parseScanArgs([]string{"http://example.test", "--per-host-rate-limit", bad})
		if o.perHostRateLimit != 0 {
			t.Errorf("--per-host-rate-limit %q: got %v, want 0", bad, o.perHostRateLimit)
		}
	}
}

func TestParseScanArgsNoUpdateFlag(t *testing.T) {
	_, o := parseScanArgs([]string{"http://example.test", "--no-update"})
	if !o.noUpdate {
		t.Error("noUpdate = false, want true")
	}
	_, o = parseScanArgs([]string{"http://example.test"})
	if o.noUpdate {
		t.Error("default noUpdate = true, want false")
	}
}

func TestRunScanNoUpdateMissingDBExits2(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	out := captureStderr(t, func() {
		if code := runScan("http://example.test", scanOptions{dbPath: missing, noUpdate: true, silent: true}); code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
	})
	if !strings.Contains(out, "not found") {
		t.Errorf("stderr = %q, want a database-not-found error", out)
	}
	if strings.Contains(out, "fetching it first") {
		t.Errorf("stderr = %q, --no-update must not auto-download", out)
	}
}

func TestUpdateIncrementalChecksumNoOp(t *testing.T) {
	payload := []byte(`{"11111111-0000-0000-0000-000000000001":{"id":"11111111-0000-0000-0000-000000000001","title":"Elementor < 3.25.0"}}`)
	gz := gzBytes(t, payload)
	srv := feedServer(t, gz)
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "feed.json")
	if err := updateFromURL(dst, srv.URL, true, feedProduction, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("database = %s, want gunzipped payload %s", got, payload)
	}
	side, err := os.ReadFile(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256Hex(gz); strings.TrimSpace(string(side)) != want {
		t.Errorf("sha256 sidecar = %q, want %q", side, want)
	}
	ft, err := os.ReadFile(dst + ".feedtype")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(ft)) != feedProduction {
		t.Errorf("feedtype sidecar = %q, want %q", ft, feedProduction)
	}

	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	sideBefore, err := os.Stat(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := updateFromURL(dst, srv.URL, true, feedProduction, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "already up to date") {
		t.Errorf("stdout = %q, want an \"already up to date\" message", out)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Errorf("database rewritten on no-op: before %v after %v", before.ModTime(), after.ModTime())
	}
	sideAfter, err := os.Stat(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if !sideAfter.ModTime().Equal(sideBefore.ModTime()) {
		t.Errorf("sha256 sidecar rewritten on no-op")
	}
}

func TestUpdateChecksumChangedRewrites(t *testing.T) {
	payload := []byte(`{"1":"one"}`)
	gz := gzBytes(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gz)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "feed.json")
	if err := updateFromURL(dst, srv.URL, true, feedProduction, false); err != nil {
		t.Fatal(err)
	}

	// The feed changes upstream: a different gzip body.
	newPayload := []byte(`{"1":"two"}`)
	newGz := gzBytes(t, newPayload)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newGz)
	})

	out := captureStdout(t, func() {
		if err := updateFromURL(dst, srv.URL, true, feedProduction, false); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "already up to date") {
		t.Errorf("stdout = %q, changed feed must not be a no-op", out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newPayload) {
		t.Errorf("database = %s, want %s", got, newPayload)
	}
	side, err := os.ReadFile(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256Hex(newGz); strings.TrimSpace(string(side)) != want {
		t.Errorf("sha256 sidecar = %q, want %q", side, want)
	}
}

func TestUpdateForceAlwaysRewrites(t *testing.T) {
	payload := []byte(`{"1":"one"}`)
	gz := gzBytes(t, payload)
	srv := feedServer(t, gz)
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "feed.json")
	if err := updateFromURL(dst, srv.URL, true, feedProduction, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	out := captureStdout(t, func() {
		if err := updateFromURL(dst, srv.URL, true, feedProduction, true); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "already up to date") {
		t.Errorf("stdout = %q, --force must skip the checksum check", out)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().After(before.ModTime()) {
		t.Errorf("--force should rewrite the database (mtime %v -> %v)", before.ModTime(), after.ModTime())
	}
}

func TestUpdateScannerFeedPlainJSON(t *testing.T) {
	payload := []byte(`{"11111111-0000-0000-0000-000000000001":{"id":"11111111-0000-0000-0000-000000000001","title":"Elementor < 3.25.0"}}`)
	srv := feedServer(t, payload)
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "wordfence-scanner.json")
	if err := updateFromURL(dst, srv.URL, false, feedScanner, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("database = %s, want the served JSON payload", got)
	}
	side, err := os.ReadFile(dst + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256Hex(payload); strings.TrimSpace(string(side)) != want {
		t.Errorf("sha256 sidecar = %q, want %q", side, want)
	}
	ft, err := os.ReadFile(dst + ".feedtype")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(ft)) != feedScanner {
		t.Errorf("feedtype sidecar = %q, want %q", ft, feedScanner)
	}
}

func TestUpdateRejectsUnknownFeed(t *testing.T) {
	if err := update("x.json", "scann3r", false); err == nil {
		t.Error("expected error for unknown feed")
	}
}

// TestStalenessWarningDownloadAgeAndFeedType verifies the richer staleness
// prompt: the age comes from the last download (the .sha256 sidecar mtime,
// not the database mtime) and the feed type is read from the .feedtype
// sidecar.
func TestStalenessWarningDownloadAgeAndFeedType(t *testing.T) {
	path := emptyDB(t) // fresh database mtime — must not drive the age
	side := path + ".sha256"
	if err := os.WriteFile(side, []byte("sum\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	download := time.Now().AddDate(0, 0, -30)
	if err := os.Chtimes(side, download, download); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".feedtype", []byte("scanner\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := staticSite()
	defer srv.Close()

	out := captureStderr(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: path, silent: true, format: "json"}); code != 0 {
			t.Errorf("exit code = %d, want 0 (warning is informational)", code)
		}
	})
	want := fmt.Sprintf("[WARN] database is %d days old (scanner feed) — run 'onyx update' for fresh data",
		int(time.Since(mustModTime(t, side)).Hours()/24))
	if !strings.Contains(out, want) {
		t.Errorf("stderr = %q, want %q", out, want)
	}
}

func TestFeedTypeSidecarDefaults(t *testing.T) {
	dir := t.TempDir()
	if got := dbFeedType(filepath.Join(dir, "db.json")); got != feedProduction {
		t.Errorf("missing sidecar: dbFeedType = %q, want production", got)
	}
	path := filepath.Join(dir, "db.json")
	if err := os.WriteFile(path+".feedtype", []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := dbFeedType(path); got != feedProduction {
		t.Errorf("unknown sidecar content: dbFeedType = %q, want production", got)
	}
}

func TestParseScanArgsOutputFlags(t *testing.T) {
	target, o := parseScanArgs([]string{"http://example.test", "--format", "csv", "--no-summary"})
	if target != "http://example.test" {
		t.Errorf("target = %q", target)
	}
	if o.format != "csv" {
		t.Errorf("format = %q, want csv", o.format)
	}
	if !o.noSummary {
		t.Error("noSummary = false, want true")
	}

	_, o = parseScanArgs([]string{"http://example.test", "--format", "cli-no-colour"})
	if o.format != "cli-no-colour" {
		t.Errorf("format = %q, want cli-no-colour", o.format)
	}

	_, o = parseScanArgs([]string{"http://example.test"})
	if o.noSummary {
		t.Error("default noSummary = true, want false")
	}
}

// elementorFeedDB writes a one-record feed (Elementor, critical) into
// t.TempDir and returns its path.
func elementorFeedDB(t *testing.T) string {
	t.Helper()
	feed := map[string]any{
		"aaaaaaaa-0000-0000-0000-000000000001": map[string]any{
			"id":    "aaaaaaaa-0000-0000-0000-000000000001",
			"title": "Elementor < 3.25.0 - SQL Injection",
			"cvss": map[string]any{
				"score":  9.1,
				"rating": "critical",
			},
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
	return path
}

// elementorSite serves a WordPress homepage plus a vulnerable readme.txt.
func elementorSite() *httptest.Server {
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
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.24.0\n"))
	})
	return httptest.NewServer(mux)
}

// TestRunScanJSONSummary verifies the JSON output carries a correctly
// populated "summary" object derived from the scan result.
func TestRunScanJSONSummary(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()

	var doc struct {
		Summary  *scanner.Summary   `json:"summary"`
		Findings []scanner.Finding  `json:"findings"`
		Detected []scanner.Detected `json:"detected"`
		Users    []scanner.User     `json:"users"`
	}
	out := captureStdout(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: elementorFeedDB(t), silent: true, format: "json"}); code != 5 {
			t.Errorf("exit code = %d, want 5", code)
		}
	})
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json output is not valid JSON: %v\n%s", err, out)
	}
	if doc.Summary == nil {
		t.Fatal("json output missing the summary field")
	}
	s := doc.Summary
	if s.Findings != len(doc.Findings) {
		t.Errorf("summary findings = %d, want %d", s.Findings, len(doc.Findings))
	}
	if s.Detected != len(doc.Detected) {
		t.Errorf("summary detected = %d, want %d", s.Detected, len(doc.Detected))
	}
	if s.Users != len(doc.Users) {
		t.Errorf("summary users = %d, want %d", s.Users, len(doc.Users))
	}
	if s.Requests < 1 {
		t.Errorf("summary requests = %d, want >= 1", s.Requests)
	}
	if s.RateLimited != 0 {
		t.Errorf("summary rate_limited = %d, want 0 (no 429s served)", s.RateLimited)
	}
	wantC, wantH, wantM, wantL := 0, 0, 0, 0
	for _, f := range doc.Findings {
		for _, v := range f.Vulnerabilities {
			switch strings.ToLower(v.Rating) {
			case "critical":
				wantC++
			case "high":
				wantH++
			case "medium":
				wantM++
			case "low":
				wantL++
			}
		}
	}
	if s.Critical != wantC || s.High != wantH || s.Medium != wantM || s.Low != wantL {
		t.Errorf("summary severities = %d/%d/%d/%d, want %d/%d/%d/%d",
			s.Critical, s.High, s.Medium, s.Low, wantC, wantH, wantM, wantL)
	}
	if s.DurationMS < 0 {
		t.Errorf("summary duration_ms = %d, want >= 0", s.DurationMS)
	}
}

// TestRunScanJSONNoSummary verifies --no-summary removes the summary field
// from the JSON output.
func TestRunScanJSONNoSummary(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()

	out := captureStdout(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: elementorFeedDB(t), silent: true, format: "json", noSummary: true}); code != 5 {
			t.Errorf("exit code = %d, want 5", code)
		}
	})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json output is not valid JSON: %v\n%s", err, out)
	}
	if _, ok := doc["summary"]; ok {
		t.Errorf("json output must omit the summary field with --no-summary:\n%s", out)
	}
}

// TestRunScanCSVOutput verifies --format csv prints the header + one row
// per vulnerability (exit code 5 for a finding), and that --output writes
// the same CSV to a file.
func TestRunScanCSVOutput(t *testing.T) {
	srv := elementorSite()
	defer srv.Close()

	out := captureStdout(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: elementorFeedDB(t), silent: true, format: "csv"}); code != 5 {
			t.Errorf("exit code = %d, want 5", code)
		}
	})
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv output is not parseable: %v\n%s", err, out)
	}
	if len(recs) != 2 {
		t.Fatalf("expected header + 1 row, got %d: %v", len(recs), recs)
	}
	if got := strings.Join(recs[0], ","); got != "slug,type,installed_version,cve,severity,title,affected_versions" {
		t.Errorf("csv header = %q", got)
	}
	if recs[1][0] != "elementor" || recs[1][4] != "critical" || recs[1][5] != "Elementor < 3.25.0 - SQL Injection" {
		t.Errorf("csv row = %v, want the elementor finding", recs[1])
	}

	dst := filepath.Join(t.TempDir(), "results.csv")
	captureStdout(t, func() {
		if code := runScan(srv.URL, scanOptions{dbPath: elementorFeedDB(t), silent: true, format: "csv", output: dst}); code != 5 {
			t.Errorf("exit code = %d, want 5", code)
		}
	})
	file, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading --output file: %v", err)
	}
	if !strings.HasPrefix(string(file), "slug,type,installed_version,cve,severity,title,affected_versions\n") {
		t.Errorf("--output csv file content = %q, want the CSV output", file)
	}
}

func TestVersionJSONValidAndFields(t *testing.T) {
	type vinfo struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
	}

	oldCommit, oldTime := buildCommit, buildTime
	buildCommit, buildTime = "abcdef", "2026-08-17T00:00:00Z"
	defer func() { buildCommit, buildTime = oldCommit, oldTime }()

	var got vinfo
	if err := json.Unmarshal([]byte(versionJSON()), &got); err != nil {
		t.Fatalf("version --json output is not valid JSON: %v", err)
	}
	if got.Version != onyxVersion {
		t.Errorf("version = %q, want %q", got.Version, onyxVersion)
	}
	if got.GoVersion == "" {
		t.Error("go_version is empty")
	}
	if got.OS != runtime.GOOS {
		t.Errorf("os = %q, want %q", got.OS, runtime.GOOS)
	}
	if got.Arch != runtime.GOARCH {
		t.Errorf("arch = %q, want %q", got.Arch, runtime.GOARCH)
	}
	if got.Commit != "abcdef" {
		t.Errorf("commit = %q, want abcdef", got.Commit)
	}
	if got.BuildTime != "2026-08-17T00:00:00Z" {
		t.Errorf("build_time = %q, want 2026-08-17T00:00:00Z", got.BuildTime)
	}
}

func TestVersionJSONUnknownMetadata(t *testing.T) {
	oldCommit, oldTime := buildCommit, buildTime
	buildCommit, buildTime = "", ""
	defer func() { buildCommit, buildTime = oldCommit, oldTime }()

	var got map[string]any
	if err := json.Unmarshal([]byte(versionJSON()), &got); err != nil {
		t.Fatalf("version --json output is not valid JSON: %v", err)
	}
	if got["commit"] != "unknown" {
		t.Errorf("commit = %v, want unknown (local build)", got["commit"])
	}
	if got["build_time"] != "unknown" {
		t.Errorf("build_time = %v, want unknown (local build)", got["build_time"])
	}
}

func TestVersionPlainKeepsFormat(t *testing.T) {
	if out := captureStdout(t, func() {
		oldArgs := os.Args
		os.Args = []string{"onyx", "version"}
		defer func() { os.Args = oldArgs }()
		main()
	}); out != "onyx "+onyxVersion+"\n" {
		t.Errorf("plain version output = %q, want %q", out, "onyx "+onyxVersion+"\n")
	}
}

// ---- updateViaDelta: manifest dedupe + freshness (downgrade) guard ----

// manifestDoc builds a minimal manifest.json body for the guard tests.
func manifestDoc(generatedAt, fullSHA string, deltas ...string) string {
	doc := fmt.Sprintf(`{"generated_at":%q,"full":{"sha256":%q,"size":1,"path":"f.json.gz"}`, generatedAt, fullSHA)
	if len(deltas) == 0 {
		return doc + `,"deltas":[]}`
	}
	entries := make([]string, 0, len(deltas))
	for _, sha := range deltas {
		entries = append(entries, fmt.Sprintf(`{"from_sha256":%q,"path":"delta-%s.json.gz","records":{"added":0,"removed":0,"updated":0,"result":0}}`, sha, sha))
	}
	return doc + fmt.Sprintf(`,"deltas":[%s]}`, strings.Join(entries, ","))
}

func TestDedupeManifestDeltas(t *testing.T) {
	m := &dbupdate.Manifest{Deltas: []dbupdate.DeltaEntry{
		{FromSha256: "aa", Path: "a.gz"},
		{FromSha256: "aa", Path: "a.gz"}, // exact duplicate: first wins
		{FromSha256: "bb", Path: "b.gz"},
		{FromSha256: "bb", Path: "b2.gz"}, // different pair: both kept
	}}
	dedupeManifestDeltas(m)
	want := []dbupdate.DeltaEntry{
		{FromSha256: "aa", Path: "a.gz"},
		{FromSha256: "bb", Path: "b.gz"},
		{FromSha256: "bb", Path: "b2.gz"},
	}
	if !reflect.DeepEqual(m.Deltas, want) {
		t.Fatalf("deduped = %+v, want %+v", m.Deltas, want)
	}

	// First occurrence wins when a later entry repeats a pair.
	m2 := &dbupdate.Manifest{Deltas: []dbupdate.DeltaEntry{
		{FromSha256: "cc", Path: "first.gz"},
		{FromSha256: "dd", Path: "x.gz"},
		{FromSha256: "dd", Path: "x.gz"},
	}}
	dedupeManifestDeltas(m2)
	if len(m2.Deltas) != 2 || m2.Deltas[1].Path != "x.gz" {
		t.Fatalf("deduped = %+v, want first occurrence kept", m2.Deltas)
	}

	dedupeManifestDeltas(nil) // must not panic
}

func TestUpdateViaDeltaDowngradeGuard(t *testing.T) {
	const localSHA = "1111111111111111111111111111111111111111111111111111111111111111"

	newer := "2026-08-22T04:00:00Z"
	older := "2026-08-21T04:00:00Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(manifestDoc(older, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(dst+".sha256", []byte(localSHA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Previously accepted a NEWER manifest: serving an older one is a
	// downgrade and the delta fast-path must refuse.
	if err := os.WriteFile(dst+".manifest-ts", []byte(newer+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ONYX_MANIFEST_URL", srv.URL)
	done, err := updateViaDelta(dst)
	if done || err == nil || !strings.Contains(err.Error(), "downgrade blocked") {
		t.Fatalf("done=%v err=%v, want downgrade blocked error", done, err)
	}

	// The bypass env var lets it proceed past the guard (it then fails on
	// delta lookup, proving the guard itself passed).
	t.Setenv("ONYX_ALLOW_OLDER_MANIFEST", "1")
	_, err = updateViaDelta(dst)
	if err == nil || strings.Contains(err.Error(), "downgrade blocked") {
		t.Fatalf("err = %v, want non-downgrade error after bypass", err)
	}
}

func TestUpdateViaDeltaGuardSkipsUnparseableTimestamps(t *testing.T) {
	const localSHA = "2222222222222222222222222222222222222222222222222222222222222222"

	// Mirror reports an up-to-date full snapshot with an unparseable
	// generated_at: the guard must skip silently, not fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(manifestDoc("", localSHA)))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(dst+".sha256", []byte(localSHA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst+".manifest-ts", []byte("not-a-time\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ONYX_MANIFEST_URL", srv.URL)
	var done bool
	var err error
	out := captureStdout(t, func() { done, err = updateViaDelta(dst) })
	if !done || err != nil {
		t.Fatalf("done=%v err=%v, want up-to-date success with unparseable stamps", done, err)
	}
	if !strings.Contains(out, "already up to date") {
		t.Fatalf("output = %q, want already-up-to-date notice", out)
	}
}

func TestAcceptManifestTimestampKeepsMax(t *testing.T) {
	dir := t.TempDir()
	tsPath := filepath.Join(dir, "feed.manifest-ts")

	// No baseline yet: new stamp written as-is.
	acceptManifestTimestamp(tsPath, "2026-08-20T00:00:00Z")
	if got := readTs(t, tsPath); got != "2026-08-20T00:00:00Z" {
		t.Fatalf("ts = %q, want 2026-08-20T00:00:00Z", got)
	}
	// Older incoming stamp must not roll the baseline back.
	acceptManifestTimestamp(tsPath, "2026-08-10T00:00:00Z")
	if got := readTs(t, tsPath); got != "2026-08-20T00:00:00Z" {
		t.Fatalf("ts = %q, want max kept (2026-08-20)", got)
	}
	// Newer stamp replaces it.
	acceptManifestTimestamp(tsPath, "2026-08-25T00:00:00Z")
	if got := readTs(t, tsPath); got != "2026-08-25T00:00:00Z" {
		t.Fatalf("ts = %q, want 2026-08-25T00:00:00Z", got)
	}
	// Unparseable input leaves the baseline untouched.
	acceptManifestTimestamp(tsPath, "garbage")
	if got := readTs(t, tsPath); got != "2026-08-25T00:00:00Z" {
		t.Fatalf("ts = %q, want unchanged after garbage input", got)
	}
}

func readTs(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}
