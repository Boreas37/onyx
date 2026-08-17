package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
