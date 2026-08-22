package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

func TestParseScanArgsMultiTarget(t *testing.T) {
	tf := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(tf, []byte("# comment line\nhttp://a.test\n\n  http://b.test  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target, o := parseScanArgs([]string{"http://first.test", "http://second.test", "-T", tf})
	if target != "http://first.test" {
		t.Fatalf("primary target = %q", target)
	}
	got := append([]string{target}, o.targets...)
	want := []string{"http://first.test", "http://second.test", "http://a.test", "http://b.test"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

// wpWithVuln serves a minimal WordPress site whose plugin readme matches a
// fixture database entry.
func wpWithVuln(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "feed.json")
	feed := `{"rec-1":{"id":"rec-1","title":"Elementor < 1.0","informational":false,"cve":"CVE-2026-9999","cvss":{"score":9.8,"rating":"critical"},"software":[{"type":"plugin","name":"Elementor","slug":"elementor","affected_versions":{"* - 1.0":{"from_version":"*","to_version":"1.0","to_inclusive":true}}}]}}`
	if err := os.WriteFile(dbPath, []byte(feed), 0o644); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/readme.txt"):
			_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 0.9\n"))
		case r.URL.Path == "/wp-login.php":
			_, _ = w.Write([]byte(`<form><input name="user_login"></form>`))
		case strings.HasPrefix(r.URL.Path, "/wp-json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"fixture","namespaces":["wp/v2"]}`))
		default:
			_, _ = w.Write([]byte("<html><head><title>wp</title></head><body>hello</body></html>"))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, dbPath
}

func TestRunMultiExitCodeAggregation(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("plain site"))
	}))
	defer clean.Close()

	o := scanOptions{
		dbPath:    dbPath,
		threads:   4,
		format:    "table",
		noSummary: true,
		silent:    true,
	}
	if code := runMulti([]string{wpSrv.URL}, o); code != 5 {
		t.Errorf("wp-with-findings exit = %d, want 5", code)
	}
	if code := runMulti([]string{clean.URL}, o); code != 0 {
		t.Errorf("clean exit = %d, want 0", code)
	}
	if code := runMulti([]string{clean.URL, wpSrv.URL}, o); code != 5 {
		t.Errorf("mixed exit = %d, want 5", code)
	}
	if code := runMulti([]string{"http://127.0.0.1:1"}, o); code != 2 {
		t.Errorf("unreachable exit = %d, want 2", code)
	}
	if code := runMulti([]string{clean.URL, "http://127.0.0.1:1"}, o); code != 2 {
		t.Errorf("clean+unreachable exit = %d, want 2 (hard failure wins)", code)
	}
}

func TestRunMultiRejectsUnmergeableFormats(t *testing.T) {
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	defer clean.Close()
	for _, format := range []string{"json", "sarif", "cyclonedx"} {
		o := scanOptions{dbPath: emptyDB(t), format: format, silent: true}
		if code := runMulti([]string{clean.URL, clean.URL}, o); code != 2 {
			t.Errorf("--format %s multi-target exit = %d, want 2", format, code)
		}
	}
}

func TestRunScanSingleTargetStillWorksAfterMultiRefactor(t *testing.T) {
	wpSrv, dbPath := wpWithVuln(t)
	code := runScan(wpSrv.URL, scanOptions{dbPath: dbPath, threads: 4, silent: true})
	if code != 5 {
		t.Fatalf("runScan findings exit = %d, want 5", code)
	}
	var _ = scanner.ErrNotWordPress // keep import stable
}
