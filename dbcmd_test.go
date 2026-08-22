package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dbFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.json")
	feed := `{
	  "r1":{"id":"r1","title":"Elementor < 1.0","informational":false,"cve":"CVE-2026-1111",
	        "cvss":{"score":9.8,"rating":"critical"},
	        "software":[{"type":"plugin","name":"Elementor","slug":"elementor","patched":true,
	                     "patched_versions":["1.0"],
	                     "affected_versions":{"* - 1.0":{"from_version":"*","to_version":"1.0","to_inclusive":true}}}]},
	  "r2":{"id":"r2","title":"Info: plugin abandoned","informational":true,
	        "software":[{"type":"plugin","slug":"elementor"}]},
	  "r3":{"id":"r3","title":"Twenty Twenty-Five < 1.2 XSS","informational":false,"cve":"CVE-2026-2222",
	        "cvss":{"score":6.5,"rating":"medium"},
	        "software":[{"type":"theme","slug":"twentytwentyfive",
	                     "affected_versions":{"- 1.2":{"from_version":"","to_version":"1.2","to_inclusive":true}}}]}
	}`
	if err := os.WriteFile(path, []byte(feed), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func captureStdoutDB(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	buf := make([]byte, 1<<16)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func TestRunDBSubcommands(t *testing.T) {
	dbPath := dbFixture(t)

	out := captureStdoutDB(t, func() { _ = runDB([]string{"stats", "--db", dbPath}) })
	for _, want := range []string{"records:      3", "plugin:", "theme:"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats missing %q in:\n%s", want, out)
		}
	}

	out = captureStdoutDB(t, func() { _ = runDB([]string{"lookup", "elementor", "--db", dbPath}) })
	for _, want := range []string{"CVE-2026-1111", "critical", "patched in: 1.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("lookup missing %q in:\n%s", want, out)
		}
	}

	out = captureStdoutDB(t, func() { _ = runDB([]string{"top", "1", "--db", dbPath}) })
	if !strings.Contains(out, "elementor") || !strings.Contains(out, "vulnerabilities") {
		t.Errorf("top output unexpected:\n%s", out)
	}

	out = captureStdoutDB(t, func() { _ = runDB([]string{"search", "CVE-2026-22", "--db", dbPath}) })
	if !strings.Contains(out, "CVE-2026-2222") {
		t.Errorf("search missing CVE in:\n%s", out)
	}

	out = captureStdoutDB(t, func() { _ = runDB([]string{"search", "zzz-no-match", "--db", dbPath}) })
	if !strings.Contains(out, "no matches") {
		t.Errorf("expected no-matches note:\n%s", out)
	}

	if code := runDB([]string{"nope", "--db", dbPath}); code != 2 {
		t.Errorf("unknown db command exit = %d, want 2", code)
	}
	if code := runDB([]string{"lookup", "--db", dbPath}); code != 2 {
		t.Errorf("lookup without slug exit = %d, want 2", code)
	}
	if code := runDB([]string{"stats", "--db", filepath.Join(t.TempDir(), "missing.json")}); code != 2 {
		t.Errorf("missing db exit = %d, want 2", code)
	}
}
