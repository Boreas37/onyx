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

// TestRunDBFlagParsing locks the repaired hand-rolled flag parsing: both
// --db PATH and --db=PATH are accepted, the flag may precede or follow the
// positional argument, and missing values / unknown flags fail with exit 2.
// Regression for the stray loop that rejected every --db invocation.
func TestRunDBFlagParsing(t *testing.T) {
	dbPath := dbFixture(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"stats --db=PATH", []string{"stats", "--db=" + dbPath}, "records:      3"},
		{"stats --db PATH before cmd", []string{"--db", dbPath, "stats"}, "records:      3"},
		{"lookup --db=PATH", []string{"lookup", "elementor", "--db=" + dbPath}, "CVE-2026-1111"},
		{"lookup flag before slug", []string{"lookup", "--db", dbPath, "elementor"}, "patched in: 1.0"},
		{"top --db=PATH", []string{"top", "1", "--db=" + dbPath}, "vulnerabilities"},
		{"top flag before N", []string{"top", "--db=" + dbPath, "2"}, "elementor"},
		{"search --db=PATH", []string{"search", "CVE-2026-2222", "--db=" + dbPath}, "CVE-2026-2222"},
		{"search flag before query", []string{"search", "--db", dbPath, "CVE-2026-22"}, "CVE-2026-2222"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			out := captureStdoutDB(t, func() { code = runDB(tc.args) })
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output missing %q in:\n%s", tc.want, out)
			}
		})
	}

	// diff must accept --db=PATH and compare against the fixture.
	bPath := filepath.Join(t.TempDir(), "b.json")
	feedB := `{"r1":{"id":"r1","title":"Elementor < 1.0","software":[{"type":"plugin","slug":"elementor"}]}}`
	if err := os.WriteFile(bPath, []byte(feedB), 0o644); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdoutDB(t, func() { code = runDB([]string{"diff", bPath, "--db=" + dbPath}) })
	if code != 0 {
		t.Fatalf("diff exit = %d, want 0", code)
	}
	if !strings.Contains(out, "db diff: 3 records vs 1 records") {
		t.Errorf("diff output unexpected:\n%s", out)
	}

	// Failure cases: every one must be usage + exit 2.
	errCases := []struct {
		name string
		args []string
	}{
		{"missing value after --db", []string{"stats", "--db"}},
		{"missing value, flag last", []string{"lookup", "elementor", "--db"}},
		{"empty --db=", []string{"stats", "--db="}},
		{"unknown flag", []string{"stats", "--bogus"}},
		{"unknown flag with valid db", []string{"stats", "--db=" + dbPath, "--bogus"}},
		{"no subcommand after flag", []string{"--db", dbPath}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if code := runDB(tc.args); code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
		})
	}
}

// TestAuditDBEqualsFlagParsers covers the same class of bug outside dbcmd:
// scan, watch and doctor also parse args by hand and previously rejected the
// --db=PATH form that the stdlib-based `update` subcommand accepts.
func TestAuditDBEqualsFlagParsers(t *testing.T) {
	const p = "/tmp/onyx-regression-db.json"

	if _, o := parseScanArgs([]string{"http://example.test", "--db=" + p}); o.dbPath != p {
		t.Errorf("scan --db=PATH dbPath = %q, want %q", o.dbPath, p)
	}
	if _, o := parseScanArgs([]string{"--db", p, "http://example.test"}); o.dbPath != p {
		t.Errorf("scan --db PATH dbPath = %q, want %q", o.dbPath, p)
	}
	if _, o, _ := parseWatchArgs([]string{"http://example.test", "--db=" + p}); o.dbPath != p {
		t.Errorf("watch --db=PATH dbPath = %q, want %q", o.dbPath, p)
	}
	// doctor returns 1 (db missing) when --db=PATH is accepted, 2 (usage)
	// when it is not: distinguishes the two without network access.
	var code int
	captureStdoutDB(t, func() { code = runDoctor([]string{"--db=" + p}) })
	if code != 1 {
		t.Errorf("doctor --db=PATH exit = %d, want 1 (accepted, db missing)", code)
	}
}
