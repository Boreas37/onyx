package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/nuclei"
	"github.com/Boreas37/onyx/internal/scanner"
)

// update rewrites the golden files in testdata/golden instead of comparing:
// go test ./internal/report/ -run TestGoldenReportFormats -update
var update = flag.Bool("update", false, "update golden files instead of comparing")

// goldenUUIDStr is the serial number injected through uuidV4Fn during the
// golden test so the CycloneDX document is byte-for-byte deterministic.
const goldenUUIDStr = "00000000-0000-4000-8000-000000000000"

// goldenResult is a fixed, realistic scan result exercising every section a
// report format can render: two findings with mixed-severity
// vulnerabilities including an empty-CVE record, remediation guidance and
// patched versions on some records only, interesting findings, users, a
// nuclei result, and detected components with a known and an unknown
// version.
func goldenResult() *scanner.Result {
	return &scanner.Result{
		Target:           "https://shop.example.test",
		IsWordPress:      true,
		WordPressVersion: "7.1",
		Interesting:      []string{"readme.html exposed", "wp-json user enumeration enabled"},
		Users: []scanner.User{
			{ID: 1, Slug: "admin", Name: "Site Admin"},
			{ID: 0, Slug: "editor"},
		},
		Nuclei: []nuclei.NucleiResult{{
			TemplateID: "CVE-2026-9999",
			CVE:        "CVE-2026-9999",
			MatchedAt:  "https://shop.example.test/readme.html",
			Severity:   "critical",
			Name:       "WordPress Readme Disclosure",
		}},
		Detected: []scanner.Detected{
			{Slug: "elementor", Name: "Elementor", Type: "plugin", Version: "3.24.0", Source: "rest", ActiveInstalls: 4000000},
			{Slug: "theme-x", Name: "Theme X", Type: "theme", Version: "unknown", Source: "style.css"},
		},
		Findings: []scanner.Finding{
			{
				Slug: "elementor", Name: "Elementor", Type: "plugin", InstalledVersion: "3.24.0",
				Vulnerabilities: []scanner.Vulnerability{
					{ID: "aaaaaaaa-0000-0000-0000-000000000001", CVE: "CVE-2024-0001",
						Title: "Elementor < 3.25.0 - SQL Injection", CVSSScore: 9.1, Rating: "critical",
						CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						AffectedLabels:  []string{"1.0.0 - 3.24.9"},
						Remediation:     "Update to Elementor 3.25.0 or newer",
						PatchedVersions: []string{"3.25.0"}},
					{ID: "bbbbbbbb-0000-0000-0000-000000000002", CVE: "CVE-2024-0002",
						Title: "Elementor < 3.23.9 - Stored XSS", CVSSScore: 6.1, Rating: "medium",
						AffectedLabels: []string{"1.0.0 - 3.23.8"}},
					{ID: "cccccccc-0000-0000-0000-000000000003", CVE: "",
						Title: "Arbitrary file download in Elementor", CVSSScore: 3.4, Rating: "low",
						AffectedLabels: []string{"3.20.0 - 3.23.8"},
						Remediation:    "Update the plugin to the latest release"},
				},
			},
			{
				Slug: "akismet", Name: "Akismet", Type: "plugin", InstalledVersion: "4.0.0",
				Vulnerabilities: []scanner.Vulnerability{
					{ID: "dddddddd-0000-0000-0000-000000000004", CVE: "CVE-2024-0003",
						Title: "Akismet < 5.0 - Comment Spam Bypass", CVSSScore: 7.5, Rating: "high",
						CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
						AffectedLabels:  []string{"1.0.0 - 4.9.9"},
						PatchedVersions: []string{"5.0"}},
				},
			},
		},
	}
}

// TestGoldenReportFormats renders goldenResult through every report writer
// with the time and UUID sources pinned, and snapshots the output against
// testdata/golden/<format>.golden. Run with -update to regenerate.
func TestGoldenReportFormats(t *testing.T) {
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	oldNow, oldUUID := now, uuidV4Fn
	now = func() time.Time { return fixed }
	uuidV4Fn = func() string { return goldenUUIDStr }
	t.Cleanup(func() { now, uuidV4Fn = oldNow, oldUUID })

	res := goldenResult()
	tests := []struct {
		name string
		run  func(*testing.T) []byte
	}{
		{"markdown", func(t *testing.T) []byte {
			var b bytes.Buffer
			WriteMarkdown(&b, res)
			return b.Bytes()
		}},
		{"html", func(t *testing.T) []byte {
			var b bytes.Buffer
			if err := WriteHTML(&b, res); err != nil {
				t.Fatal(err)
			}
			return b.Bytes()
		}},
		{"junit", func(t *testing.T) []byte {
			var b bytes.Buffer
			if err := WriteJUnit(&b, "0.1.0", res); err != nil {
				t.Fatal(err)
			}
			return b.Bytes()
		}},
		{"cyclonedx", func(t *testing.T) []byte {
			var b bytes.Buffer
			writeCycloneDX(&b, "0.1.0", res)
			return b.Bytes()
		}},
		{"csv", func(t *testing.T) []byte {
			var b bytes.Buffer
			if err := WriteCSV(&b, res); err != nil {
				t.Fatal(err)
			}
			return b.Bytes()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkGolden(t, tt.name+".golden", tt.run(t))
		})
	}
}

// checkGolden compares got against testdata/golden/name. With -update (or a
// missing file) it rewrites the file; otherwise a mismatch fails with a
// line diff.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	want, err := os.ReadFile(path)
	switch {
	case *update || os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		if os.IsNotExist(err) {
			t.Fatalf("golden file %s did not exist; wrote it (re-run without -update to verify)", path)
		}
		return
	case err != nil:
		t.Fatal(err)
	}
	if bytes.Equal(got, want) {
		return
	}
	t.Errorf("golden mismatch %s:\n%s", path,
		diffLines(strings.Split(string(want), "\n"), strings.Split(string(got), "\n")))
}

// diffLines renders a minimal LCS-based line diff of a (expected) against b
// (actual) without external dependencies.
func diffLines(a, b []string) string {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			out.WriteString("  " + a[i] + "\n")
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			out.WriteString("- " + a[i] + "\n")
			i++
		} else {
			out.WriteString("+ " + b[j] + "\n")
			j++
		}
	}
	for ; i < n; i++ {
		out.WriteString("- " + a[i] + "\n")
	}
	for ; j < m; j++ {
		out.WriteString("+ " + b[j] + "\n")
	}
	return out.String()
}
