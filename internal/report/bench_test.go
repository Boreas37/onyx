package report

import (
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

// benchResult builds a mid-sized realistic result: 20 findings with a few
// vulnerabilities each, mixed severities, remediation and vectors.
func benchResult() *scanner.Result {
	res := &scanner.Result{
		Target: "https://example.test", IsWordPress: true,
		WordPressVersion: "7.1",
		Interesting:      []string{"robots.txt with disallow rules", "xmlrpc.php exposed"},
		Users:            []scanner.User{{ID: 1, Slug: "admin", Name: "admin"}},
	}
	for i := 0; i < 20; i++ {
		f := scanner.Finding{
			Slug: "plugin-" + string(rune('a'+i)), Type: "plugin",
			InstalledVersion: "1." + string(rune('0'+i%10)),
			Vulnerabilities: []scanner.Vulnerability{
				{ID: "rec-1", CVE: "CVE-2026-0001", Title: "SQL Injection in widget loader", CVSSScore: 9.8, Rating: "critical", CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Remediation: "Update to 2.0"},
				{ID: "rec-2", CVE: "CVE-2026-0002", Title: "Stored XSS", CVSSScore: 6.1, Rating: "medium"},
			},
		}
		res.Findings = append(res.Findings, f)
	}
	return res
}

func BenchmarkWriteHTML(b *testing.B) {
	res := benchResult()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		_ = WriteHTML(&sb, res)
	}
}

func BenchmarkWriteMarkdown(b *testing.B) {
	res := benchResult()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		WriteMarkdown(&sb, res)
	}
}

func BenchmarkWriteCSV(b *testing.B) {
	res := benchResult()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		_ = WriteCSV(&sb, res)
	}
}

func BenchmarkWriteJUnit(b *testing.B) {
	res := benchResult()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		_ = WriteJUnit(&sb, "0.9.0", res)
	}
}

func BenchmarkWriteCycloneDX(b *testing.B) {
	res := benchResult()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		WriteCycloneDX(&sb, "0.9.0", res)
	}
}
