package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

// maxFuzzField bounds hostile inputs so each fuzz iteration stays cheap.
const maxFuzzField = 512

// FuzzWriteReportSafety feeds arbitrary bytes into the target-controlled
// fields of a Result and asserts the HTML, CSV, Markdown, JUnit and
// CycloneDX writers never panic, never emit a literal <script> tag, and
// never produce a CSV cell that starts with a spreadsheet formula
// character.
func FuzzWriteReportSafety(f *testing.F) {
	seeds := [][]string{
		{`high"><script>alert(1)</script>`, `=HYPERLINK("http://evil","x")`, `low | injected | col`},
		{"", "", ""},
		{"critical", "Elementor < 3.25.0 - SQL Injection", "elementor"},
		{"\x1b[31mred", "tab\tand\nnewline", "\x01ctl\x7f"},
		{"info", "=1+1; -2", "@evil"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}

	f.Fuzz(func(t *testing.T, rating, title, slug string) {
		if len(rating) > maxFuzzField || len(title) > maxFuzzField || len(slug) > maxFuzzField {
			t.Skip()
		}
		res := &scanner.Result{
			Target:      "https://fuzz.test",
			IsWordPress: true,
			Findings: []scanner.Finding{{
				Slug: slug, Type: "plugin", InstalledVersion: "1.0",
				Vulnerabilities: []scanner.Vulnerability{{
					CVE:            "CVE-2026-0001",
					Rating:         rating,
					Title:          title,
					AffectedLabels: []string{title},
				}},
			}},
		}

		var html bytes.Buffer
		if err := WriteHTML(&html, res); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(html.String(), "<script>") {
			t.Fatalf("HTML contains <script> for rating %q", rating)
		}

		var csvBuf bytes.Buffer
		if err := WriteCSV(&csvBuf, res); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&csvBuf).ReadAll()
		if err != nil {
			t.Fatalf("csv output not parseable: %v\n%s", err, csvBuf.String())
		}
		for rowIdx, row := range recs {
			if rowIdx == 0 {
				continue // header
			}
			for _, cell := range row {
				if cell == "" {
					continue
				}
				if strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
					t.Fatalf("csv cell %q starts with a formula character", cell)
				}
			}
		}

		var md bytes.Buffer
		WriteMarkdown(&md, res)
		var junit bytes.Buffer
		if err := WriteJUnit(&junit, "dev", res); err != nil {
			t.Fatal(err)
		}
		var cdx bytes.Buffer
		writeCycloneDX(&cdx, "dev", res)
	})
}
