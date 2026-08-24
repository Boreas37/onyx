package report

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

func formatsFixture() *scanner.Result {
	return &scanner.Result{
		IsWordPress:      true,
		Target:           "http://lab.test",
		WordPressVersion: "7.1",
		Interesting:      []string{"readme.html exposed", "evil\x1b[31mANSI"},
		Findings: []scanner.Finding{{
			Slug:             "contact-form-7",
			Type:             "plugin",
			InstalledVersion: "5.3.2",
			Vulnerabilities: []scanner.Vulnerability{
				{CVE: "CVE-2025-3247", Rating: "Medium", Title: "Order Replay | <injection>", AffectedLabels: []string{"*-6.0.5"}},
				{CVE: "CVE-2023-6449", Rating: "High", Title: "File Upload", AffectedLabels: []string{"*-5.8.3"}},
			},
		}},
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b bytes.Buffer
	WriteMarkdown(&b, formatsFixture())
	out := b.String()
	for _, want := range []string{
		"# onyx scan — http://lab.test", "**WordPress core:** 7.1",
		"### plugin/contact-form-7 @ 5.3.2 (2)", "| medium | CVE-2025-3247 | Order Replay \\| <injection> |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}

	var empty bytes.Buffer
	WriteMarkdown(&empty, &scanner.Result{Target: "http://x.test"})
	if !strings.Contains(empty.String(), "No known vulnerabilities matched.") {
		t.Error("clean-scan markdown missing closing note")
	}
}

func TestWriteHTMLEscapesHostileInput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHTML(&b, formatsFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<injection>") || strings.Contains(out, "\x1b") {
		t.Errorf("HTML contains unescaped hostile content:\n%s", out)
	}
	for _, want := range []string{
		"<!DOCTYPE html>", "WordPress <strong>7.1</strong>", "class=\"sev-high\"", "readme.html exposed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
	var clean bytes.Buffer
	if err := WriteHTML(&clean, &scanner.Result{Target: "http://x.test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clean.String(), "No known vulnerabilities matched.") {
		t.Error("clean html missing closing note")
	}
}

func TestWriteJUnit(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJUnit(&b, "0.3.0", formatsFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, xml.Header[:len(xml.Header)-1]) {
		t.Errorf("missing XML declaration:\n%s", out)
	}
	for _, want := range []string{
		`<testsuites name="onyx 0.3.0" tests="2" failures="2">`,
		`<testsuite name="plugin/contact-form-7@5.3.2" tests="2" failures="2">`,
		`message="medium: Order Replay | &lt;injection&gt;"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("junit missing %q:\n%s", want, out)
		}
	}

	var clean bytes.Buffer
	if err := WriteJUnit(&clean, "0.3.0", &scanner.Result{Target: "http://x.test"}); err != nil {
		t.Fatal(err)
	}
	c := clean.String()
	if !strings.Contains(c, `tests="1" failures="0"`) || !strings.Contains(c, "no known vulnerabilities matched") {
		t.Errorf("clean junit malformed:\n%s", c)
	}
	// Must be well-formed XML.
	var suites junitTestSuites
	if err := xml.Unmarshal([]byte(c), &suites); err != nil {
		t.Fatalf("clean junit not valid XML: %v", err)
	}
	if err := xml.Unmarshal([]byte(out), &suites); err != nil {
		t.Fatalf("junit not valid XML: %v", err)
	}
}

// TestWriteMarkdownScannedAt verifies the report timestamp comes from
// res.ScannedAt when set, and falls back to the now() clock (no panic, line
// still present) when the result predates the field.
func TestWriteMarkdownScannedAt(t *testing.T) {
	res := formatsFixture()
	res.ScannedAt = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	WriteMarkdown(&b, res)
	if !strings.Contains(b.String(), "**Scanned:** 2026-08-01T12:00:00Z") {
		t.Errorf("markdown missing deterministic ScannedAt:\n%s", b.String())
	}

	var zero bytes.Buffer
	WriteMarkdown(&zero, formatsFixture())
	if !strings.Contains(zero.String(), "**Scanned:**") {
		t.Errorf("zero ScannedAt markdown missing scanned line:\n%s", zero.String())
	}
}

// TestWriteHTMLScannedAt verifies the HTML "Generated:" line comes from
// res.ScannedAt when set, and falls back to the now() clock (no panic)
// when the result predates the field.
func TestWriteHTMLScannedAt(t *testing.T) {
	res := formatsFixture()
	res.ScannedAt = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	if err := WriteHTML(&b, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Generated: 2026-08-01T12:00:00Z") {
		t.Errorf("html missing deterministic Generated line:\n%s", b.String())
	}

	var zero bytes.Buffer
	if err := WriteHTML(&zero, formatsFixture()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(zero.String(), "Generated:") {
		t.Errorf("zero ScannedAt html missing generated line:\n%s", zero.String())
	}
}

// remediationFixture carries remediation guidance and patched versions on
// the first vulnerability only, so format tests can assert the new rows and
// the omission on the second.
func remediationFixture() *scanner.Result {
	return &scanner.Result{
		IsWordPress: true,
		Target:      "http://lab.test",
		Findings: []scanner.Finding{{
			Slug:             "contact-form-7",
			Type:             "plugin",
			InstalledVersion: "5.3.2",
			Vulnerabilities: []scanner.Vulnerability{
				{CVE: "CVE-2025-3247", Rating: "Medium", Title: "Order Replay",
					AffectedLabels:  []string{"*-5.3.2"},
					Remediation:     "Update to >= 5.4.2 | latest",
					PatchedVersions: []string{"5.4.2", "5.3.3"}},
				{CVE: "CVE-2023-6449", Rating: "High", Title: "File Upload",
					AffectedLabels: []string{"*-5.8.3"}},
			},
		}},
	}
}

func TestWriteMarkdownRemediation(t *testing.T) {
	var b bytes.Buffer
	WriteMarkdown(&b, remediationFixture())
	out := b.String()
	for _, want := range []string{
		"| Remediation | Update to >= 5.4.2 \\| latest |",
		"**Patched in:** 5.4.2, 5.3.3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestWriteHTMLRemediation(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHTML(&b, remediationFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`<tr><td>Remediation</td><td colspan="2">Update to &gt;= 5.4.2 | latest</td></tr>`,
		`<p><strong>Patched in:</strong> 5.4.2, 5.3.3</p>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestWriteJUnitRemediation(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJUnit(&b, "0.3.0", remediationFixture()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`message="medium: Order Replay — Update to &gt;= 5.4.2 | latest"`,
		`*-5.3.2, Patched in: 5.4.2, 5.3.3</failure>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("junit missing %q:\n%s", want, out)
		}
	}
}

// TestSevClass verifies the render-layer severity whitelist: only the
// known labels pass through, everything else (markup, formulas, junk from
// any source) collapses to "unknown".
func TestSevClass(t *testing.T) {
	cases := map[string]string{
		"":                                "unknown",
		"critical":                        "critical",
		"Critical":                        "critical",
		"HIGH":                            "high",
		"medium":                          "medium",
		"low":                             "low",
		"info":                            "info",
		"informational":                   "info",
		"Informational":                   "info",
		"none":                            "unknown",
		"moderate":                        "unknown",
		`high"><script>alert(1)</script>`: "unknown",
		`=HYPERLINK("http://evil","x")`:   "unknown",
		"low | injected | col":            "unknown",
		"\x1b[31mhigh":                    "unknown",
	}
	for in, want := range cases {
		if got := sevClass(in); got != want {
			t.Errorf("sevClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// hostileSeverityResult builds a Result whose rating carries a full XSS
// payload — as a Result assembled outside db.Load could contain.
func hostileSeverityResult(rating string) *scanner.Result {
	return &scanner.Result{
		IsWordPress: true,
		Target:      "http://lab.test",
		Findings: []scanner.Finding{{
			Slug: "wp-plugin", Type: "plugin", InstalledVersion: "1.0",
			Vulnerabilities: []scanner.Vulnerability{{
				CVE: "CVE-2026-9999", Rating: rating, Title: "T",
			}},
		}},
	}
}

// TestWriteHTMLHostileSeverity proves the sev class attribute and cell text
// are whitelisted: an XSS-bearing rating must not inject markup.
func TestWriteHTMLHostileSeverity(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHTML(&b, hostileSeverityResult(`high"><script>alert(1)</script>`)); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	if strings.Contains(out, "<script>") || strings.Contains(out, "alert(1)") {
		t.Errorf("HTML leaked hostile rating content:\n%s", out)
	}
	// Every class="sev-…" occurrence must carry a known class.
	re := regexp.MustCompile(`class="sev-([^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		switch m[1] {
		case "critical", "high", "medium", "low", "info", "unknown":
		default:
			t.Errorf("unknown severity class %q in output:\n%s", m[1], out)
		}
	}
	// Snapshot: both attribute and text collapse to the unknown class.
	wantRow := `<tr><td class="sev-unknown">unknown</td><td>CVE-2026-9999</td><td>T</td></tr>`
	if !strings.Contains(out, wantRow) {
		t.Errorf("hostile-rating row mismatch:\nwant %s\ngot:\n%s", wantRow, out)
	}
}

// TestWriteCSVHostileSeverityField proves a formula-bearing rating cannot
// yield a cell that spreadsheets would execute: after parsing, the severity
// field is the whitelisted word "unknown" and starts with no trigger char.
func TestWriteCSVHostileSeverityField(t *testing.T) {
	res := hostileSeverityResult(`=HYPERLINK("http://evil","x")`)
	res.Findings[0].Vulnerabilities[0].AffectedLabels = []string{"=1+1; -2"}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, res); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("csv output not parseable: %v\n%s", err, buf.String())
	}
	if len(recs) != 2 {
		t.Fatalf("expected header + 1 row, got %d records: %v", len(recs), recs)
	}
	sev := recs[1][4]
	if strings.ContainsAny(sev[:1], "=+-@\t\r") {
		t.Errorf("severity field starts with spreadsheet trigger %q:\n%s", sev, buf.String())
	}
	if sev != "unknown" {
		t.Errorf("severity field = %q, want whitelisted %q", sev, "unknown")
	}
	labels := recs[1][6]
	if strings.ContainsAny(labels[:1], "=+-@\t\r") {
		t.Errorf("affected_versions field starts with spreadsheet trigger %q", labels)
	}
}

// TestWriteMarkdownHostileSeverityPipes proves a pipe-bearing rating cannot
// add columns to the vulnerability table.
func TestWriteMarkdownHostileSeverityPipes(t *testing.T) {
	var b bytes.Buffer
	WriteMarkdown(&b, hostileSeverityResult("low | injected | col"))
	out := b.String()

	if strings.Contains(out, "injected") {
		t.Errorf("markdown leaked hostile rating content:\n%s", out)
	}
	var row string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "CVE-2026-9999") {
			row = ln
			break
		}
	}
	if row == "" {
		t.Fatalf("data row missing:\n%s", out)
	}
	// Header and data rows must both stay 3 cells wide (4 pipes).
	if n := strings.Count(row, "|"); n != 4 {
		t.Errorf("hostile rating changed column count: %d pipes in %q (want 4)", n, row)
	}
	if !strings.HasPrefix(row, "| unknown | CVE-2026-9999 | T |") {
		t.Errorf("severity cell = %q, want whitelisted \"unknown\"", row)
	}
}

// TestWriteJUnitHostileFieldsRoundTrip verifies encoding/xml escaping keeps
// markup-bearing Title/Rating/slug/target structurally valid: the document
// unmarshals back into the schema with every field intact.
func TestWriteJUnitHostileFieldsRoundTrip(t *testing.T) {
	res := &scanner.Result{
		Target: `http://evil"/><script>`,
		Findings: []scanner.Finding{{
			Slug: `a"b<c`, Type: "plugin", InstalledVersion: "1.0&",
			Vulnerabilities: []scanner.Vulnerability{{
				CVE:            "CVE-2026-0002",
				Rating:         `high"&<script>`,
				Title:          `T "&'<`,
				AffectedLabels: []string{"1.0 - 1.9", `<>&"`},
			}},
		}},
	}
	var b bytes.Buffer
	if err := WriteJUnit(&b, "0.3.0", res); err != nil {
		t.Fatal(err)
	}
	var suites junitTestSuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatalf("hostile junit output is not valid XML: %v\n%s", err, b.String())
	}
	if suites.Tests != 1 || suites.Failures != 1 || len(suites.Suites) != 1 {
		t.Fatalf("round-tripped structure = tests:%d failures:%d suites:%d",
			suites.Tests, suites.Failures, len(suites.Suites))
	}
	got := suites.Suites[0].Cases[0]
	if got.Failure == nil {
		t.Fatal("failure element lost in round-trip")
	}
	if want := `high"&<script>: T "&'<`; got.Failure.Message != want {
		t.Errorf("failure message = %q, want %q", got.Failure.Message, want)
	}
	if want := "1.0 - 1.9, <>&\""; got.Failure.Text != want {
		t.Errorf("failure text = %q, want %q", got.Failure.Text, want)
	}
}
