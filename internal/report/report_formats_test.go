package report

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

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
