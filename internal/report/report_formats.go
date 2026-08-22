package report

import (
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/scanner"
)

// esc strips control characters (ANSI escapes, newlines) and then
// HTML-escapes: html.EscapeString alone leaves raw control bytes in place.
func esc(s string) string {
	return html.EscapeString(sanitize.Text(s, 500))
}

// mdCell escapes a string for use inside a Markdown table cell: pipes are
// the column separator and raw newlines break the row.
func mdCell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", "").Replace(s)
}

// WriteMarkdown renders res as a self-contained Markdown document.
func WriteMarkdown(w io.Writer, res *scanner.Result) {
	fmt.Fprintf(w, "# onyx scan — %s\n\n", mdCell(res.Target))
	if res.WordPressVersion != "" {
		fmt.Fprintf(w, "**WordPress core:** %s\n\n", mdCell(res.WordPressVersion))
	}
	fmt.Fprintf(w, "**Scanned:** %s\n\n", time.Now().UTC().Format(time.RFC3339))

	if len(res.Interesting) > 0 {
		fmt.Fprint(w, "## Interesting findings\n\n")
		for _, n := range res.Interesting {
			fmt.Fprintf(w, "- %s\n", mdCell(n))
		}
		fmt.Fprint(w, "\n")
	}

	if len(res.Findings) == 0 {
		fmt.Fprint(w, "## No known vulnerabilities matched.\n")
		return
	}

	fmt.Fprint(w, "## Vulnerabilities\n\n")
	for i := range res.Findings {
		f := &res.Findings[i]
		fmt.Fprintf(w, "### %s/%s @ %s (%d)\n\n",
			f.Type, mdCell(f.Slug), mdCell(f.InstalledVersion), len(f.Vulnerabilities))
		fmt.Fprint(w, "| Severity | CVE | Title |\n|---|---|---|\n")
		for _, v := range f.Vulnerabilities {
			cve := v.CVE
			if cve == "" {
				cve = "-"
			}
			fmt.Fprintf(w, "| %s | %s | %s |\n",
				strings.ToLower(v.Rating), mdCell(cve), mdCell(v.Title))
		}
		fmt.Fprint(w, "\n")
	}
}

// PrintMarkdown prints the result as Markdown to stdout.
func PrintMarkdown(res *scanner.Result) { WriteMarkdown(os.Stdout, res) }

// WriteHTML renders res as a standalone HTML page with inline CSS — no
// external assets. Every target-derived string is HTML-escaped.
func WriteHTML(w io.Writer, res *scanner.Result) error {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>onyx — ` + esc(res.Target) + `</title>
<style>
 body{font-family:-apple-system,sans-serif;margin:2rem auto;max-width:60rem;color:#1a1a2e;background:#fafafa}
 h1{border-bottom:2px solid #16213e;padding-bottom:.3rem}
 .meta{color:#555}
 .sev-critical{color:#8b0000;font-weight:700}.sev-high{color:#c0392b;font-weight:600}
 .sev-medium{color:#d35400}.sev-low,.sev-info,.sev-unknown{color:#7f8c8d}
 table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}
 td,th{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}
 th{background:#eee}.slug{font-family:monospace}
</style></head><body>
<h1>onyx scan report</h1>
<p class="meta">Target: <strong>` + esc(res.Target) + `</strong>`)
	if res.WordPressVersion != "" {
		b.WriteString(" · WordPress <strong>" + esc(res.WordPressVersion) + "</strong>")
	}
	fmt.Fprintf(&b, " · Generated: %s</p>\n", time.Now().UTC().Format(time.RFC3339))

	if len(res.Interesting) > 0 {
		b.WriteString("<h2>Interesting</h2>\n<ul>\n")
		for _, n := range res.Interesting {
			b.WriteString("<li>" + esc(n) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}

	vulnTotal := 0
	for i := range res.Findings {
		vulnTotal += len(res.Findings[i].Vulnerabilities)
	}
	if vulnTotal == 0 && len(res.Findings) == 0 {
		b.WriteString("<h2>No known vulnerabilities matched.</h2>\n")
	} else {
		fmt.Fprintf(&b, "<h2>Vulnerabilities (%d)</h2>\n", vulnTotal)
		for i := range res.Findings {
			f := &res.Findings[i]
			fmt.Fprintf(&b, "<h3><span class=\"slug\">%s</span> — %d</h3>\n<table>\n<tr><th>Severity</th><th>CVE</th><th>Title</th></tr>\n",
				esc(f.Type+"/"+f.Slug+"@"+f.InstalledVersion), len(f.Vulnerabilities))
			for _, v := range f.Vulnerabilities {
				sev := strings.ToLower(v.Rating)
				fmt.Fprintf(&b, "<tr><td class=\"sev-%s\">%s</td><td>%s</td><td>%s</td></tr>\n",
					sev, sev, esc(v.CVE), esc(v.Title))
			}
			b.WriteString("</table>\n")
		}
	}
	b.WriteString("</body></html>\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// PrintHTML prints the result as a standalone HTML page to stdout.
func PrintHTML(res *scanner.Result) {
	if err := WriteHTML(os.Stdout, res); err != nil {
		fmt.Fprintln(os.Stderr, "html output:", err)
	}
}

// JUnit XML schema subset consumed by CI systems (GitLab/Jenkins/GitHub
// annotations via converters).
type junitTestSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit writes res as JUnit XML: one failing testcase per recorded
// vulnerability, grouped into one testsuite per vulnerable component. A
// clean scan produces a single passing testcase so CI systems always see
// a structurally valid report. encoding/xml escapes every field.
func WriteJUnit(w io.Writer, version string, res *scanner.Result) error {
	suites := junitTestSuites{Name: "onyx " + version}
	for i := range res.Findings {
		f := &res.Findings[i]
		suite := junitSuite{
			Name:     f.Type + "/" + f.Slug + "@" + f.InstalledVersion,
			Tests:    len(f.Vulnerabilities),
			Failures: len(f.Vulnerabilities),
		}
		for _, v := range f.Vulnerabilities {
			cve := v.CVE
			if cve == "" {
				cve = "no-cve"
			}
			suite.Cases = append(suite.Cases, junitCase{
				Name:      cve,
				ClassName: res.Target,
				Failure: &junitFailure{
					Message: strings.ToLower(v.Rating) + ": " + v.Title,
					Text:    strings.Join(v.AffectedLabels, ", "),
				},
			})
		}
		suites.Suites = append(suites.Suites, suite)
		suites.Tests += suite.Tests
		suites.Failures += suite.Failures
	}
	if suites.Tests == 0 {
		suites.Suites = append(suites.Suites, junitSuite{
			Name:  "clean@" + res.Target,
			Tests: 1,
			Cases: []junitCase{{Name: "no known vulnerabilities matched"}},
		})
		suites.Tests++
	}
	out, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return err
	}
	if _, err = w.Write([]byte(xml.Header)); err != nil {
		return err
	}
	if _, err = w.Write(out); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// PrintJUnit prints the result as JUnit XML to stdout.
func PrintJUnit(version string, res *scanner.Result) {
	if err := WriteJUnit(os.Stdout, version, res); err != nil {
		fmt.Fprintln(os.Stderr, "junit output:", err)
	}
}
