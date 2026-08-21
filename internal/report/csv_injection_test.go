package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/scanner"
)

func TestCSVSafeNeutralizesFormulas(t *testing.T) {
	cases := map[string]string{
		"=HYPERLINK(\"http://evil\",\"x\")": "'=HYPERLINK(\"http://evil\",\"x\")",
		"+1+1":                              "'+1+1",
		"-1-1":                              "'-1-1",
		"@SUM(1)":                           "'@SUM(1)",
		"\tcmd":                             "'\tcmd",
		"\rSUM(1)":                          "'\rSUM(1)",
		"normal-slug":                       "normal-slug",
		"1.2.3":                             "1.2.3",
		"":                                  "",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteCSVEscapesHostileFinding(t *testing.T) {
	res := &scanner.Result{
		Findings: []scanner.Finding{
			{
				Slug:             "=cmd|' /C calc'!A0",
				Type:             "plugin",
				InstalledVersion: "@1.0",
				Vulnerabilities: []scanner.Vulnerability{
					{CVE: "CVE-2026-0001", Rating: "High", Title: "+inject via title"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, bad := range []string{"\n=cmd", ",@1.0", ",+inject"} {
		if strings.Contains(out, bad) {
			t.Fatalf("CSV contains unneutralized field %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "'=cmd") || !strings.Contains(out, "'@1.0") || !strings.Contains(out, "'+inject") {
		t.Fatalf("expected escaped fields in output:\n%s", out)
	}
}
