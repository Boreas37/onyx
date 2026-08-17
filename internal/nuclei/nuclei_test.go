package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindTemplate(t *testing.T) {
	dir := t.TempDir()
	y2026 := filepath.Join(dir, "http", "cves", "2026", "CVE-2026-69084.yaml")
	if err := os.MkdirAll(filepath.Dir(y2026), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(y2026, []byte("id: CVE-2026-69084\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := FindTemplate(dir, "CVE-2026-69084")
	if !ok || got != y2026 {
		t.Errorf("FindTemplate(CVE-2026-69084) = %q, %v; want %q, true", got, ok, y2026)
	}

	if _, ok := FindTemplate(dir, "CVE-2025-12345"); ok {
		t.Error("FindTemplate(CVE-2025-12345) = true, want false")
	}

	// Recursive fallback: no year directory, template sitting under http/cves/.
	flat := filepath.Join(dir, "http", "cves", "CVE-2024-99999.yaml")
	if err := os.WriteFile(flat, []byte("id: CVE-2024-99999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok = FindTemplate(dir, "CVE-2024-99999")
	if !ok || got != flat {
		t.Errorf("FindTemplate(CVE-2024-99999) = %q, %v; want %q, true", got, ok, flat)
	}
}

// writeMockNuclei creates an executable "nuclei" script whose stdout is a
// fixed JSONL match stream and which dumps its argv into argDump (when
// non-empty). It reports the script path.
func writeMockNuclei(t *testing.T, argDump string) string {
	t.Helper()
	tmp := t.TempDir()
	script := filepath.Join(tmp, "nuclei")
	body := `#!/bin/sh
[ -n "$NUCLEI_ARG_DUMP" ] && printf '%s\n' "$@" > "$NUCLEI_ARG_DUMP"
printf '%s\n' '{"template-id":"CVE-2026-69084","info":{"name":"Elementor File Read","severity":"critical"},"matched-at":"https://host/wp-admin/","matcher-name":"y-word"}'
printf '%s\n' '{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"low"},"matched-at":"https://host/","matcher-name":"x-word"}'
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_BIN", script)
	if argDump != "" {
		t.Setenv("NUCLEI_ARG_DUMP", argDump)
	}
	return script
}

func TestRunMockNuclei(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "args.txt")
	writeMockNuclei(t, dump)
	t.Setenv("PATH", "")

	tpl := filepath.Join(t.TempDir(), "CVE-2026-69084.yaml")
	results, err := Run("https://host/", []string{tpl}, []string{"-H", "X-Api-Key: x"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	first := results[0]
	if first.TemplateID != "CVE-2026-69084" || first.CVE != "CVE-2026-69084" {
		t.Errorf("first.TemplateID/CVE = %q/%q, want CVE-2026-69084 both", first.TemplateID, first.CVE)
	}
	if first.Severity != "critical" || first.Name != "Elementor File Read" {
		t.Errorf("first severity/name = %q/%q, want critical/Elementor File Read", first.Severity, first.Name)
	}
	if first.MatchedAt != "https://host/wp-admin/" || first.MatcherName != "y-word" {
		t.Errorf("first matched-at/matcher-name = %q/%q", first.MatchedAt, first.MatcherName)
	}

	second := results[1]
	if second.TemplateID != "http-missing-security-headers" || second.CVE != "" {
		t.Errorf("second TemplateID/CVE = %q/%q, want template id, empty cve", second.TemplateID, second.CVE)
	}
	if second.Severity != "low" || second.Name != "Missing Security Headers" {
		t.Errorf("second severity/name = %q/%q", second.Severity, second.Name)
	}

	args, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("reading arg dump: %v", err)
	}
	got := strings.TrimSpace(string(args))
	for _, want := range []string{"-target", "https://host/", "-t", tpl, "-json", "-silent", "-H", "X-Api-Key: x"} {
		if !strings.Contains(got, want) {
			t.Errorf("nuclei argv missing %q: %s", want, got)
		}
	}
}

func TestParseLine(t *testing.T) {
	r, err := ParseLine(`{"template-id":"CVE-2026-69084","info":{"name":"X","severity":"critical"},"matched-at":"http://x/","matcher-name":"y"}`)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if r.TemplateID != "CVE-2026-69084" || r.CVE != "CVE-2026-69084" {
		t.Errorf("TemplateID/CVE = %q/%q", r.TemplateID, r.CVE)
	}
	if r.Name != "X" || r.Severity != "critical" {
		t.Errorf("Name/Severity = %q/%q", r.Name, r.Severity)
	}
	if r.MatchedAt != "http://x/" || r.MatcherName != "y" {
		t.Errorf("MatchedAt/MatcherName = %q/%q", r.MatchedAt, r.MatcherName)
	}

	// info.classification.cve-id wins over the template id.
	r, err = ParseLine(`{"template-id":"elementor-file-read","info":{"name":"X","severity":"high","classification":{"cve-id":"CVE-2026-11111"}},"matched-at":"https://h/"}`)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if r.CVE != "CVE-2026-11111" {
		t.Errorf("CVE = %q, want CVE-2026-11111", r.CVE)
	}

	if _, err := ParseLine(`not json`); err == nil {
		t.Error("ParseLine(invalid) = nil error, want error")
	}
}

func TestRunBinaryNotFound(t *testing.T) {
	t.Setenv("NUCLEI_BIN", "")
	t.Setenv("PATH", filepath.Dir(t.TempDir()))
	if _, err := Run("https://host/", nil, nil); err != ErrBinaryNotFound {
		t.Errorf("Run without nuclei = %v, want ErrBinaryNotFound", err)
	}
}
