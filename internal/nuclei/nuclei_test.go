package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ceilingCVE returns a CVE id for the current dynamic ceiling year
// (time.Now().Year()+1), the year a hardcoded bound would reject.
func ceilingCVE(num string) string {
	return fmt.Sprintf("CVE-%d-%s", time.Now().Year()+1, num)
}

func TestFindTemplate(t *testing.T) {
	dir := t.TempDir()
	cve := ceilingCVE("69084")
	yNext := filepath.Join(dir, "http", "cves", strconv.Itoa(time.Now().Year()+1), cve+".yaml")
	if err := os.MkdirAll(filepath.Dir(yNext), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yNext, []byte("id: "+cve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := FindTemplate(dir, cve)
	if !ok || got != yNext {
		t.Errorf("FindTemplate(%s) = %q, %v; want %q, true", cve, got, ok, yNext)
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

// TestCVEYearTracksWallClock pins the dynamic bounds of cveYear: the
// floating ceiling (now+1) is accepted, one past it is rejected, and the
// 2002 lower bound stays.
func TestCVEYearTracksWallClock(t *testing.T) {
	next := strconv.Itoa(time.Now().Year() + 1)
	if got := cveYear("CVE-" + next + "-12345"); got != next {
		t.Errorf("cveYear(ceiling year) = %q, want %q", got, next)
	}
	beyond := strconv.Itoa(time.Now().Year() + 2)
	if got := cveYear("CVE-" + beyond + "-12345"); got != "" {
		t.Errorf("cveYear(year beyond ceiling) = %q, want \"\"", got)
	}
	if got := cveYear("CVE-2001-99999"); got != "" {
		t.Errorf("cveYear(pre-2002) = %q, want \"\"", got)
	}
	if got := cveYear("CVE-2002-00001"); got != "2002" {
		t.Errorf("cveYear(2002 lower bound) = %q, want 2002", got)
	}
	if got := cveYear("CVE-abcd-1234"); got != "" {
		t.Errorf("cveYear(non-numeric year) = %q, want \"\"", got)
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

// writeBatchingMockNuclei creates an executable "nuclei" script that emits
// one JSONL match per -t template (template-id = template basename, in argv
// order) and whose failure behavior is driven by env vars: NUCLEI_FAIL_ALL=1
// makes every invocation exit 1, and NUCLEI_FAIL_IF_COUNT=<n> makes
// invocations carrying exactly <n> templates exit 1. When
// NUCLEI_INVOCATION_LOG is set, each invocation appends its template list.
func writeBatchingMockNuclei(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	script := filepath.Join(tmp, "nuclei")
	body := `#!/bin/sh
ids=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-t" ]; then
    b=$(basename "$a"); b=${b%.yaml}
    ids="$ids $b"
  fi
  prev="$a"
done
if [ -n "$NUCLEI_INVOCATION_LOG" ]; then
  echo "$ids" >> "$NUCLEI_INVOCATION_LOG"
fi
count=$(printf '%s' "$ids" | wc -w | tr -d ' ')
if [ -n "$NUCLEI_FAIL_IF_COUNT" ] && [ "$count" = "$NUCLEI_FAIL_IF_COUNT" ]; then
  echo "mock: failing batch with $count templates" >&2
  exit 1
fi
if [ -n "$NUCLEI_FAIL_ALL" ]; then
  echo "mock: failing all" >&2
  exit 1
fi
for id in $ids; do
  printf '%s\n' "{\"template-id\":\"$id\",\"info\":{\"name\":\"Mock $id\",\"severity\":\"low\"},\"matched-at\":\"https://host/\",\"matcher-name\":\"m\"}"
done
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_BIN", script)
	return script
}

// makeTemplates writes n placeholder template files named T01.yaml..T0n.yaml
// and returns their paths in order.
func makeTemplates(t *testing.T, n int) []string {
	t.Helper()
	dir := t.TempDir()
	var tpls []string
	for i := 1; i <= n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("T%02d.yaml", i))
		if err := os.WriteFile(p, []byte("id: T%02d\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		tpls = append(tpls, p)
	}
	return tpls
}

// TestRunBatchesPartialFailure covers > templatesPerBatch templates where
// the second batch exits non-zero: the first batch's results must survive
// and the error must be nil (partial coverage is better than nothing).
func TestRunBatchesPartialFailure(t *testing.T) {
	t.Setenv("NUCLEI_FAIL_IF_COUNT", "2")
	writeBatchingMockNuclei(t)
	tpls := makeTemplates(t, 12)

	results, err := Run("https://host/", tpls, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 10 {
		t.Fatalf("len(results) = %d, want 10 (first batch preserved)", len(results))
	}
	for i, r := range results {
		if want := fmt.Sprintf("T%02d", i+1); r.TemplateID != want {
			t.Errorf("results[%d].TemplateID = %q, want %q", i, r.TemplateID, want)
		}
	}
}

// TestRunBatchesAllFail covers the total-failure path: every batch exits
// non-zero, so Run must return the first batch error and no results.
func TestRunBatchesAllFail(t *testing.T) {
	t.Setenv("NUCLEI_FAIL_ALL", "1")
	writeBatchingMockNuclei(t)
	tpls := makeTemplates(t, 12)

	results, err := Run("https://host/", tpls, nil)
	if err == nil {
		t.Fatal("Run = nil error, want error when every batch fails")
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
	if !strings.Contains(err.Error(), "nuclei failed") {
		t.Errorf("error = %v, want nuclei failure", err)
	}
}

// TestRunBatchesOrderAndComposition verifies templates are split into
// templatesPerBatch-sized invocations (10, 10, 5 for 25 templates) and the
// merged results keep template order across batches.
func TestRunBatchesOrderAndComposition(t *testing.T) {
	log := filepath.Join(t.TempDir(), "invocations.txt")
	t.Setenv("NUCLEI_INVOCATION_LOG", log)
	writeBatchingMockNuclei(t)
	tpls := makeTemplates(t, 25)

	results, err := Run("https://host/", tpls, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 25 {
		t.Fatalf("len(results) = %d, want 25", len(results))
	}
	for i, r := range results {
		if want := fmt.Sprintf("T%02d", i+1); r.TemplateID != want {
			t.Errorf("results[%d].TemplateID = %q, want %q (order must follow template order)", i, r.TemplateID, want)
		}
	}

	lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, log))), "\n")
	wantBatches := []string{
		"T01 T02 T03 T04 T05 T06 T07 T08 T09 T10",
		"T11 T12 T13 T14 T15 T16 T17 T18 T19 T20",
		"T21 T22 T23 T24 T25",
	}
	if len(lines) != len(wantBatches) {
		t.Fatalf("invocations = %d, want %d (25 templates / 10 per batch)", len(lines), len(wantBatches))
	}
	for i, want := range wantBatches {
		if strings.TrimSpace(lines[i]) != want {
			t.Errorf("invocation[%d] = %q, want %q", i, lines[i], want)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
