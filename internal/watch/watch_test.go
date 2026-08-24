package watch

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

var testNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// vuln builds a Vulnerability fixture.
func vuln(cve, title, rating string) scanner.Vulnerability {
	return scanner.Vulnerability{ID: cve, Title: title, CVE: cve, Rating: rating}
}

// finding builds a Finding fixture.
func finding(slug, typ string, vulns ...scanner.Vulnerability) scanner.Finding {
	return scanner.Finding{Slug: slug, Name: slug, Type: typ, Vulnerabilities: vulns}
}

// baseResult is the first-scan fixture: plugin "akismet" with two CVEs,
// plugin "hello" with one, theme "theme-x" with a CVE-less vulnerability.
func baseResult() *scanner.Result {
	return &scanner.Result{
		Target: "https://example.com",
		Findings: []scanner.Finding{
			finding("akismet", "plugin",
				vuln("CVE-2024-1111", "Akismet XSS", "high"),
				vuln("CVE-2024-2222", "Akismet RCE", "critical"),
			),
			finding("hello", "plugin",
				vuln("CVE-2023-3333", "Hello Dolly SQLi", "medium"),
			),
			finding("theme-x", "theme",
				vuln("", "Theme-X stored XSS", "low"),
			),
		},
	}
}

// modifiedResult is the second-scan fixture derived from baseResult:
// akismet keeps CVE-2024-1111/CVE-2024-2222 and gains CVE-2025-9999 (new),
// hello is gone (resolved), theme-x keeps its CVE-less vulnerability
// (unchanged), and jetpack appears (new).
func modifiedResult() *scanner.Result {
	return &scanner.Result{
		Target: "https://example.com",
		Findings: []scanner.Finding{
			finding("akismet", "plugin",
				vuln("CVE-2024-1111", "Akismet XSS", "high"),
				vuln("CVE-2024-2222", "Akismet RCE", "critical"),
				vuln("CVE-2025-9999", "Akismet SSRF", "high"),
			),
			finding("theme-x", "theme",
				vuln("", "Theme-X stored XSS", "low"),
			),
			finding("jetpack", "plugin",
				vuln("CVE-2025-4444", "Jetpack file upload", "critical"),
			),
		},
	}
}

func TestBuildStateDerivesBaseline(t *testing.T) {
	st := BuildState("https://example.com", baseResult(), testNow)
	want := map[string]map[string]bool{
		"akismet": {"CVE-2024-1111": true, "CVE-2024-2222": true},
		"hello":   {"CVE-2023-3333": true},
		"theme-x": {"-": true},
	}
	if !reflect.DeepEqual(st.Baseline, want) {
		t.Fatalf("baseline = %v, want %v", st.Baseline, want)
	}
	if st.Target != "https://example.com" {
		t.Fatalf("target = %q", st.Target)
	}
	if !st.ScannedAt.Equal(testNow) {
		t.Fatalf("scanned_at = %v, want %v", st.ScannedAt, testNow)
	}
}

func TestBuildStateNilResult(t *testing.T) {
	st := BuildState("https://example.com", nil, testNow)
	if len(st.Baseline) != 0 {
		t.Fatalf("baseline = %v, want empty", st.Baseline)
	}
}

func TestRoundTripDiff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := SaveState(path, BuildState("https://example.com", baseResult(), testNow)); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	prev, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	later := testNow.Add(time.Hour)
	d := DiffStates(prev, modifiedResult(), later)

	if len(d.New) != 2 {
		t.Fatalf("new = %d (%v), want 2", len(d.New), d.New)
	}
	if len(d.Resolved) != 1 {
		t.Fatalf("resolved = %d (%v), want 1", len(d.Resolved), d.Resolved)
	}
	if d.Unchanged != 3 {
		t.Fatalf("unchanged = %d, want 3", d.Unchanged)
	}

	wantNew := []Change{
		{Slug: "akismet", Type: "plugin", CVE: "CVE-2025-9999", Title: "Akismet SSRF", Rating: "high"},
		{Slug: "jetpack", Type: "plugin", CVE: "CVE-2025-4444", Title: "Jetpack file upload", Rating: "critical"},
	}
	if !reflect.DeepEqual(d.New, wantNew) {
		t.Fatalf("new = %+v, want %+v", d.New, wantNew)
	}
	wantResolved := []Change{{Slug: "hello", CVE: "CVE-2023-3333"}}
	if !reflect.DeepEqual(d.Resolved, wantResolved) {
		t.Fatalf("resolved = %+v, want %+v", d.Resolved, wantResolved)
	}
	if d.Target != "https://example.com" {
		t.Fatalf("target = %q", d.Target)
	}
	if !d.ScannedAt.Equal(later) {
		t.Fatalf("scanned_at = %v, want %v", d.ScannedAt, later)
	}
}

func TestDiffStatesFirstRunAllNew(t *testing.T) {
	prev := &State{Baseline: make(map[string]map[string]bool)}
	d := DiffStates(prev, baseResult(), testNow)
	if len(d.New) != 4 {
		t.Fatalf("new = %d (%v), want 4", len(d.New), d.New)
	}
	if d.Unchanged != 0 || len(d.Resolved) != 0 {
		t.Fatalf("unchanged = %d, resolved = %d, want 0/0", d.Unchanged, len(d.Resolved))
	}
	if d.Empty() {
		t.Fatal("first-run diff should not be empty")
	}
}

func TestDiffStatesEmptyBothSides(t *testing.T) {
	prev := BuildState("https://example.com", &scanner.Result{}, testNow)
	d := DiffStates(prev, &scanner.Result{}, testNow)
	if !d.Empty() {
		t.Fatalf("diff should be empty, got %+v", d)
	}
	if d.Unchanged != 0 {
		t.Fatalf("unchanged = %d, want 0", d.Unchanged)
	}
	if s := d.Summary(); s != "0 new, 0 resolved, 0 unchanged" {
		t.Fatalf("summary = %q", s)
	}
}

func TestDiffStatesNilPrev(t *testing.T) {
	d := DiffStates(nil, baseResult(), testNow)
	if len(d.New) != 4 || d.Unchanged != 0 {
		t.Fatalf("nil prev: new = %d, unchanged = %d, want 4/0", len(d.New), d.Unchanged)
	}
}

func TestLoadStateMissingReturnsErrNoState(t *testing.T) {
	_, err := LoadState(filepath.Join(t.TempDir(), "absent.json"))
	if !errors.Is(err, ErrNoState) {
		t.Fatalf("err = %v, want ErrNoState", err)
	}
}

func TestLoadStateInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil || errors.Is(err, ErrNoState) {
		t.Fatalf("err = %v, want parse error", err)
	}
}

// walkTmp returns all *.tmp files anywhere under dir.
func walkTmp(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".tmp") {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestSaveStateAtomicNoTmpLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")

	if err := SaveState(path, BuildState("https://example.com", baseResult(), testNow)); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	leftovers := walkTmp(t, dir)
	if len(leftovers) != 0 {
		t.Fatalf("tmp leftovers: %v", leftovers)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("reload after save: %v", err)
	}
	if len(st.Baseline) != 3 {
		t.Fatalf("reloaded baseline has %d slugs, want 3", len(st.Baseline))
	}
}

func TestSaveStateOverwritesCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	first := BuildState("https://example.com", baseResult(), testNow)
	second := BuildState("https://example.com", modifiedResult(), testNow)
	if err := SaveState(path, first); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := SaveState(path, second); err != nil {
		t.Fatalf("second save: %v", err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := st.Baseline["jetpack"]; !ok {
		t.Fatalf("second state not persisted: %v", st.Baseline)
	}
}

func TestSummaryFormat(t *testing.T) {
	tests := []struct {
		name string
		diff *Diff
		want string
	}{
		{"nil", nil, "0 new, 0 resolved, 0 unchanged"},
		{"empty", &Diff{}, "0 new, 0 resolved, 0 unchanged"},
		{"mixed", &Diff{New: make([]Change, 3), Resolved: make([]Change, 1), Unchanged: 12},
			"3 new, 1 resolved, 12 unchanged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.diff.Summary(); got != tt.want {
				t.Fatalf("summary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	tests := []struct {
		name string
		diff *Diff
		want bool
	}{
		{"nil", nil, true},
		{"no changes", &Diff{Unchanged: 7}, true},
		{"new only", &Diff{New: []Change{{Slug: "x"}}}, false},
		{"resolved only", &Diff{Resolved: []Change{{Slug: "x"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.diff.Empty(); got != tt.want {
				t.Fatalf("empty = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostileStringsSanitizedAndCapped(t *testing.T) {
	hostile := &scanner.Result{
		Target: "https://example.com",
		Findings: []scanner.Finding{
			{
				Slug: "\x1b[31m" + strings.Repeat("p", 250) + "\x1b[0m\n",
				Type: "plugin\x07",
				Vulnerabilities: []scanner.Vulnerability{
					{
						Title:  "\x1b]0;pwned\x07" + strings.Repeat("A", 50_000),
						CVE:    "CVE-2024-" + strings.Repeat("9", 100),
						Rating: "critical\x00\x1b[0m",
					},
				},
			},
		},
	}

	later := testNow.Add(time.Hour)
	d := DiffStates(BuildState("https://example.com", &scanner.Result{}, testNow), hostile, later)
	if len(d.New) != 1 {
		t.Fatalf("new = %d, want 1", len(d.New))
	}
	c := d.New[0]

	caps := []struct {
		field string
		got   string
		max   int
	}{
		{"slug", c.Slug, maxSlugLen},
		{"type", c.Type, maxSlugLen},
		{"cve", c.CVE, maxCVELen},
		{"title", c.Title, maxTitleLen},
		{"rating", c.Rating, maxRatingLen},
	}
	for _, tc := range caps {
		if n := len([]rune(tc.got)); n > tc.max {
			t.Errorf("%s = %d runes, cap %d", tc.field, n, tc.max)
		}
		for _, r := range tc.got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
				t.Errorf("%s kept control char %q: %q", tc.field, r, tc.got)
				break
			}
		}
	}
	if !strings.Contains(c.Title, "pwned") {
		t.Errorf("title lost sanitized content: %q", c.Title[:20])
	}
	if !strings.HasPrefix(c.CVE, "CVE-2024-") {
		t.Errorf("cve mangled: %q", c.CVE)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "hostile.json")
	if err := SaveState(path, BuildState("https://example.com", hostile, later)); err != nil {
		t.Fatalf("save hostile state: %v", err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("load hostile state: %v", err)
	}
	for slug, cves := range st.Baseline {
		if len([]rune(slug)) > maxSlugLen {
			t.Errorf("stored slug exceeds cap: %d runes", len([]rune(slug)))
		}
		for cve := range cves {
			if len([]rune(cve)) > maxCVELen {
				t.Errorf("stored cve exceeds cap: %d runes", len([]rune(cve)))
			}
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("hostile state is not valid JSON: %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
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
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestPrintDiffSections(t *testing.T) {
	d := DiffStates(BuildState("https://example.com", baseResult(), testNow), modifiedResult(), testNow)
	out := captureStdout(t, func() { PrintDiff(d) })
	for _, want := range []string{
		"https://example.com",
		"2 new, 1 resolved, 3 unchanged",
		"New vulnerabilities:",
		"[high] plugin/akismet CVE-2025-9999: Akismet SSRF",
		"Resolved:",
		"hello",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintDiffEmpty(t *testing.T) {
	out := captureStdout(t, func() { PrintDiff(&Diff{Target: "t", Unchanged: 3}) })
	if !strings.Contains(out, "0 new, 0 resolved, 3 unchanged") {
		t.Errorf("summary missing from output: %q", out)
	}
	if strings.Contains(out, "New vulnerabilities:") || strings.Contains(out, "Resolved:") {
		t.Errorf("empty diff printed sections: %q", out)
	}
}

func TestRenderSlackTextSections(t *testing.T) {
	d := DiffStates(BuildState("https://example.com", baseResult(), testNow), modifiedResult(), testNow)
	out := renderSlackText(d)
	for _, want := range []string{
		"https://example.com",
		"2 new, 1 resolved, 3 unchanged",
		"New vulnerabilities:",
		"- [high] plugin/akismet CVE-2025-9999: Akismet SSRF",
		"- [critical] plugin/jetpack CVE-2025-4444: Jetpack file upload",
		"Resolved:",
		"- [] /hello CVE-2023-3333",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("slack text missing %q:\n%s", want, out)
		}
	}
}

func TestRenderSlackTextNilAndEmpty(t *testing.T) {
	if got := renderSlackText(nil); got != "" {
		t.Errorf("renderSlackText(nil) = %q, want empty", got)
	}
	out := renderSlackText(&Diff{Target: "t", Unchanged: 5})
	if strings.Contains(out, "New vulnerabilities:") || strings.Contains(out, "Resolved:") {
		t.Errorf("empty diff rendered sections:\n%s", out)
	}
	if !strings.Contains(out, "0 new, 0 resolved, 5 unchanged") {
		t.Errorf("empty diff missing summary: %q", out)
	}
}
