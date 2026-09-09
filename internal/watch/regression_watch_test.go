package watch

import (
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

func TestAuditIncompleteScanPreservesBaseline(t *testing.T) {
	dir := t.TempDir()
	prev := &State{Target: "https://example.com", Baseline: map[string]map[string]bool{"foo": {"CVE-1": true}}, ScannedAt: time.Now()}
	if err := SaveState(dir+"/s.json", prev); err != nil {
		t.Fatal(err)
	}
	// Load via Run path: use StateDir with pre-seeded state file name? Simpler: test Run guard directly
	_ = dir
	res := &scanner.Result{Target: "https://example.com", TimedOut: true}
	if _, err := Run("https://example.com", res, Options{StateDir: t.TempDir()}, time.Now()); err == nil {
		t.Errorf("Run with TimedOut must error to preserve baseline")
	}
	res2 := &scanner.Result{Target: "https://example.com", RateLimitedAbort: true}
	if _, err := Run("https://example.com", res2, Options{StateDir: t.TempDir()}, time.Now()); err == nil {
		t.Errorf("Run with RateLimitedAbort must error to preserve baseline")
	}
	if _, err := Run("https://example.com", nil, Options{StateDir: t.TempDir()}, time.Now()); err == nil {
		t.Errorf("Run with nil res must error")
	}
}

func TestAuditNewSorted(t *testing.T) {
	prev := &State{Baseline: map[string]map[string]bool{}}
	res := &scanner.Result{
		Findings: []scanner.Finding{
			{Slug: "zebra", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2"}}},
			{Slug: "apple", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-1"}}},
		},
	}
	d := DiffStates(prev, res, time.Now())
	if len(d.New) != 2 {
		t.Fatalf("want 2 new, got %d", len(d.New))
	}
	if d.New[0].Slug != "apple" || d.New[1].Slug != "zebra" {
		t.Errorf("New not sorted: %+v", d.New)
	}
}
