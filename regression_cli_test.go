package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditCliWinsOverConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"enumerate":"ptum","max_requests":99,"crawl_pages":7,"stealth":false,"random_user_agent":false,"no_brute":false,"fail_on":"low","strict_wp":false,"per_host_rate_limit":5}`
	cp := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cp, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	target, o := parseScanArgs([]string{"http://example.test", "--enumerate", "u", "--max-requests", "11", "--crawl-pages", "3", "--stealth", "--random-user-agent", "--no-brute", "--fail-on", "high", "--strict-wp", "--per-host-rate-limit", "0", "--config", cp})
	if target != "http://example.test" {
		t.Fatalf("target=%q", target)
	}
	if o.enumerate != "u" {
		t.Errorf("enumerate=%q want u (CLI wins)", o.enumerate)
	}
	if o.maxReq != 11 {
		t.Errorf("maxReq=%d want 11", o.maxReq)
	}
	if o.crawlPages != 3 {
		t.Errorf("crawlPages=%d want 3", o.crawlPages)
	}
	if !o.stealth {
		t.Errorf("stealth=false want true")
	}
	if !o.randomUA {
		t.Errorf("randomUA=false want true")
	}
	if !o.noBrute {
		t.Errorf("noBrute=false want true")
	}
	if o.failOn != "high" {
		t.Errorf("failOn=%q want high", o.failOn)
	}
	if !o.strictWP {
		t.Errorf("strictWP=false want true")
	}
	if o.perHostRateLimit != 0 {
		t.Errorf("perHostRateLimit=%v want 0 (explicit 0 wins over 5)", o.perHostRateLimit)
	}
}

func TestAuditStreamImpliesJsonlAfterConfig(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cp, []byte(`{"format":"json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// stream without explicit format: config format json would previously clobber jsonl; now stream forces jsonl only when format not explicitly set via CLI.
	// With config format set and no CLI format, stream implication runs after config: since setFlags[format] is false, stream sets jsonl (documented behavior).
	_, o := parseScanArgs([]string{"http://example.test", "--stream", "--config", cp})
	if o.format != "jsonl" {
		t.Errorf("format=%q want jsonl (stream implies jsonl when CLI format unset)", o.format)
	}
	_, o2 := parseScanArgs([]string{"http://example.test", "--stream", "--format", "json", "--config", cp})
	if o2.format != "json" {
		t.Errorf("format=%q want json (explicit CLI wins over stream)", o2.format)
	}
}

func TestAuditSplitNucleiArgsQuoted(t *testing.T) {
	got := splitNucleiArgs(`-H "X-Api-Key: x" -u 'a b' plain`)
	want := []string{"-H", "X-Api-Key: x", "-u", "a b", "plain"}
	if len(got) != len(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d: got %q want %q (full %q)", i, got[i], want[i], got)
		}
	}
}
