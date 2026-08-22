package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveProfileBuiltins(t *testing.T) {
	for _, name := range []string{"stealth", "aggressive", "fast"} {
		path, cleanup, err := resolveProfile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer cleanup()
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("%s: %v", name, rerr)
		}
		if !strings.Contains(string(data), "threads") {
			t.Errorf("%s preset missing threads: %s", name, data)
		}
	}
}

func TestResolveProfileFromFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	customDir := filepath.Join(dir, ".onyx", "profiles")
	if mErr := os.MkdirAll(customDir, 0o755); mErr != nil {
		t.Fatal(mErr)
	}
	if wErr := os.WriteFile(filepath.Join(customDir, "mine.json"), []byte(`{"threads":7}`), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	path, cleanup, err := resolveProfile("mine")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if filepath.Base(path) != "mine.json" {
		t.Fatalf("resolved %q", path)
	}
	if _, _, err := resolveProfile("nope"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}

func TestProfileAppliesAndCliWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	target, o := parseScanArgs([]string{"http://example.test", "--profile", "stealth"})
	if o.threads != 1 || !o.stealth || o.maxReq != 300 || !o.randomUA {
		t.Fatalf("stealth profile not applied: %+v", o)
	}
	if target != "http://example.test" {
		t.Fatalf("target = %q", target)
	}

	// Explicit flag beats the profile.
	_, o = parseScanArgs([]string{"http://example.test", "--threads", "8", "--profile", "stealth"})
	if o.threads != 8 {
		t.Fatalf("--threads lost to profile: %d", o.threads)
	}
	if o.maxReq != 300 {
		t.Fatalf("other profile values must still apply: maxReq=%d", o.maxReq)
	}

	// Custom file profile via $HOME.
	customDir := filepath.Join(dir, ".onyx", "profiles")
	if mErr := os.MkdirAll(customDir, 0o755); mErr != nil {
		t.Fatal(mErr)
	}
	if wErr := os.WriteFile(filepath.Join(customDir, "mine.json"),
		[]byte(`{"threads":3,"format":"jsonl","fail_on":"high"}`), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	_, o = parseScanArgs([]string{"http://example.test", "--profile", "mine"})
	if o.threads != 3 || o.format != "jsonl" || o.failOn != "high" {
		t.Fatalf("custom profile not applied: %+v", o)
	}

	// Unknown profile is a hard error (os.Exit) — assert via subprocess-free
	// path: parseScanArgs calls os.Exit(2) directly, so guard with a helper
	// that would otherwise return.
	if _, _, err := resolveProfile("definitely-missing"); err == nil {
		t.Fatal("missing profile must error at resolution time")
	}
}
