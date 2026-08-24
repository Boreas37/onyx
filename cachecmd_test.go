package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCacheEntry(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunCacheStats(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "http")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ONYX_CACHE_DIR", dir)
	writeCacheEntry(t, dir, "a", "hello")
	writeCacheEntry(t, dir, "sub/b", "world")

	var code int
	out := captureStdoutDB(t, func() { code = runCache([]string{"stats"}) })
	if code != 0 {
		t.Fatalf("runCache stats exit = %d, want 0", code)
	}
	for _, want := range []string{
		"cache dir:     " + dir,
		"entries:       2",
		"total size:    10 bytes",
		"oldest entry:",
		"newest entry:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stats output missing %q in:\n%s", want, out)
		}
	}
}

func TestRunCacheStatsMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	t.Setenv("ONYX_CACHE_DIR", dir)
	var code int
	errOut := captureStderr(t, func() { code = runCache([]string{"stats"}) })
	if code != 0 {
		t.Fatalf("runCache stats exit = %d, want 0", code)
	}
	if !strings.Contains(errOut, "[WARN] no cache directory") {
		t.Errorf("missing dir stats stderr = %q, want WARN", errOut)
	}
}

func TestRunCachePurge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "http")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ONYX_CACHE_DIR", dir)
	writeCacheEntry(t, dir, "a", "hello")
	writeCacheEntry(t, dir, "sub/b", "world")

	var code int
	out := captureStdoutDB(t, func() { code = runCache([]string{"purge"}) })
	if code != 0 {
		t.Fatalf("runCache purge exit = %d, want 0", code)
	}
	if !strings.Contains(out, "purged 2 entries") {
		t.Errorf("purge output = %q, want 'purged 2 entries'", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cache dir %s still exists after purge (err=%v)", dir, err)
	}
}

func TestRunCachePurgeMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	t.Setenv("ONYX_CACHE_DIR", dir)
	var code int
	out := captureStdoutDB(t, func() { code = runCache([]string{"purge"}) })
	if code != 0 {
		t.Fatalf("runCache purge exit = %d, want 0", code)
	}
	if !strings.Contains(out, "purged 0 entries") {
		t.Errorf("missing dir purge output = %q, want 'purged 0 entries'", out)
	}
}

func TestRunCacheUnknownCommand(t *testing.T) {
	t.Setenv("ONYX_CACHE_DIR", t.TempDir())
	if code := runCache([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown cache command exit = %d, want 2", code)
	}
	if code := runCache(nil); code != 2 {
		t.Errorf("cache without subcommand exit = %d, want 2", code)
	}
}

func TestCacheDirDefault(t *testing.T) {
	t.Setenv("ONYX_CACHE_DIR", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".cache", "onyx", "http")
	if got := cacheDir(); got != want {
		t.Errorf("cacheDir() = %q, want %q", got, want)
	}
}
