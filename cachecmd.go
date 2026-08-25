package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// cacheDir returns the onyx HTTP response cache directory: $ONYX_CACHE_DIR
// when set, otherwise ~/.cache/onyx/http — the same location the scanner
// uses for --cache-ttl.
func cacheDir() string {
	if v := os.Getenv("ONYX_CACHE_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cache", "onyx", "http")
}

// runCache drives the `onyx cache` subcommands: read-only stats and a
// destructive purge of the on-disk HTTP response cache.
//
//	onyx cache stats
//	onyx cache purge
func runCache(args []string) int {
	if len(args) != 1 {
		cacheUsage()
		return 2
	}
	switch args[0] {
	case "stats":
		return cacheStats()
	case "purge":
		return cachePurge()
	default:
		fmt.Fprintf(os.Stderr, "unknown cache command %q\n\n", args[0])
		cacheUsage()
		return 2
	}
}

func cacheUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  onyx cache stats
  onyx cache purge`)
}

// cacheStats prints the cache directory, entry count, total size and the
// oldest/newest entry mtimes. A missing cache directory is a warning, not
// an error.
func cacheStats() int {
	dir := cacheDir()
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "[WARN] no cache directory")
			return 0
		}
		fmt.Fprintln(os.Stderr, "cache stats:", err)
		return 2
	}
	count := 0
	var total int64
	var oldest, newest time.Time
	var walkErr error
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p == dir || d.IsDir() {
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil {
			walkErr = ierr
			return nil
		}
		count++
		total += fi.Size()
		m := fi.ModTime()
		if oldest.IsZero() || m.Before(oldest) {
			oldest = m
		}
		if m.After(newest) {
			newest = m
		}
		return nil
	}); err != nil && walkErr == nil {
		walkErr = err
	}
	if walkErr != nil {
		fmt.Fprintln(os.Stderr, "cache stats:", walkErr)
		return 2
	}
	fmt.Printf("cache dir:     %s\n", dir)
	fmt.Printf("entries:       %d\n", count)
	fmt.Printf("total size:    %d bytes\n", total)
	if count == 0 {
		fmt.Printf("oldest entry:  n/a\n")
		fmt.Printf("newest entry:  n/a\n")
	} else {
		fmt.Printf("oldest entry:  %s\n", oldest.Format(time.RFC3339))
		fmt.Printf("newest entry:  %s\n", newest.Format(time.RFC3339))
	}
	return 0
}

// cachePurge deletes every cache entry (recursively) and removes the
// cache directory itself when it ends up empty. A missing cache directory
// counts as zero entries purged.
func cachePurge() int {
	dir := cacheDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("purged 0 entries")
			return 0
		}
		fmt.Fprintln(os.Stderr, "cache purge:", err)
		return 2
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			n, dErr := countEntries(filepath.Join(dir, e.Name()))
			if dErr != nil {
				fmt.Fprintln(os.Stderr, "cache purge:", dErr)
				return 2
			}
			count += n
		} else {
			count++
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, "cache purge:", err)
		return 2
	}
	fmt.Printf("purged %d entries\n", count)
	return 0
}

// countEntries counts the files under dir (non-recursive callers count
// the top-level entries themselves).
func countEntries(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p != dir && !d.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}
