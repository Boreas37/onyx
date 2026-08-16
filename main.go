package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/report"
	"github.com/Boreas37/onyx/internal/scanner"
)

const defaultDB = "data/wordfence.json"

func main() {
	updCmd := flag.NewFlagSet("update", flag.ExitOnError)
	updDB := updCmd.String("db", defaultDB, "destination database path")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		target, opts := parseScanArgs(os.Args[2:])
		if target == "" {
			fmt.Fprintln(os.Stderr, "error: scan needs a target URL")
			usage()
			os.Exit(2)
		}
		runScan(target, opts)
	case "update":
		updCmd.Parse(os.Args[2:])
		if err := update(*updDB); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("onyx 0.1.0")
	default:
		usage()
		os.Exit(2)
	}
}

// scanOptions holds the parsed scan flags.
type scanOptions struct {
	dbPath     string
	threads    int
	timeout    int
	asJSON     bool
	apiOnly    bool
	stealth    bool
	rateLimit  float64
	verbose    bool
	minSeverity string
}

// parseScanArgs parses `scan` arguments by hand so flags can come before or
// after the target URL (the stdlib flag package stops at the first non-flag
// argument, which breaks `onyx scan http://x --json`).
func parseScanArgs(args []string) (target string, o scanOptions) {
	o.dbPath = defaultDB
	o.threads = 5
	o.timeout = 10
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.asJSON = true
		case a == "--api":
			o.apiOnly = true
		case a == "--stealth":
			o.stealth = true
		case a == "--verbose":
			o.verbose = true
		case a == "--min-severity" && i+1 < len(args):
			i++
			o.minSeverity = strings.ToLower(args[i])
		case a == "--db" && i+1 < len(args):
			i++
			o.dbPath = args[i]
		case a == "--threads" && i+1 < len(args):
			i++
			o.threads = atoi(args[i], 5)
		case a == "--timeout" && i+1 < len(args):
			i++
			o.timeout = atoi(args[i], 10)
		case a == "--rate-limit" && i+1 < len(args):
			i++
			rl, err := strconv.ParseFloat(args[i], 64)
			if err == nil && rl > 0 {
				o.rateLimit = rl
			}
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "unknown flag:", a)
			os.Exit(2)
		default:
			if target == "" {
				target = a
			}
		}
	}
	return target, o
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func usage() {
	fmt.Fprintf(os.Stderr, `onyx — local-first WordPress vulnerability scanner

Usage:
  onyx scan <url> [flags]    scan a WordPress site
  onyx update [flags]        fetch the latest database
  onyx version               print the version

Scan flags:
  --db PATH          database file (default: %s)
  --threads N        concurrent requests (default: 5)
  --timeout S        per-request timeout in seconds (default: 10)
  --json             print results as JSON
  --api              only query the REST API, skip brute-force enumeration
  --stealth          one request per second
  --rate-limit N     max requests per second (overrides --stealth)
  --verbose          full one-line-per-finding output (default: compact)
  --min-severity S   only show findings >= severity (critical|high|medium|low)
`, defaultDB)
}

func runScan(target string, o scanOptions) {
	if _, err := os.Stat(o.dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "database not found at %s — fetching it first...\n", o.dbPath)
		if err := update(o.dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			os.Exit(1)
		}
	}

	database, err := db.Load(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		os.Exit(1)
	}

	if !o.asJSON {
		report.PrintBanner("0.1.0", database.Count())
	}

	sc, err := scanner.NewScanner(database, target, scanner.Options{
		Threads:   o.threads,
		Timeout:   time.Duration(o.timeout) * time.Second,
		APIOnly:   o.apiOnly,
		Stealth:   o.stealth,
		RateLimit: o.rateLimit,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	res, err := sc.Scan()
	if err != nil && res == nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	if o.asJSON {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}
	report.PrintTable(res, o.verbose, o.minSeverity)
}

// update fetches the newest database release from the onyx-db GitHub repo,
// downloads the compressed feed asset, and unpacks it to dst.
func update(dst string) error {
	const repo = "Boreas37/onyx-db"
	const asset = "wordfence-latest.json.gz"

	fmt.Printf("update: fetching latest database from %s...\n", repo)

	// 1. Latest release metadata
	relURL := "https://api.github.com/repos/" + repo + "/releases/latest"
	req, err := http.NewRequest("GET", relURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "onyx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("release lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("release lookup: HTTP %d", resp.StatusCode)
	}

	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("release decode: %w", err)
	}

	var assetURL string
	for _, a := range rel.Assets {
		if a.Name == asset {
			assetURL = a.BrowserDownloadURL
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("asset %s not found in release %s", asset, rel.TagName)
	}

	// 2. Download the gzipped feed
	gzResp, err := http.Get(assetURL)
	if err != nil {
		return fmt.Errorf("asset download: %w", err)
	}
	defer gzResp.Body.Close()
	if gzResp.StatusCode != 200 {
		return fmt.Errorf("asset download: HTTP %d", gzResp.StatusCode)
	}

	// 3. Gunzip into a temp file, then move into place
	zr, err := gzip.NewReader(gzResp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer zr.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".onyx-db-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, zr); err != nil {
		tmp.Close()
		return fmt.Errorf("unpack: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	if fi, err := os.Stat(dst); err == nil {
		fmt.Printf("update: done — %s (%d bytes)\n", dst, fi.Size())
	}
	return nil
}
