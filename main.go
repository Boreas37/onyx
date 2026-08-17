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
	"github.com/Boreas37/onyx/internal/progress"
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
		os.Exit(runScan(target, opts))
	case "update":
		updCmd.Parse(os.Args[2:])
		if err := update(*updDB); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			os.Exit(2)
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
	dbPath         string
	threads        int
	timeout        int
	format         string
	apiOnly        bool
	stealth        bool
	rateLimit      float64
	verbose        bool
	minSeverity    string
	enumerate      string
	maxReq         int
	output         string
	silent         bool
	progress       bool
	userAgent      string
	randomUA       bool
	detectionMode  string
	proxy          string
	noXMLRPC       bool
	checks         string
	connectTimeout int
	requestTimeout int
	contentDir     string
	pluginsDir     string
}

// parseScanArgs parses `scan` arguments by hand so flags can come before or
// after the target URL (the stdlib flag package stops at the first non-flag
// argument, which breaks `onyx scan http://x --json`).
func parseScanArgs(args []string) (target string, o scanOptions) {
	o.dbPath = defaultDB
	o.threads = 5
	o.timeout = 10
	o.maxReq = 500
	o.format = "table"
	o.connectTimeout = 10
	o.contentDir = "wp-content"
	o.pluginsDir = "wp-content/plugins"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.format = "json"
		case a == "--api":
			o.apiOnly = true
		case a == "--stealth":
			o.stealth = true
		case a == "--verbose":
			o.verbose = true
		case a == "--progress":
			o.progress = true
		case a == "--silent":
			o.silent = true
		case a == "--random-user-agent":
			o.randomUA = true
		case a == "--user-agent" && i+1 < len(args):
			i++
			o.userAgent = args[i]
		case a == "--detection-mode" && i+1 < len(args):
			i++
			o.detectionMode = strings.ToLower(args[i])
		case a == "--proxy" && i+1 < len(args):
			i++
			o.proxy = args[i]
		case a == "--no-xmlrpc":
			o.noXMLRPC = true
		case a == "--checks" || a == "--check":
			if i+1 < len(args) {
				i++
				o.checks = strings.ToLower(args[i])
			}
		case a == "--connect-timeout" && i+1 < len(args):
			i++
			o.connectTimeout = atoi(args[i], 10)
		case a == "--request-timeout" && i+1 < len(args):
			i++
			o.requestTimeout = atoi(args[i], 10)
		case a == "--wp-content-dir" && i+1 < len(args):
			i++
			o.contentDir = args[i]
		case a == "--wp-plugins-dir" && i+1 < len(args):
			i++
			o.pluginsDir = args[i]
		case a == "--format" && i+1 < len(args):
			i++
			o.format = strings.ToLower(args[i])
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
		case a == "--enumerate" && i+1 < len(args):
			i++
			o.enumerate = strings.ToLower(args[i])
		case a == "--max-requests" && i+1 < len(args):
			i++
			o.maxReq = atoi(args[i], 500)
		case a == "--output" && i+1 < len(args):
			i++
			o.output = args[i]
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "unknown flag:", a)
			os.Exit(2)
		default:
			if target == "" {
				target = a
			}
		}
	}
	if o.enumerate != "" {
		for _, c := range o.enumerate {
			if !strings.ContainsRune("ptu", c) {
				fmt.Fprintf(os.Stderr, "invalid --enumerate value %q (use p, t and/or u)\n", o.enumerate)
				os.Exit(2)
			}
		}
	}
	switch o.format {
	case "table", "json", "jsonl", "sarif":
	default:
		fmt.Fprintf(os.Stderr, "invalid --format %q (use table, json, jsonl or sarif)\n", o.format)
		os.Exit(2)
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
  --format F         output format: table, json, jsonl, sarif (default: table)
  --json             print results as JSON (same as --format json)
  --api              only query the REST API, skip brute-force enumeration
  --stealth          one request per second
  --rate-limit N     max requests per second (overrides --stealth)
  --verbose          full one-line-per-finding output (default: compact)
  --min-severity S   only show findings >= severity (critical|high|medium|low)
  --enumerate M      enumerate p (plugins), t (themes), u (users); combine (default: pt)
  --max-requests N   cap on brute-force enumeration requests (default: 500)
  --output FILE      write JSON results to FILE (table still prints to stdout)
  --silent           suppress progress output
  --progress         show live progress bar while scanning (off by default)
  --user-agent UA    send a custom User-Agent string on every request
  --random-user-agent  use a random browser User-Agent per request
  --detection-mode M detection: passive (homepage only), aggressive (DB only), mixed (default)
  --proxy URL        route requests through an http(s) proxy (socks5 unsupported)
  --no-xmlrpc        skip the XML-RPC (xmlrpc.php) ping check
  --checks LIST      run extra checks: cb (config backups), dbe (db exports); combine with commas
  --connect-timeout S  TCP connect timeout in seconds (default: 10)
  --request-timeout S  per-request timeout in seconds (default: 10; --timeout is an alias)
  --wp-content-dir PATH  wp-content directory (default: wp-content)
  --wp-plugins-dir PATH  plugins directory (default: wp-content/plugins)
`, defaultDB)
}

func runScan(target string, o scanOptions) int {
	if _, err := os.Stat(o.dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "database not found at %s — fetching it first...\n", o.dbPath)
		if err := update(o.dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			return 2
		}
	}

	database, err := db.Load(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return 2
	}

	if o.format == "table" {
		report.PrintBanner("0.1.0", database.Count())
	}

	// --timeout stays as an alias for --request-timeout.
	reqTimeout := o.requestTimeout
	if reqTimeout == 0 {
		reqTimeout = o.timeout
	}

	sc, err := scanner.NewScanner(database, target, scanner.Options{
		Threads:        o.threads,
		Timeout:        time.Duration(o.timeout) * time.Second,
		ConnectTimeout: time.Duration(o.connectTimeout) * time.Second,
		RequestTimeout: time.Duration(reqTimeout) * time.Second,
		APIOnly:        o.apiOnly,
		Stealth:        o.stealth,
		RateLimit:      o.rateLimit,
		MaxRequests:    o.maxReq,
		Enumerate:      o.enumerate,
		UserAgent:      o.userAgent,
		RandomUA:       o.randomUA,
		DetectionMode:  o.detectionMode,
		Proxy:          o.proxy,
		NoXMLRPC:       o.noXMLRPC,
		Checks:         o.checks,
		ContentDir:     o.contentDir,
		PluginsDir:     o.pluginsDir,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	// Progress bar is on by default (a single live line showing a
	// percentage bar — no per-request noise). --silent disables it.
	if !o.silent {
		bar := progress.New(os.Stderr, false)
		sc.SetProgress(bar)
	}

	res, err := sc.Scan()
	if err != nil && res == nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		return 2
	}

	if pr := sc.Progress(); pr != nil {
		pr.Finish()
	}

	if o.output != "" {
		if werr := writeScanOutput(o.output, res); werr != nil {
			fmt.Fprintln(os.Stderr, "error writing output:", werr)
		} else if pr := sc.Progress(); pr != nil {
			pr.LogInf("results written to %s", o.output)
		}
	}

	switch o.format {
	case "json":
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
	case "jsonl":
		report.PrintJSONL(res)
	case "sarif":
		report.PrintSARIF("0.1.0", res)
	default:
		report.PrintTable(res, o.verbose, o.minSeverity)
	}
	return scanExitCode(res, err)
}

// scanExitCode maps a scan outcome onto the onyx exit codes: 0 when the
// scan completed with no findings (including non-WordPress targets), 5 when
// findings were found, 2 on outright failure.
func scanExitCode(res *scanner.Result, err error) int {
	if err != nil && res == nil {
		return 2
	}
	if len(res.Findings) > 0 {
		return 5
	}
	return 0
}

// writeScanOutput serializes res as indented JSON to path, creating the
// parent directory if needed.
func writeScanOutput(path string, res *scanner.Result) error {
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
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
