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
	"github.com/Boreas37/onyx/internal/nuclei"
	"github.com/Boreas37/onyx/internal/pocs"
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
		fmt.Println("onyx 0.2.0")
	default:
		usage()
		os.Exit(2)
	}
}

// scanOptions holds the parsed scan flags.
type scanOptions struct {
	dbPath              string
	threads             int
	timeout             int
	format              string
	apiOnly             bool
	stealth             bool
	rateLimit           float64
	verbose             bool
	minSeverity         string
	enumerate           string
	maxReq              int
	output              string
	silent              bool
	progress            bool
	userAgent           string
	randomUA            bool
	detectionMode       string
	proxy               string
	noXMLRPC            bool
	checks              string
	connectTimeout      int
	requestTimeout      int
	contentDir          string
	pluginsDir          string
	excludeContentBased string
	scope               string
	noUpdateCheck       bool
	pluginsList         string
	themesList          string
	maxScanDuration     time.Duration
	maxScanDurationSpec string
	cacheTTL            time.Duration
	stream              bool
	configPath          string
	nuclei              bool
	nucleiTemplateDir   string
	nucleiArgs          string
	pocTrackerDir       string
	noPocs              bool
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
	setFlags := make(map[string]bool)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.format = "json"
			setFlags["format"] = true
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
			setFlags["detection-mode"] = true
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
		case a == "--exclude-content-based" && i+1 < len(args):
			i++
			o.excludeContentBased = args[i]
		case a == "--scope" && i+1 < len(args):
			i++
			o.scope = args[i]
		case a == "--no-update-check":
			o.noUpdateCheck = true
		case a == "--format" && i+1 < len(args):
			i++
			o.format = strings.ToLower(args[i])
			setFlags["format"] = true
		case a == "--min-severity" && i+1 < len(args):
			i++
			o.minSeverity = strings.ToLower(args[i])
			setFlags["min-severity"] = true
		case a == "--db" && i+1 < len(args):
			i++
			o.dbPath = args[i]
		case a == "--threads" && i+1 < len(args):
			i++
			o.threads = atoi(args[i], 5)
			setFlags["threads"] = true
		case a == "--timeout" && i+1 < len(args):
			i++
			o.timeout = atoi(args[i], 10)
		case a == "--rate-limit" && i+1 < len(args):
			i++
			rl, err := strconv.ParseFloat(args[i], 64)
			if err == nil && rl > 0 {
				o.rateLimit = rl
				setFlags["rate-limit"] = true
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
		case a == "--plugins-list" && i+1 < len(args):
			i++
			o.pluginsList = args[i]
		case a == "--themes-list" && i+1 < len(args):
			i++
			o.themesList = args[i]
		case a == "--max-scan-duration" && i+1 < len(args):
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid --max-scan-duration %q (use Go duration format, e.g. 30s or 5m)\n", args[i])
				os.Exit(2)
			}
			o.maxScanDuration = d
			o.maxScanDurationSpec = args[i]
		case a == "--cache-ttl" && i+1 < len(args):
			i++
			o.cacheTTL = time.Duration(atoi(args[i], 0)) * time.Hour
		case a == "--stream":
			o.stream = true
		case a == "--nuclei":
			o.nuclei = true
		case a == "--nuclei-template-dir" && i+1 < len(args):
			i++
			o.nucleiTemplateDir = args[i]
		case a == "--nuclei-args" && i+1 < len(args):
			i++
			o.nucleiArgs = args[i]
		case a == "--poc-tracker-dir" && i+1 < len(args):
			i++
			o.pocTrackerDir = args[i]
		case a == "--no-pocs":
			o.noPocs = true
		case a == "--config" && i+1 < len(args):
			i++
			o.configPath = args[i]
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "unknown flag:", a)
			os.Exit(2)
		default:
			if target == "" {
				target = a
				setFlags["url"] = true
			}
		}
	}
	// --stream alone implies --format jsonl.
	if o.stream && !setFlags["format"] {
		o.format = "jsonl"
	}
	// --config FILE: JSON defaults overridden by explicit CLI flags.
	if o.configPath != "" {
		if err := applyConfig(&o, &target, setFlags, o.configPath); err != nil {
			fmt.Fprintln(os.Stderr, "error loading config:", err)
			os.Exit(2)
		}
	}
	if o.enumerate != "" {
		for _, c := range o.enumerate {
			if !strings.ContainsRune("ptum", c) {
				fmt.Fprintf(os.Stderr, "invalid --enumerate value %q (use p, t, u and/or m)\n", o.enumerate)
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

// applyConfig overlays the known keys of a JSON config file onto o. CLI
// flags (tracked in setFlags) always win; unknown keys are ignored.
func applyConfig(o *scanOptions, target *string, setFlags map[string]bool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg struct {
		URL           string   `json:"url"`
		Threads       *int     `json:"threads"`
		RateLimit     *float64 `json:"rate_limit"`
		DetectionMode *string  `json:"detection_mode"`
		Format        *string  `json:"format"`
		MinSeverity   *string  `json:"min_severity"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if !setFlags["url"] && cfg.URL != "" {
		*target = cfg.URL
	}
	if !setFlags["threads"] && cfg.Threads != nil {
		o.threads = *cfg.Threads
	}
	if !setFlags["rate-limit"] && cfg.RateLimit != nil {
		o.rateLimit = *cfg.RateLimit
	}
	if !setFlags["detection-mode"] && cfg.DetectionMode != nil {
		o.detectionMode = strings.ToLower(*cfg.DetectionMode)
	}
	if !setFlags["format"] && cfg.Format != nil {
		o.format = strings.ToLower(*cfg.Format)
	}
	if !setFlags["min-severity"] && cfg.MinSeverity != nil {
		o.minSeverity = strings.ToLower(*cfg.MinSeverity)
	}
	return nil
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// staleDays returns how many whole days old the file at path is, or -1 when
// its age cannot be determined (e.g. missing file).
func staleDays(path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return int(time.Since(fi.ModTime()).Hours() / 24)
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
  --enumerate M      enumerate p (plugins), t (themes), u (users), m (media); combine (default: pt)
  --max-requests N   cap on brute-force enumeration requests (default: 500)
  --output FILE      write JSON results to FILE (table still prints to stdout)
  --silent           suppress progress output
  --progress         show live progress bar while scanning (off by default)
  --user-agent UA    send a custom User-Agent string on every request
  --random-user-agent  use a random browser User-Agent per request
  --detection-mode M detection: passive (homepage only), aggressive (DB only), mixed (default)
  --proxy URL        route requests through an http(s) proxy (socks5 unsupported)
  --no-xmlrpc        skip the XML-RPC (xmlrpc.php) ping check
  --checks LIST      run extra checks: cb (config backups), dbe (db exports), timthumb; combine with commas
  --connect-timeout S  TCP connect timeout in seconds (default: 10)
  --request-timeout S  per-request timeout in seconds (default: 10; --timeout is an alias)
  --wp-content-dir PATH  wp-content directory (default: wp-content)
  --wp-plugins-dir PATH  plugins directory (default: wp-content/plugins)
  --exclude-content-based REGEX  abort the scan when homepage HTML matches REGEX (WAF/error page)
  --scope REGEX     only scan when the target URL matches REGEX
  --no-update-check suppress the stale-database warning
  --plugins-list FILE  enumerate exactly the plugin slugs listed in FILE (one per line, # comments)
  --themes-list FILE   enumerate exactly the theme slugs listed in FILE (one per line, # comments)
  --max-scan-duration D  stop the scan after D (Go duration format, e.g. 30s or 5m)
  --cache-ttl HOURS  cache HTTP responses on disk for HOURS (default: 0 = off; dir: ~/.cache/onyx/http or $ONYX_CACHE_DIR)
  --stream           emit findings as JSON Lines the moment they are found (implies --format jsonl)
  --nuclei           verify findings against projectdiscovery templates (needs the nuclei binary)
  --nuclei-template-dir PATH  template directory (default: ~/nuclei-templates or $NUCLEI_TEMPLATES_DIR)
  --nuclei-args ARGS extra arguments passed to nuclei (shell-free split, quotes supported)
  --poc-tracker-dir PATH  local clone of CVE-PoC-Tracker (default: ~/projects/cve-tracker or $POC_TRACKER_DIR)
  --no-pocs          skip PoC reference lookup (nuclei findings only)
  --config FILE      JSON config file; explicit CLI flags win over config values
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

	// Warn (informational only) when the local database is over 14 days old.
	if !o.noUpdateCheck {
		if days := staleDays(o.dbPath); days > 14 {
			fmt.Fprintf(os.Stderr, "[WARN] database is %d days old — run 'onyx update' for fresh data\n", days)
		}
	}

	if o.format == "table" {
		report.PrintBanner("0.2.0", database.Count())
	}

	// --timeout stays as an alias for --request-timeout.
	reqTimeout := o.requestTimeout
	if reqTimeout == 0 {
		reqTimeout = o.timeout
	}

	// --stream: findings are emitted as JSON Lines the moment they are
	// found (only meaningful with --format jsonl).
	var findings chan scanner.Finding
	var streamDone chan struct{}
	if o.stream && o.format == "jsonl" {
		findings = make(chan scanner.Finding)
		streamDone = make(chan struct{})
		go func() {
			defer close(streamDone)
			enc := json.NewEncoder(os.Stdout)
			for f := range findings {
				_ = enc.Encode(&f)
			}
		}()
	}

	sc, err := scanner.NewScanner(database, target, scanner.Options{
		Threads:             o.threads,
		Timeout:             time.Duration(o.timeout) * time.Second,
		ConnectTimeout:      time.Duration(o.connectTimeout) * time.Second,
		RequestTimeout:      time.Duration(reqTimeout) * time.Second,
		APIOnly:             o.apiOnly,
		Stealth:             o.stealth,
		RateLimit:           o.rateLimit,
		MaxRequests:         o.maxReq,
		Enumerate:           o.enumerate,
		UserAgent:           o.userAgent,
		RandomUA:            o.randomUA,
		DetectionMode:       o.detectionMode,
		Proxy:               o.proxy,
		NoXMLRPC:            o.noXMLRPC,
		Checks:              o.checks,
		ContentDir:          o.contentDir,
		PluginsDir:          o.pluginsDir,
		ExcludeContentBased: o.excludeContentBased,
		Scope:               o.scope,
		PluginsList:         o.pluginsList,
		ThemesList:          o.themesList,
		MaxScanDuration:     o.maxScanDuration,
		CacheTTL:            o.cacheTTL,
		Findings:            findings,
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
	if streamDone != nil {
		<-streamDone
	}
	if res != nil && res.TimedOut {
		spec := o.maxScanDurationSpec
		if spec == "" {
			spec = o.maxScanDuration.String()
		}
		fmt.Fprintf(os.Stderr, "[WARN] scan timed out after %s — results may be incomplete\n", spec)
	}
	if err != nil && res == nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		return 2
	}

	if pr := sc.Progress(); pr != nil {
		pr.Finish()
	}

	// --nuclei: after the regular scan, verify every CVE from the findings
	// with projectdiscovery templates. Hard failures degrade to WARNs — the
	// scan result is never discarded because nuclei is missing or crashed.
	if o.nuclei && res != nil {
		verifyWithNuclei(res, o)
		if !o.noPocs {
			collectPoCs(res, o)
		}
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
		if !o.stream {
			report.PrintJSONL(res)
		}
	case "sarif":
		report.PrintSARIF("0.2.0", res)
	default:
		report.PrintTable(res, o.verbose, o.minSeverity)
	}
	return scanExitCode(res, err)
}

// scanExitCode maps a scan outcome onto the onyx exit codes: 0 when the
// scan completed with no findings (including non-WordPress targets), 5 when
// findings were found (by the scanner or by nuclei verification), 2 on
// outright failure.
func scanExitCode(res *scanner.Result, err error) int {
	if err != nil && res == nil {
		return 2
	}
	if len(res.Findings) > 0 || len(res.Nuclei) > 0 {
		return 5
	}
	return 0
}

// verifyWithNuclei drives the --nuclei pipeline after a scan: collect the
// unique CVE ids from res.Findings, resolve one template per CVE, run the
// nuclei binary once with all templates, and append every match to
// res.Nuclei. Every failure along the way is soft — a WARN to stderr and a
// skip, never an error.
func verifyWithNuclei(res *scanner.Result, o scanOptions) {
	seen := make(map[string]bool)
	var cves []string
	for i := range res.Findings {
		for _, v := range res.Findings[i].Vulnerabilities {
			if v.CVE == "" || seen[v.CVE] {
				continue
			}
			seen[v.CVE] = true
			cves = append(cves, v.CVE)
		}
	}
	if len(cves) == 0 {
		return
	}

	// Resolve the nuclei binary first: when it is missing the whole
	// pipeline is skipped (soft fail) without spamming template WARNs.
	if _, err := nuclei.NucleiBinary(); err != nil {
		fmt.Fprintln(os.Stderr, "[WARN] nuclei not found in PATH — skipping verification")
		return
	}

	dir := o.nucleiTemplateDir
	if dir == "" {
		dir = os.Getenv("NUCLEI_TEMPLATES_DIR")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, "nuclei-templates")
		}
	}
	dir = expandHome(dir)

	var templates []string
	for _, cve := range cves {
		tpl, ok := nuclei.FindTemplate(dir, cve)
		if !ok {
			fmt.Fprintf(os.Stderr, "[WARN] no nuclei template for %s\n", cve)
			continue
		}
		templates = append(templates, tpl)
	}
	if len(templates) == 0 {
		return
	}

	results, err := nuclei.Run(res.Target, templates, splitNucleiArgs(o.nucleiArgs))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] nuclei verification failed: %v — skipping verification\n", err)
		return
	}
	res.Nuclei = results
}

// collectPoCs enriches nuclei findings with the top-5 most-starred PoC
// repositories per CVE, looked up in a local clone of CVE-PoC-Tracker.
// Every failure is soft: a missing tracker clone produces a WARN, a CVE
// missing from the tracker is skipped silently, and GitHub API errors
// fall back to the star counts from the tracker table (never 0) with the
// links still listed.
func collectPoCs(res *scanner.Result, o scanOptions) {
	if len(res.Nuclei) == 0 {
		return
	}
	dir := o.pocTrackerDir
	if dir == "" {
		dir = os.Getenv("POC_TRACKER_DIR")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, "projects", "cve-tracker")
		}
	}
	dir = expandHome(dir)
	if dir == "" {
		return
	}
	if _, err := os.Stat(dir); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] CVE-PoC-Tracker not found at %s — skipping PoC lookup\n", dir)
		return
	}

	seen := make(map[string]bool)
	var cves []string
	for _, n := range res.Nuclei {
		if n.CVE == "" || seen[n.CVE] {
			continue
		}
		seen[n.CVE] = true
		cves = append(cves, n.CVE)
	}
	if len(cves) == 0 {
		return
	}

	fetcher := pocs.NewFetcher(os.Getenv("GITHUB_TOKEN"))
	for _, cve := range cves {
		found := pocs.ExtractLinks(dir, cve)
		if len(found) == 0 {
			continue
		}
		top := pocs.TopByStars(fetcher.Fetch(found))
		for i := range top {
			top[i].CVE = cve
		}
		res.PoCs = append(res.PoCs, top...)
	}
}

// splitNucleiArgs splits a --nuclei-args string into direct exec arguments
// (never through a shell). Whitespace separates arguments; double and
// single quotes group words, e.g. `-H "X-Api-Key: x"` yields
// [-H, X-Api-Key: x].
func splitNucleiArgs(s string) []string {
	var args []string
	start := -1
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				args = append(args, s[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, s[start:])
	}
	return args
}

// expandHome replaces a leading ~/ (and bare ~) with the user's home
// directory.
func expandHome(p string) string {
	if p == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
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
