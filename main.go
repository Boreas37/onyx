package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/dbupdate"
	"github.com/Boreas37/onyx/internal/intel"
	"github.com/Boreas37/onyx/internal/nuclei"
	"github.com/Boreas37/onyx/internal/pocs"
	"github.com/Boreas37/onyx/internal/progress"
	"github.com/Boreas37/onyx/internal/report"
	"github.com/Boreas37/onyx/internal/scanner"
	"github.com/Boreas37/onyx/internal/watch"
)

const (
	onyxVersion     = "1.0.0"
	defaultDB       = "data/wordfence.json"
	feedProduction  = "production"
	feedScanner     = "scanner"
	scannerFeedURL  = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
	productionRepo  = "Boreas37/onyx-db"
	productionAsset = "wordfence-latest.json.gz"
)

// buildCommit and buildTime are injected at build time via
// -ldflags "-X main.buildCommit=<sha> -X main.buildTime=<RFC3339>".
// Local builds leave them empty, reported as "unknown" in --json output.
var buildCommit, buildTime string

func main() {
	updCmd := flag.NewFlagSet("update", flag.ExitOnError)
	updDB := updCmd.String("db", defaultDB, "destination database path")
	updFeed := updCmd.String("feed", feedProduction, "feed to fetch (production or scanner)")
	updForce := updCmd.Bool("force", false, "skip the checksum check and always rewrite the database")

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
		all := append([]string{target}, opts.targets...)
		if len(all) == 1 {
			os.Exit(runScan(target, opts))
		}
		os.Exit(runMulti(all, opts))
	case "update":
		_ = updCmd.Parse(os.Args[2:]) // ExitOnError flag set: never returns an error
		feed := strings.ToLower(*updFeed)
		if feed != feedProduction && feed != feedScanner {
			fmt.Fprintf(os.Stderr, "error: invalid --feed %q (use production or scanner)\n", feed)
			os.Exit(2)
		}
		if err := update(*updDB, feed, *updForce); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			os.Exit(2)
		}
	case "watch":
		target, opts, wopts := parseWatchArgs(os.Args[2:])
		if target == "" {
			fmt.Fprintln(os.Stderr, "error: watch needs a target URL")
			usage()
			os.Exit(2)
		}
		os.Exit(runWatch(target, opts, wopts))
	case "version":
		if slices.Contains(os.Args[2:], "--check") {
			if err := runVersionCheck(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			os.Exit(0)
		}
		if slices.Contains(os.Args[2:], "--json") {
			fmt.Println(versionJSON())
		} else {
			fmt.Println("onyx", onyxVersion)
		}
	case "db":
		os.Exit(runDB(os.Args[2:]))
	case "cache":
		os.Exit(runCache(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "diff":
		os.Exit(runDiff(os.Args[2:]))
	case "example-config":
		os.Exit(runExampleConfig(os.Args[2:]))
	case "completion":
		os.Exit(runCompletion(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

// versionInfo is the machine-readable shape of `onyx version --json`.
type versionInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// versionJSON renders build metadata as a single-line JSON object. Commit
// and build time come from ldflags (release builds); local builds report
// "unknown" for both.
func versionJSON() string {
	commit, ts := buildCommit, buildTime
	if commit == "" {
		commit = "unknown"
	}
	if ts == "" {
		ts = "unknown"
	}
	info := versionInfo{
		Version:   onyxVersion,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Commit:    commit,
		BuildTime: ts,
	}
	b, err := json.Marshal(info)
	if err != nil {
		return `{"error": "cannot marshal version info"}`
	}
	return string(b)
}

// scanOptions holds the parsed scan flags.
type scanOptions struct {
	dbPath               string
	threads              int
	timeout              int
	format               string
	apiOnly              bool
	stealth              bool
	rateLimit            float64
	verbose              bool
	minSeverity          string
	enumerate            string
	maxReq               int
	output               string
	silent               bool
	progress             bool
	userAgent            string
	randomUA             bool
	detectionMode        string
	proxy                string
	proxyAuth            string
	proxyTargetOnly      bool
	tlsFingerprint       string
	perHostRateLimit     float64
	noXMLRPC             bool
	checks               string
	connectTimeout       int
	requestTimeout       int
	contentDir           string
	pluginsDir           string
	excludeContentBased  string
	scope                string
	noUpdateCheck        bool
	noUpdate             bool
	pluginsList          string
	themesList           string
	maxScanDuration      time.Duration
	maxScanDurationSpec  string
	cacheTTL             time.Duration
	stream               bool
	configPath           string
	nuclei               bool
	nucleiTemplateDir    string
	nucleiArgs           string
	pocTrackerDir        string
	noPocs               bool
	passwordsFile        string
	usernamesFile        string
	user                 string
	xmlrpcBrute          string
	mcMaxPasswords       int
	wpAuth               string
	noBrute              bool
	noSummary            bool
	strictWP             bool
	targets              []string
	targetsFile          string
	profile              string
	crawlPages           int
	failOn               string
	noIntel              bool
	fingerprintDB        string
	popularSlugs         bool
	allowForeignRedirect bool
	retries              int
	jobs                 int
	discover404          bool
	popularFile          string
	popularThemes        bool
	wpVersion            string
	disableTLSChecks     bool
	updateDB             bool
	failOnRateLimited    bool
	nucleiMinSeverity    string
	outputs              []string

	basicAuthUser string
	basicAuthPass string
	cookie        string
	headers       map[string]string
	vhost         string
	force         bool
	excludeVulns  []string
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
	o.popularSlugs = true
	o.popularThemes = true
	o.retries = 2
	o.jobs = 1
	o.discover404 = true
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
		case a == "--proxy-auth" && i+1 < len(args):
			i++
			o.proxyAuth = args[i]
		case a == "--proxy-target-only":
			o.proxyTargetOnly = true
		case a == "--tls-fingerprint" && i+1 < len(args):
			i++
			o.tlsFingerprint = strings.ToLower(args[i])
		case a == "--per-host-rate-limit" && i+1 < len(args):
			i++
			phl, err := strconv.ParseFloat(args[i], 64)
			if err == nil && phl > 0 {
				o.perHostRateLimit = phl
			}
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
		case a == "--no-update":
			o.noUpdate = true
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
		case a == "--passwords" && i+1 < len(args):
			i++
			o.passwordsFile = args[i]
		case a == "--usernames" && i+1 < len(args):
			i++
			o.usernamesFile = args[i]
		case a == "--user" && i+1 < len(args):
			i++
			o.user = args[i]
		case a == "--xmlrpc-brute" && i+1 < len(args):
			i++
			o.xmlrpcBrute = args[i]
		case a == "--multicall-max-passwords" && i+1 < len(args):
			i++
			o.mcMaxPasswords = atoi(args[i], 3)
		case a == "--wp-auth" && i+1 < len(args):
			i++
			o.wpAuth = args[i]
		case a == "--no-brute":
			o.noBrute = true
		case a == "--no-summary":
			o.noSummary = true
		case a == "--strict-wp":
			o.strictWP = true
		case a == "--crawl-pages" && i+1 < len(args):
			i++
			o.crawlPages = atoi(args[i], 25)
		case a == "--fail-on" && i+1 < len(args):
			i++
			o.failOn = strings.ToLower(args[i])
			if severityRankOf(o.failOn) == 0 {
				fmt.Fprintf(os.Stderr, "error: invalid --fail-on %q (use critical, high, medium or low)\n", args[i])
				os.Exit(2)
			}
		case a == "--no-intel":
			o.noIntel = true
		case a == "--fingerprint-db" && i+1 < len(args):
			i++
			o.fingerprintDB = args[i]
		case a == "--no-popular":
			o.popularSlugs = false
		case a == "--allow-foreign-redirect":
			o.allowForeignRedirect = true
		case a == "--retries" && i+1 < len(args):
			i++
			o.retries = atoi(args[i], 2)
		case a == "--jobs" && i+1 < len(args):
			i++
			o.jobs = atoi(args[i], 1)
			if o.jobs < 1 {
				fmt.Fprintln(os.Stderr, "error: --jobs must be >= 1")
				os.Exit(2)
			}
		case a == "--wp-version" && i+1 < len(args):
			i++
			o.wpVersion = args[i]
		case a == "--disable-tls-checks":
			o.disableTLSChecks = true
		case a == "--update-db":
			o.updateDB = true
		case a == "--no-discover-404":
			o.discover404 = false
		case a == "--fail-on-rate-limited":
			o.failOnRateLimited = true
		case a == "--nuclei-min-severity" && i+1 < len(args):
			i++
			sev := strings.ToLower(args[i])
			switch sev {
			case "critical", "high", "medium", "low", "info":
			default:
				fmt.Fprintf(os.Stderr, "error: invalid --nuclei-min-severity %q (use critical, high, medium, low or info)\n", args[i])
				os.Exit(2)
			}
			o.nucleiMinSeverity = sev
		case a == "--outputs" && i+1 < len(args):
			i++
			for _, f := range strings.Split(args[i], ",") {
				f = strings.ToLower(strings.TrimSpace(f))
				if f == "" {
					continue
				}
				switch f {
				case "table", "cli-no-colour", "json", "jsonl", "sarif", "csv", "cyclonedx",
					"markdown", "md", "html", "junit", "gitlab-sast":
				default:
					fmt.Fprintf(os.Stderr, "error: invalid --outputs format %q\n", f)
					os.Exit(2)
				}
				o.outputs = append(o.outputs, f)
			}
		case a == "--profile" && i+1 < len(args):
			i++
			o.profile = args[i]
		case a == "-T" && i+1 < len(args), a == "--targets" && i+1 < len(args):
			i++
			o.targetsFile = args[i]
		case a == "--config" && i+1 < len(args):
			i++
			o.configPath = args[i]
		case a == "--basic-auth" && i+1 < len(args):
			i++
			user, pass, err := splitBasicAuth(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid --basic-auth %q (use USER:PASS)\n", args[i])
				os.Exit(2)
			}
			o.basicAuthUser, o.basicAuthPass = user, pass
		case a == "--cookie" && i+1 < len(args):
			i++
			o.cookie = args[i]
		case a == "--headers" && i+1 < len(args):
			i++
			hdr, err := parseHeaders(args[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid --headers: %v\n", err)
				os.Exit(2)
			}
			o.headers = hdr
		case a == "--vhost" && i+1 < len(args):
			i++
			o.vhost = args[i]
		case a == "--force":
			o.force = true
		case a == "--exclude-vulns" && i+1 < len(args):
			i++
			o.excludeVulns = parseExcludeVulns(args[i])
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "unknown flag:", a)
			os.Exit(2)
		default:
			if target == "" {
				target = a
				setFlags["url"] = true
			} else {
				o.targets = append(o.targets, a)
			}
		}
	}
	// --stream alone implies --format jsonl.
	if o.stream && !setFlags["format"] {
		o.format = "jsonl"
	}
	// Config cascade: when no explicit --config was given, look for a
	// defaults file in the standard locations (first match wins), the
	// same convention WPScan follows. Explicit CLI flags still win over
	// anything discovered.
	if o.configPath == "" {
		if discovered := discoverConfig(); discovered != "" {
			o.configPath = discovered
		}
	}
	// --config FILE: JSON defaults overridden by explicit CLI flags.
	if o.configPath != "" {
		if err := applyConfig(&o, &target, setFlags, o.configPath); err != nil {
			fmt.Fprintln(os.Stderr, "error loading config:", err)
			os.Exit(2)
		}
	}
	if o.profile != "" {
		ppath, pcleanup, perr := resolveProfile(o.profile)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "error loading profile:", perr)
			os.Exit(2)
		}
		defer pcleanup()
		if aerr := applyConfig(&o, &target, setFlags, ppath); aerr != nil {
			fmt.Fprintln(os.Stderr, "error loading profile:", aerr)
			os.Exit(2)
		}
	}
	if o.enumerate != "" {
		validToken := func(tok string) bool {
			switch tok {
			case "p", "vp", "ap", "t", "vt", "at", "u", "m":
				return true
			}
			return false
		}
		tokens := strings.Split(o.enumerate, ",")
		allTokens := true
		for _, tok := range tokens {
			if !validToken(strings.ToLower(strings.TrimSpace(tok))) {
				allTokens = false
				break
			}
		}
		if !allTokens {
			// Legacy bare-letter form ("ptum"): validate per rune and
			// keep popular seeds on for both kinds.
			if strings.Contains(o.enumerate, ",") {
				fmt.Fprintf(os.Stderr, "invalid --enumerate value %q (use p, vp, ap, t, vt, at, u and/or m; comma-separated)\n", o.enumerate)
				os.Exit(2)
			}
			for _, c := range o.enumerate {
				if !strings.ContainsRune("ptum", c) {
					fmt.Fprintf(os.Stderr, "invalid --enumerate value %q (use p, t, u and/or m)\n", o.enumerate)
					os.Exit(2)
				}
			}
		} else {
			// Normalize the tokens back to the scanner's single-letter
			// alphabet (p/t/u/m): the v/a prefixes only carry the
			// popular-seed mapping above, and the scanner derives
			// enumeration purely from substring presence.
			var norm []byte
			for _, tok := range tokens {
				tok = strings.ToLower(strings.TrimSpace(tok))
				switch tok {
				case "p", "ap":
					o.popularSlugs = true
					norm = append(norm, 'p')
				case "vp":
					o.popularSlugs = false
					norm = append(norm, 'p')
				case "t", "at":
					o.popularThemes = true
					norm = append(norm, 't')
				case "vt":
					o.popularThemes = false
					norm = append(norm, 't')
				case "u":
					norm = append(norm, 'u')
				case "m":
					norm = append(norm, 'm')
				}
			}
			o.enumerate = string(norm)
		}
	}
	switch o.format {
	case "table", "cli-no-colour", "json", "jsonl", "sarif", "csv", "cyclonedx",
		"markdown", "md", "html", "junit", "gitlab-sast":
	default:
		fmt.Fprintf(os.Stderr, "invalid --format %q (use table, cli-no-colour, json, jsonl, sarif, csv, cyclonedx, markdown, html, junit or gitlab-sast)\n", o.format)
		os.Exit(2)
	}
	if o.targetsFile != "" {
		data, err := os.ReadFile(o.targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading --targets: %v\n", err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			o.targets = append(o.targets, line)
		}
	}
	return target, o
}

// discoverConfig returns the path of the first existing onyx defaults
// file, following the usual cascade: $XDG_CONFIG_HOME/onyx/scan.json,
// ~/.config/onyx/scan.json and ./onyx.json (current directory). It
// returns "" when none exists.
func discoverConfig() string {
	var candidates []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "onyx", "scan.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "onyx", "scan.json"))
	}
	candidates = append(candidates, filepath.Join(".", "onyx.json"))
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// applyConfig overlays the known keys of a JSON config file onto o. CLI
// flags (tracked in setFlags) always win; unknown keys are ignored.
func applyConfig(o *scanOptions, target *string, setFlags map[string]bool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg struct {
		URL            string   `json:"url"`
		Threads        *int     `json:"threads"`
		RateLimit      *float64 `json:"rate_limit"`
		DetectionMode  *string  `json:"detection_mode"`
		Format         *string  `json:"format"`
		MinSeverity    *string  `json:"min_severity"`
		Enumerate      *string  `json:"enumerate"`
		MaxRequests    *int     `json:"max_requests"`
		CrawlPages     *int     `json:"crawl_pages"`
		Stealth        *bool    `json:"stealth"`
		RandomUA       *bool    `json:"random_user_agent"`
		NoBrute        *bool    `json:"no_brute"`
		FailOn         *string  `json:"fail_on"`
		StrictWP       *bool    `json:"strict_wp"`
		PerHostLimiter *float64 `json:"per_host_rate_limit"`
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
	if !setFlags["enumerate"] && cfg.Enumerate != nil {
		o.enumerate = strings.ToLower(*cfg.Enumerate)
	}
	if !setFlags["max-requests"] && cfg.MaxRequests != nil {
		o.maxReq = *cfg.MaxRequests
	}
	if !setFlags["crawl-pages"] && cfg.CrawlPages != nil {
		o.crawlPages = *cfg.CrawlPages
	}
	if !setFlags["stealth"] && cfg.Stealth != nil {
		o.stealth = *cfg.Stealth
	}
	if !setFlags["random-user-agent"] && cfg.RandomUA != nil {
		o.randomUA = *cfg.RandomUA
	}
	if !setFlags["no-brute"] && cfg.NoBrute != nil {
		o.noBrute = *cfg.NoBrute
	}
	if !setFlags["fail-on"] && cfg.FailOn != nil {
		o.failOn = strings.ToLower(*cfg.FailOn)
	}
	if !setFlags["strict-wp"] && cfg.StrictWP != nil {
		o.strictWP = *cfg.StrictWP
	}
	if !setFlags["per-host-rate-limit"] && cfg.PerHostLimiter != nil {
		o.perHostRateLimit = *cfg.PerHostLimiter
	}
	return nil
}

// builtinProfiles are named option presets shipped with onyx. Values here
// are applied like a config file: explicit CLI flags always win.
var builtinProfiles = map[string]string{
	// stealth: one request per second, randomized UA, trimmed request
	// budget — for targets where getting blocked matters more than speed.
	"stealth": `{"threads":1,"rate_limit":1,"random_user_agent":true,"stealth":true,"max_requests":300,"crawl_pages":0}`,
	// aggressive: wide-open enumeration with sitemap discovery.
	"aggressive": `{"threads":20,"detection_mode":"aggressive","max_requests":1500,"crawl_pages":25,"enumerate":"ptum"}`,
	// fast: quick surface pass — passive only, no brute force.
	"fast": `{"threads":10,"detection_mode":"passive","enumerate":"pt","max_requests":200,"no_brute":true}`,
}

// resolveProfile returns the config-file path for a --profile name:
// built-in presets render to a temp file; anything else is looked up in
// $HOME/.onyx/profiles/<name>.json then ./.onyx/profiles/<name>.json.
func resolveProfile(name string) (path string, cleanup func(), err error) {
	cleanup = func() {}
	if js, ok := builtinProfiles[name]; ok {
		tmp, tErr := os.CreateTemp("", ".onyx-profile-*")
		if tErr != nil {
			return "", cleanup, tErr
		}
		if _, wErr := tmp.WriteString(js); wErr != nil {
			tmp.Close()
			return "", cleanup, wErr
		}
		p := tmp.Name()
		return p, func() { os.Remove(p) }, tmp.Close()
	}
	home := ""
	if h, hErr := os.UserHomeDir(); hErr == nil {
		home = filepath.Join(h, ".onyx", "profiles", name+".json")
	}
	for _, candidate := range []string{home, filepath.Join(".onyx", "profiles", name+".json")} {
		if candidate == "" {
			continue
		}
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, cleanup, nil
		}
	}
	return "", cleanup, fmt.Errorf("unknown profile %q (built-ins: stealth, aggressive, fast — or a file in ~/.onyx/profiles/)", name)
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// splitBasicAuth splits a USER:PASS value on the first colon; a value
// without a colon is malformed.
func splitBasicAuth(v string) (user, pass string, err error) {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected USER:PASS")
	}
	return parts[0], parts[1], nil
}

// parseHeaders parses a comma-separated "Name: value,Name2: value2"
// header list into a map. Names and values are trimmed; a pair without a
// colon or with an empty header name is malformed. Empty list parts
// (trailing commas) are ignored.
func parseHeaders(v string) (map[string]string, error) {
	h := make(map[string]string)
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 {
			return nil, fmt.Errorf("malformed header %q (use \"Name: value\")", part)
		}
		name := strings.TrimSpace(pair[0])
		if name == "" {
			return nil, fmt.Errorf("empty header name in %q", part)
		}
		h[name] = strings.TrimSpace(pair[1])
	}
	return h, nil
}

// parseExcludeVulns splits a comma-separated vulnerability ID list,
// dropping empty entries.
func parseExcludeVulns(v string) []string {
	var ids []string
	for _, id := range strings.Split(v, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// dbAgeDays returns how many whole days have passed since the database at
// dbPath was last downloaded, or -1 when its age cannot be determined. The
// age is measured from the .sha256 sidecar (written on every real
// download); when the sidecar is missing the database file's own mtime is
// used as a fallback.
func dbAgeDays(dbPath string) int {
	agePath := dbPath
	if _, err := os.Stat(dbPath + ".sha256"); err == nil {
		agePath = dbPath + ".sha256"
	}
	fi, err := os.Stat(agePath)
	if err != nil {
		return -1
	}
	return int(time.Since(fi.ModTime()).Hours() / 24)
}

// dbFeedType returns the feed that produced the database at dbPath
// ("production" or "scanner"), read from the .feedtype sidecar written by
// update. Missing or unknown sidecar content falls back to production.
func dbFeedType(dbPath string) string {
	b, err := os.ReadFile(dbPath + ".feedtype")
	if err != nil {
		return feedProduction
	}
	switch strings.TrimSpace(string(b)) {
	case feedProduction, feedScanner:
		return strings.TrimSpace(string(b))
	}
	return feedProduction
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
  --format F         output format: table, cli-no-colour, json, jsonl, sarif, csv, cyclonedx, md, html, junit, gitlab-sast (default: table)
  --json             print results as JSON (same as --format json)
  --api              only query the REST API, skip brute-force enumeration
  --stealth          one request per second
  --rate-limit N     max requests per second (overrides --stealth)
  --verbose          full one-line-per-finding output (default: compact)
  --min-severity S   only show findings >= severity (critical|high|medium|low)
  --enumerate M      enumerate p/vp/ap (plugins), t/vt/at (themes), u (users), m (media); comma-separated (default: pt)
  --max-requests N   cap on brute-force enumeration requests (default: 500)
  --output FILE      write JSON results to FILE (CSV with --format csv; table still prints to stdout)
  --no-summary       omit the scan summary section (stats are in the JSON "summary" field otherwise)
  --silent           suppress progress output
  --progress         show live progress bar while scanning (off by default)
  --user-agent UA    send a custom User-Agent string on every request
  --random-user-agent  use a random browser User-Agent per request
  --detection-mode M detection: passive (homepage only), aggressive (DB only), mixed (default)
  --proxy URL        route requests through an http(s) or socks5/socks5h proxy
  --proxy-auth USER:PASS  authenticate to a SOCKS5 proxy (RFC 1929 username/password)
  --proxy-target-only  use the proxy only for the scanned target host (other connections direct)
  --tls-fingerprint MODE  TLSClientConfig variation: chrome, firefox or random (per-request rotation)
  --per-host-rate-limit N  max requests per second per host (each host gets its own limiter)
  --basic-auth USER:PASS  send HTTP Basic authentication (admin:secret) on every request
  --cookie COOKIE         send a raw Cookie header, e.g. "wordpress_sec=abc; wp_lang=en"
  --headers LIST          send extra request headers, comma-separated "Name: value" pairs
  --vhost HOST            use HOST as the HTTP Host header (virtual-host scanning)
  --force                 scan anyway when the target does not look like WordPress
  --exclude-vulns LIST    drop vulnerability IDs from the report (comma-separated)
  --no-xmlrpc        skip the XML-RPC (xmlrpc.php) ping check
  --checks LIST      run extra checks: cb (config backups), dbe (db exports), timthumb; combine with commas
  --connect-timeout S  TCP connect timeout in seconds (default: 10)
  --request-timeout S  per-request timeout in seconds (default: 10; --timeout is an alias)
  --wp-content-dir PATH  wp-content directory (default: wp-content)
  --wp-plugins-dir PATH  plugins directory (default: wp-content/plugins)
  --exclude-content-based REGEX  abort the scan when homepage HTML matches REGEX (WAF/error page)
  --scope REGEX     only scan when the target URL matches REGEX
  --no-update-check suppress the stale-database warning
  --no-update       error out (exit 2) instead of auto-downloading the database when it is missing
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
  --passwords FILE   wordlist of passwords (one per line) — enables the wp-login brute force (needs --usernames FILE or --enumerate u)
  --usernames FILE   wordlist of usernames (one per line) for brute-force attacks
  --user USER        single username for the XML-RPC multicall attack (--xmlrpc-brute)
  --xmlrpc-brute FILE  XML-RPC multicall password attack (wp.getUsersBlogs; needs --usernames FILE or --user USER)
  --multicall-max-passwords N  passwords per XML-RPC multicall request (default: 3)
  --wp-auth USER:PASS  authenticated REST inventory over HTTP Basic auth — use a WordPress Application Password (wp-admin → Users → Profile → Application Passwords)
  --no-brute         disable credential brute force (wp-login and XML-RPC)
  --strict-wp        exit with code 3 when the target does not look like WordPress (default: warn and continue)
  --crawl-pages N    fetch N sitemap pages for passive plugin/theme discovery (default: 0 = off)
  -T, --targets FILE scan several targets sequentially (one URL per line; # comments); exit code aggregates
  --fail-on SEV      only exit 5 when findings >= SEV exist (critical/high/medium/low); default: any finding
  --no-intel         skip EPSS/CISA KEV enrichment
  --fingerprint-db FILE  JSON core-fingerprint table (md5 file hashes -> versions)
  --no-popular       do not append the static popular plugin/theme slug lists
  --allow-foreign-redirect  follow redirects to hosts other than the target
  --retries N        retry transient network errors N times (default: 2, 0 = off)
  --jobs N           scan -T/extra targets with up to N concurrent scans (default: 1)
  --no-discover-404  do not probe a nonexistent path for plugin/theme references
  --fail-on-rate-limited  exit 4 when the target's 429 throttling cut the scan short
  --disable-tls-checks    skip TLS certificate verification (MITM proxies)
  --update-db             refresh a database older than 14 days before scanning
  --nuclei-min-severity S  only run nuclei templates of S or worse (critical|high|medium|low|info)
  --outputs LIST     write extra copies of the report (comma list of formats)
  --config FILE      JSON config file; explicit CLI flags win over config values

Watch mode:
  onyx watch URL [--interval D] [--webhook URL] [scan flags]
  --interval D       re-scan every duration (30m, 1h); default: single compare-and-exit pass
  --webhook URL      POST a JSON change report when new/resolved vulnerabilities appear
  --webhook-format F payload shape: generic (default) or slack
  --jsonl            emit each watch pass as one JSON line (machine-readable)
  --state-dir DIR    where baselines are stored (default: user cache dir /onyx/watch)

Database inspection:
  onyx db stats|lookup SLUG|top [N]|search QUERY|diff B.json [--db PATH]

Cache management:
  onyx cache stats               show the HTTP cache directory, entry count, total size and entry ages
  onyx cache purge               delete all cached HTTP responses (and the cache dir when empty)

Diagnostics & helpers:
  onyx doctor [--db PATH] [--network]   local health checks (offline by default)
  onyx diff A.json B.json               compare two saved scan results
  onyx example-config                   print a commented JSON config template

Shell completions:
  onyx completion bash|zsh|fish     (add the output to your shell config)

Update flags:
  --db PATH          destination database file (default: %s)
  --feed F           feed to fetch: production (default) or scanner
  --force            skip the checksum check and rewrite the database even when unchanged
   ONYX_MANIFEST_URL  override the update manifest URL (mirror overrides/testing)
   ONYX_ALLOW_OLDER_MANIFEST=1  accept a manifest older than the last accepted one (disables the delta-path downgrade guard)
`, defaultDB, defaultDB)
}

// scanSignalContext returns a context cancelled on SIGINT or SIGTERM so
// an interactive interrupt stops the in-flight scan cleanly instead of
// killing the process mid-request.
func scanSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// scannerOptionsForRun builds the scanner options for a single runScan
// invocation, attaching the signal-based context unless a scan-wide
// deadline is configured: when MaxScanDuration > 0 the scanner builds
// its own timeout ctx, which requestCtx() prefers over Options.Context.
func scannerOptionsForRun(o scanOptions, findings chan scanner.Finding, ctx context.Context) scanner.Options {
	opts := scannerOptionsFrom(o, findings)
	if o.maxScanDuration == 0 {
		opts.Context = ctx
	}
	return opts
}

func runScan(target string, o scanOptions) int {
	ctx, cancel := scanSignalContext()
	defer cancel()

	if _, err := os.Stat(o.dbPath); err != nil {
		if o.noUpdate {
			fmt.Fprintf(os.Stderr, "error: database not found at %s (--no-update given — run 'onyx update' first)\n", o.dbPath)
			return 2
		}
		fmt.Fprintf(os.Stderr, "database not found at %s — fetching it first...\n", o.dbPath)
		if err := update(o.dbPath, feedProduction, false); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			return 2
		}
	} else if o.updateDB && !o.noUpdate {
		// --update-db: refresh a stale database (older than 14 days)
		// before scanning. Network failures degrade to a warning — the
		// existing data still gets scanned.
		if days := dbAgeDays(o.dbPath); days > 14 {
			fmt.Fprintf(os.Stderr, "database is %d days old — refreshing...\n", days)
			if err := update(o.dbPath, feedProduction, false); err != nil {
				fmt.Fprintln(os.Stderr, "[WARN] update failed (scanning with existing data):", err)
			}
		}
	}

	database, err := db.LoadCached(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return 2
	}
	// Optional data assets that `onyx update` mirrors next to the feed:
	// a popular-list file and a core-fingerprint table. When present they
	// become the defaults for the corresponding scan features.
	if o.popularFile == "" {
		if _, perr := os.Stat(filepath.Join(filepath.Dir(o.dbPath), "popular.json")); perr == nil {
			o.popularFile = filepath.Join(filepath.Dir(o.dbPath), "popular.json")
		}
	}
	if o.fingerprintDB == "" {
		fp := filepath.Join(filepath.Dir(o.dbPath), "fingerprints.json")
		if _, ferr := os.Stat(fp); ferr == nil {
			o.fingerprintDB = fp
		}
	}

	// Warn (informational only) when the local database is over 14 days
	// old; the age reflects the last download and the warning names the
	// feed that produced the database.
	if !o.noUpdateCheck {
		if days := dbAgeDays(o.dbPath); days > 14 {
			fmt.Fprintf(os.Stderr, "[WARN] database is %d days old (%s feed) — run 'onyx update' for fresh data\n", days, dbFeedType(o.dbPath))
		}
	}

	if o.format == "table" || o.format == "cli-no-colour" {
		report.PrintBanner(onyxVersion, database.Count())
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

	sc, err := scanner.NewScanner(database, target, scannerOptionsForRun(o, findings, ctx))
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
	// An interrupted scan is not a hard failure: the scanner treats ctx
	// cancellation like a scan-wide deadline (workers stop, res.TimedOut
	// may be set), so warn and keep reporting whatever was collected.
	if ctx.Err() != nil && res != nil {
		fmt.Fprintln(os.Stderr, "[WARN] scan interrupted — results may be incomplete")
	}
	if res != nil && res.TimedOut {
		spec := o.maxScanDurationSpec
		if spec == "" {
			spec = o.maxScanDuration.String()
		}
		fmt.Fprintf(os.Stderr, "[WARN] scan timed out after %s — results may be incomplete\n", spec)
	}
	if err != nil && res == nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "[WARN] scan interrupted")
		}
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		return 2
	}

	if pr := sc.Progress(); pr != nil {
		pr.Finish()
	}

	// EPSS/KEV enrichment: annotate every finding with exploitation
	// intelligence and sort by real-world priority (KEV first, then EPSS,
	// then CVSS). Fully optional — offline or a broken feed degrades to a
	// WARN and the raw findings are still reported.
	if !o.noIntel && res != nil && len(res.Findings) > 0 {
		enrichFindings(res)
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
		if werr := writeScanOutput(o.output, res, o.format); werr != nil {
			fmt.Fprintln(os.Stderr, "error writing output:", werr)
		} else if pr := sc.Progress(); pr != nil {
			pr.LogInf("results written to %s", o.output)
		}
	}
	// --outputs: render the same result into several formats at once.
	// Each file is <output>.<format> (or onyx-report.<format> when
	// --output is unset); stdout still carries the --format rendering.
	for _, f := range o.outputs {
		if f == o.format {
			continue // already rendered above
		}
		if f == "table" || f == "cli-no-colour" {
			continue // table formats go to stdout only
		}
		base := o.output
		if base == "" {
			base = "onyx-report"
		}
		p := base + "." + f
		if werr := writeScanOutput(p, res, f); werr != nil {
			fmt.Fprintf(os.Stderr, "error writing %s output: %v\n", f, werr)
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
		report.PrintSARIF(onyxVersion, res)
	case "csv":
		report.PrintCSV(res)
	case "cyclonedx":
		report.PrintCycloneDX(onyxVersion, res)
	case "markdown", "md":
		report.PrintMarkdown(res)
	case "html":
		report.PrintHTML(res)
	case "junit":
		report.PrintJUnit(onyxVersion, res)
	case "gitlab-sast":
		report.PrintGitLabSAST(res)
	case "cli-no-colour":
		report.NoColor = true
		report.PrintTable(res, o.verbose, o.minSeverity)
		if !o.noSummary {
			report.PrintSummary(res)
		}
	default:
		report.PrintTable(res, o.verbose, o.minSeverity)
		if !o.noSummary {
			report.PrintSummary(res)
		}
	}
	return scanExitCode(res, err, o.strictWP, o.failOn, o.failOnRateLimited)
}

// runMulti scans several targets, printing a section header per target and
// aggregating exit codes: any hard failure (2) wins, then findings (5),
// then strict-WP misses (3), else 0. With --jobs N (N > 1) the targets are
// scanned concurrently with at most N in flight; because scans are
// network-bound this can cut wall time for large target files. Output
// order may then differ from the input order (each target still prints
// under its own "=== [i/N] target ===" header).
//
// Formats that cannot be meaningfully concatenated (json document, sarif,
// cyclonedx) are rejected up front; jsonl and csv are flat formats and
// concatenate naturally, table output simply repeats per target.
func runMulti(targets []string, o scanOptions) int {
	if len(targets) > 1 {
		switch o.format {
		case "table", "cli-no-colour", "jsonl", "csv":
		default:
			fmt.Fprintf(os.Stderr,
				"error: --format %s cannot represent multiple targets (use table, jsonl or csv)\n", o.format)
			return 2
		}
	}
	rank := func(c int) int {
		switch c {
		case 2:
			return 3
		case 4, 5:
			return 2
		case 3:
			return 1
		}
		return 0
	}
	worst := 0
	jobs := o.jobs
	if jobs < 1 {
		jobs = 1
	}
	if jobs == 1 || len(targets) == 1 {
		for i, t := range targets {
			if len(targets) > 1 {
				fmt.Fprintf(os.Stderr, "\n=== [%d/%d] %s ===\n", i+1, len(targets), t)
			}
			code := runScan(t, o)
			if rank(code) > rank(worst) {
				worst = code
			}
		}
		return worst
	}
	// Concurrent mode: bounded worker pool, codes aggregated afterwards.
	codes := make([]int, len(targets))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i, t := range targets {
		i, t := i, t
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fmt.Fprintf(os.Stderr, "\n=== [%d/%d] %s ===\n", i+1, len(targets), t)
			codes[i] = runScan(t, o)
		}()
	}
	wg.Wait()
	for _, c := range codes {
		if rank(c) > rank(worst) {
			worst = c
		}
	}
	return worst
}

// severityRankOf maps a severity name to a rank (critical=4 … low=1);
// unknown names return 0.
func severityRankOf(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// scanExitCode maps a scan outcome onto the onyx exit codes: 0 when the
// scan completed with no qualifying findings (including non-WordPress
// targets), 5 when findings were found (by the scanner or by nuclei
// verification), 3 when --strict-wp is set and the target turned out not
// to be WordPress, and 2 on outright failure. failOn raises the bar for
// exit 5: only findings at or above that severity count ("high" is the
// typical CI choice); an empty failOn keeps the old any-finding behavior.
func scanExitCode(res *scanner.Result, err error, strictWP bool, failOn string, failOnRateLimited bool) int {
	if err != nil && res == nil {
		return 2
	}
	if strictWP && errors.Is(err, scanner.ErrNotWordPress) {
		return 3
	}
	// A scan that the target's 429 throttling cut short is a distinct
	// signal for CI: with --fail-on-rate-limited it exits 4 (incomplete)
	// instead of reading as a clean pass.
	if failOnRateLimited && res != nil && res.RateLimitedAbort {
		return 4
	}
	// Nuclei-verified hits always count as failures: they are confirmed
	// exploitations, not version-inference guesses.
	if len(res.Nuclei) > 0 {
		return 5
	}
	if len(res.Findings) == 0 {
		return 0
	}
	if rank := severityRankOf(failOn); rank > 0 {
		for i := range res.Findings {
			f := &res.Findings[i]
			for _, v := range f.Vulnerabilities {
				if severityRankOf(strings.ToLower(v.Rating)) >= rank {
					return 5
				}
			}
		}
		return 0
	}
	return 5
}

// scannerOptionsFrom translates parsed CLI options into the scanner's
// Options struct; shared by `scan` and `watch` so both honor the same
// flags. findings may be nil (no streaming).
func scannerOptionsFrom(o scanOptions, findings chan scanner.Finding) scanner.Options {
	reqTimeout := o.requestTimeout
	if reqTimeout == 0 {
		reqTimeout = o.timeout
	}
	return scanner.Options{
		Threads:              o.threads,
		Timeout:              time.Duration(o.timeout) * time.Second,
		ConnectTimeout:       time.Duration(o.connectTimeout) * time.Second,
		RequestTimeout:       time.Duration(reqTimeout) * time.Second,
		APIOnly:              o.apiOnly,
		Stealth:              o.stealth,
		RateLimit:            o.rateLimit,
		MaxRequests:          o.maxReq,
		Enumerate:            o.enumerate,
		UserAgent:            o.userAgent,
		RandomUA:             o.randomUA,
		DetectionMode:        o.detectionMode,
		Proxy:                o.proxy,
		ProxyAuth:            o.proxyAuth,
		ProxyTargetOnly:      o.proxyTargetOnly,
		TLSFingerprint:       o.tlsFingerprint,
		PerHostRateLimit:     o.perHostRateLimit,
		NoXMLRPC:             o.noXMLRPC,
		Checks:               o.checks,
		ContentDir:           o.contentDir,
		PluginsDir:           o.pluginsDir,
		ExcludeContentBased:  o.excludeContentBased,
		Scope:                o.scope,
		PluginsList:          o.pluginsList,
		ThemesList:           o.themesList,
		MaxScanDuration:      o.maxScanDuration,
		CacheTTL:             o.cacheTTL,
		Findings:             findings,
		PasswordsFile:        o.passwordsFile,
		UsernamesFile:        o.usernamesFile,
		User:                 o.user,
		XMLRPCBrute:          o.xmlrpcBrute,
		MCPerRequest:         o.mcMaxPasswords,
		WPAuth:               o.wpAuth,
		NoBrute:              o.noBrute,
		NoSummary:            o.noSummary,
		CrawlPages:           o.crawlPages,
		FingerprintDB:        o.fingerprintDB,
		PopularSlugs:         o.popularSlugs,
		AllowForeignRedirect: o.allowForeignRedirect,
		MaxRetries:           o.retries,
		Discover404:          o.discover404,
		PopularFile:          o.popularFile,
		PopularThemes:        o.popularThemes,
		CoreVersionOverride:  o.wpVersion,
		InsecureTLS:          o.disableTLSChecks,
		MediaIDs:             mediaIDsFor(o.enumerate),
		BasicAuthUser:        o.basicAuthUser,
		BasicAuthPass:        o.basicAuthPass,
		Cookie:               o.cookie,
		Headers:              o.headers,
		VHost:                o.vhost,
		Force:                o.force,
		ExcludeVulns:         o.excludeVulns,
	}
}

// enrichFindings pulls the cached EPSS scores and CISA KEV catalog
// (downloading them into the user cache dir when stale) and reorders
// res.Findings by exploitation priority. Every failure mode is soft: a
// warning on stderr, un-enriched but still correct findings.
func enrichFindings(res *scanner.Result) {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	cacheDir := filepath.Join(base, "onyx", "intel")
	in, warns, err := intel.Load(cacheDir, http.DefaultClient, time.Now())
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "[WARN] intel: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] intel unavailable (%v) — findings are not EPSS/KEV-annotated\n", err)
		return
	}
	intel.Enrich(res.Findings, in)
}

// watchOptions are the flags unique to `onyx watch`.
type watchOptions struct {
	interval      time.Duration
	webhook       string
	webhookFormat string
	stateDir      string
	jsonl         bool
}

// parseWatchArgs parses `watch` arguments. A subset of scan flags is
// honored for the underlying scan; --interval loops forever when > 0,
// the default (0) runs a single compare-and-exit pass.
func parseWatchArgs(args []string) (target string, o scanOptions, w watchOptions) {
	o.dbPath = defaultDB
	o.threads = 5
	o.maxReq = 500
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--interval" && i+1 < len(args):
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "error: invalid --interval %q (use e.g. 30m, 1h)\n", args[i])
				os.Exit(2)
			}
			w.interval = d
		case a == "--webhook" && i+1 < len(args):
			i++
			w.webhook = args[i]
		case a == "--webhook-format" && i+1 < len(args):
			i++
			f := strings.ToLower(args[i])
			if f != "generic" && f != "slack" {
				fmt.Fprintf(os.Stderr, "error: invalid --webhook-format %q (use generic or slack)\n", args[i])
				os.Exit(2)
			}
			w.webhookFormat = f
		case a == "--state-dir" && i+1 < len(args):
			i++
			w.stateDir = args[i]
		case a == "--jsonl":
			w.jsonl = true
		case a == "--db" && i+1 < len(args):
			i++
			o.dbPath = args[i]
		case a == "--threads" && i+1 < len(args):
			i++
			o.threads = atoi(args[i], 5)
		case a == "--max-requests" && i+1 < len(args):
			i++
			o.maxReq = atoi(args[i], 500)
		case a == "--enumerate" && i+1 < len(args):
			i++
			o.enumerate = args[i]
		case a == "--silent":
			o.silent = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "unknown flag:", a)
			os.Exit(2)
		default:
			if target == "" {
				target = a
			}
		}
	}
	return target, o, w
}

// runWatch drives recurring scans with baseline diffing: every pass scans
// the target, diffs the findings against the stored state, reports new and
// resolved vulnerabilities, optionally POSTs a webhook on changes, and —
// when --interval is set — sleeps and repeats. Exit codes: 0 on success,
// 2 on hard failure.
func runWatch(target string, o scanOptions, w watchOptions) int {
	stateDir := w.stateDir
	if stateDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		stateDir = filepath.Join(base, "onyx", "watch")
	}

	pass := 0
	for {
		pass++
		database, err := db.LoadCached(o.dbPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error loading database:", err)
			return 2
		}
		sc, err := scanner.NewScanner(database, target, scannerOptionsFrom(o, nil))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		if !o.silent {
			sc.SetProgress(progress.New(os.Stderr, false))
		}
		res, err := sc.Scan()
		if pr := sc.Progress(); pr != nil {
			pr.Finish()
		}
		if err != nil && res == nil {
			fmt.Fprintln(os.Stderr, "scan failed:", err)
			return 2
		}
		if !o.noIntel && res != nil && len(res.Findings) > 0 {
			enrichFindings(res)
		}

		diff, err := watch.Run(target, res, watch.Options{
			StateDir:     stateDir,
			Webhook:      w.webhook,
			NotifyFormat: w.webhookFormat,
		}, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "watch error:", err)
			return 2
		}
		if w.jsonl {
			if j, jerr := watch.DiffToJSON(diff); jerr == nil {
				fmt.Println(string(j))
			} else {
				fmt.Fprintln(os.Stderr, "watch jsonl:", jerr)
			}
		} else {
			fmt.Printf("[%s] %s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"), diff.Summary())
		}
		if !diff.Empty() && !w.jsonl {
			watch.PrintDiff(diff)
		} else if w.webhook != "" && pass == 1 && !o.silent {
			// Run() already notified on first-run baselines; nothing else to do.
			_ = diff
		}

		if w.interval <= 0 {
			return 0
		}
		time.Sleep(w.interval)
	}
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

	extra := splitNucleiArgs(o.nucleiArgs)
	if o.nucleiMinSeverity != "" {
		// nuclei's own -severity filter skips low-value templates before
		// any request is made (no YAML parsing needed on our side).
		extra = append(extra, "-severity", o.nucleiMinSeverity)
	}
	results, err := nuclei.Run(res.Target, templates, extra)
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

// writeScanOutput serializes res to path in the requested format: CSV for
// --format csv, indented JSON otherwise. The parent directory is created
// if needed.
func writeScanOutput(path string, res *scanner.Result, format string) error {
	var out []byte
	switch format {
	case "csv":
		var buf bytes.Buffer
		if err := report.WriteCSV(&buf, res); err != nil {
			return err
		}
		out = buf.Bytes()
	case "sarif":
		var buf bytes.Buffer
		report.WriteSARIF(&buf, onyxVersion, res)
		out = buf.Bytes()
	case "cyclonedx":
		var buf bytes.Buffer
		report.WriteCycloneDX(&buf, onyxVersion, res)
		out = buf.Bytes()
	case "gitlab-sast":
		var buf bytes.Buffer
		report.WriteGitLabSAST(&buf, res)
		out = buf.Bytes()
	case "jsonl":
		var buf bytes.Buffer
		report.WriteJSONL(&buf, res)
		out = buf.Bytes()
	case "markdown", "md", "html", "junit":
		var buf bytes.Buffer
		if format == "markdown" {
			format = "md"
		}
		if err := writeFormatTo(&buf, format, res); err != nil {
			return err
		}
		out = buf.Bytes()
	default:
		j, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		out = append(j, '\n')
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, out, 0o644)
}

// writeFormatTo renders one of the text report formats into w.
func writeFormatTo(w io.Writer, format string, res *scanner.Result) error {
	switch format {
	case "csv":
		return report.WriteCSV(w, res)
	case "md":
		report.WriteMarkdown(w, res)
		return nil
	case "html":
		return report.WriteHTML(w, res)
	case "junit":
		return report.WriteJUnit(w, onyxVersion, res)
	case "gitlab-sast":
		report.WriteGitLabSAST(w, res)
		return nil
	}
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(j, '\n'))
	return err
}

// update fetches the newest feed and unpacks it to dst. feed selects the
// source: the production feed (gzipped asset of the latest onyx-db
// release, the default) or the scanner feed (broad-coverage Wordfence
// Intelligence endpoint). The raw downloaded bytes are SHA-256 hashed and
// stored next to the database; when the digest matches the previous
// download and force is false the database is left untouched ("already up
// to date"). force skips that check and always rewrites.
func update(dst, feed string, force bool) error {
	var (
		url string
		gz  bool
	)
	switch feed {
	case feedScanner:
		url, gz = scannerFeedURL, false
	case feedProduction:
		// Fast path: when a delta from the locally installed version is
		// available on the mirror, apply it instead of re-downloading the
		// whole 151MB feed. Any problem along the way falls back to the
		// classic full download, so this can never make update worse.
		if !force {
			done, err := updateViaDelta(dst)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] delta update unavailable (%v) — falling back to full download\n", err)
			} else if done {
				// A delta was applied (or the database was already current).
				// Warm the read index so subsequent scans start fast.
				if _, iErr := db.LoadCached(dst); iErr != nil {
					fmt.Fprintf(os.Stderr, "[WARN] index warm-up failed (scans will build it lazily): %v\n", iErr)
				}
				// Mirror optional data assets (popular lists, fingerprints) next to
				// the database so scans auto-use them. Every failure is a warning.
				if rel, rerr := latestReleaseAssets("https://api.github.com/repos/" + productionRepo + "/releases/latest"); rerr == nil {
					updateOptionalAssets(dst, rel)
				}
				return nil
			}
		}
		var err error
		url, err = productionAssetURL()
		if err != nil {
			return err
		}
		gz = true
	default:
		return fmt.Errorf("unknown feed %q (use production or scanner)", feed)
	}
	if err := updateFromURL(dst, url, gz, feed, force); err != nil {
		return err
	}
	// Signature verification happens inside updateFromURL, on the raw
	// published artifact before unpacking. Warm the read index so the
	// first scan after an update does not pay the full parse cost.
	if _, iErr := db.LoadCached(dst); iErr != nil {
		fmt.Fprintf(os.Stderr, "[WARN] index warm-up failed (scans will build it lazily): %v\n", iErr)
	}
	// Mirror optional data assets (popular lists, fingerprints) next to
	// the database so scans auto-use them (best-effort, warnings only).
	if rel, rerr := latestReleaseAssets("https://api.github.com/repos/" + productionRepo + "/releases/latest"); rerr == nil {
		updateOptionalAssets(dst, rel)
	}
	return nil
}

// dbPubKeyPath returns the minisign public key path configured for
// database signature verification, or "" when verification is off.
func dbPubKeyPath() string {
	if v := os.Getenv("ONYX_DB_PUBKEY"); v != "" {
		return v
	}
	return ""
}

// downloadToFile streams url into path without any re-encoding.
func downloadToFile(url, path string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "onyx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// copyFile copies the file at src to dst with 0o644 permissions,
// replacing any existing content.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// defaultManifestURL is where the mirror publishes its update manifest.
const defaultManifestURL = "https://raw.githubusercontent.com/" + productionRepo + "/main/manifest.json"

// manifestURL returns the update manifest location. $ONYX_MANIFEST_URL
// overrides the default (for mirror overrides and testing). Deltas listed
// in the manifest are keyed by the sha256 of the GZIPPED artifact a
// client last downloaded — the value stored in dst+".sha256", which is an
// upstream artifact pointer, not a hash of the local decompressed file.
func manifestURL() string {
	if v := os.Getenv("ONYX_MANIFEST_URL"); v != "" {
		return v
	}
	return defaultManifestURL
}

// dedupeManifestDeltas collapses manifest delta entries sharing the same
// from_sha256+path pair, keeping the first occurrence, so a mirror bug
// that published duplicate rows cannot cause repeated lookups.
func dedupeManifestDeltas(m *dbupdate.Manifest) {
	if m == nil || len(m.Deltas) < 2 {
		return
	}
	seen := make(map[string]bool, len(m.Deltas))
	kept := m.Deltas[:0]
	for _, d := range m.Deltas {
		key := d.FromSha256 + "\x00" + d.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, d)
	}
	m.Deltas = kept
}

// checkManifestFreshness implements the downgrade guard for the delta
// fast-path: when dst+".manifest-ts" holds an RFC3339 timestamp from a
// previously accepted manifest and the new manifest's generated_at is
// STRICTLY older, the mirror has regressed and applying its deltas would
// downgrade the database — return an error so the caller falls back to
// the full-download path. Missing or unparseable timestamps on either
// side skip the guard silently; ONYX_ALLOW_OLDER_MANIFEST=1 bypasses it.
func checkManifestFreshness(tsPath, generatedAt string) error {
	raw, err := os.ReadFile(tsPath)
	if err != nil {
		return nil // no baseline recorded yet
	}
	stored, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return nil // unparseable baseline: skip the guard
	}
	newT, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		return nil // empty/unparseable generated_at: skip the guard
	}
	if newT.Before(stored) {
		return fmt.Errorf("manifest is older than the last accepted one (downgrade blocked); set ONYX_ALLOW_OLDER_MANIFEST=1 to override")
	}
	return nil
}

// acceptManifestTimestamp records an accepted manifest's generated_at in
// dst+".manifest-ts", keeping the LATER of any existing stamp and the new
// value (RFC3339). Unparseable input leaves any existing stamp untouched;
// nothing is fatal — the stamp only feeds the freshness guard.
func acceptManifestTimestamp(tsPath, generatedAt string) {
	newT, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		return
	}
	best := newT
	if raw, rErr := os.ReadFile(tsPath); rErr == nil {
		if stored, pErr := time.Parse(time.RFC3339, strings.TrimSpace(string(raw))); pErr == nil && stored.After(best) {
			best = stored
		}
	}
	_ = os.WriteFile(tsPath, []byte(best.UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// updateViaDelta tries the incremental update path: read the local
// checksum, fetch the mirror manifest, and when a delta exists for the
// installed version, download + apply it. Returns done=true when the
// database was updated (or already current per the manifest), false when
// a full download should proceed. The result's checksum is taken from the
// manifest so subsequent runs keep chaining deltas.
//
// The local checksum is read from dst+".sha256", which stores the sha256
// of the GZIPPED artifact as published upstream — exactly the key the
// manifest's delta entries are indexed by. It is NOT a digest of the
// local decompressed database.
//
// Guards applied before any delta is trusted: duplicate manifest entries
// are collapsed (first wins), and a manifest strictly older than the last
// accepted one (dst+".manifest-ts") is rejected as a downgrade so the
// caller falls back to the full download.
func updateViaDelta(dst string) (bool, error) {
	prevBytes, err := os.ReadFile(dst + ".sha256")
	if err != nil || strings.TrimSpace(string(prevBytes)) == "" {
		return false, fmt.Errorf("no local checksum to delta from")
	}
	localSHA := strings.TrimSpace(string(prevBytes))

	raw, err := dbupdate.FetchManifestRaw(http.DefaultClient, manifestURL())
	if err != nil {
		return false, fmt.Errorf("manifest: %w", err)
	}
	// Signature gate for the manifest itself: when a pubkey is configured,
	// an unsigned or mis-signed manifest.json is a hard error — never a
	// silent acceptance. This closes the last unauthenticated link in the
	// delta chain (the manifest is what selects which delta to trust).
	if pub := dbPubKeyPath(); pub != "" {
		sigPath := dst + ".manifest.sig.tmp"
		defer os.Remove(sigPath)
		if dErr := downloadToFile(manifestURL()+".minisig", sigPath); dErr != nil {
			return false, fmt.Errorf("manifest signature fetch (pubkey configured): %w", dErr)
		}
		if vErr := dbupdate.VerifyManifest(pub, raw, sigPath); vErr != nil {
			return false, fmt.Errorf("manifest signature verification FAILED: %w", vErr)
		}
		fmt.Println("update: manifest signature verified")
	}
	m, err := dbupdate.ParseManifest(raw)
	if err != nil {
		return false, fmt.Errorf("manifest: %w", err)
	}
	dedupeManifestDeltas(m)

	tsPath := dst + ".manifest-ts"
	if os.Getenv("ONYX_ALLOW_OLDER_MANIFEST") != "1" {
		if err := checkManifestFreshness(tsPath, m.GeneratedAt); err != nil {
			return false, err
		}
	}

	if m.Full.Sha256 == localSHA {
		fmt.Printf("update: already up to date — %s\n", dst)
		acceptManifestTimestamp(tsPath, m.GeneratedAt)
		return true, nil
	}
	var entry *dbupdate.DeltaEntry
	for i := range m.Deltas {
		if m.Deltas[i].FromSha256 == localSHA {
			entry = &m.Deltas[i]
			break
		}
	}
	if entry == nil {
		return false, fmt.Errorf("no delta from the installed version")
	}

	deltaPath := dst + ".delta.tmp"
	defer os.Remove(deltaPath)
	if err := downloadToFile(entry.Path, deltaPath); err != nil {
		return false, fmt.Errorf("delta download: %w", err)
	}
	// Signature verification for deltas mirrors the full-download path:
	// when a pubkey is configured a missing or bad signature is a hard
	// error — never a silent downgrade.
	if pub := dbPubKeyPath(); pub != "" {
		sigPath := dst + ".delta.sig.tmp"
		defer os.Remove(sigPath)
		if dErr := downloadToFile(entry.Path+".minisig", sigPath); dErr != nil {
			return false, fmt.Errorf("delta signature fetch (pubkey configured): %w", dErr)
		}
		if vErr := dbupdate.VerifyMinisign(pub, sigPath, deltaPath); vErr != nil {
			return false, fmt.Errorf("delta signature verification FAILED: %w", vErr)
		}
	}
	outPath := dst + ".delta-out.tmp"
	defer os.Remove(outPath)
	st, err := dbupdate.ApplyDelta(dst, deltaPath, outPath)
	if err != nil {
		return false, fmt.Errorf("delta apply: %w", err)
	}
	if err := os.Rename(outPath, dst); err != nil {
		return false, fmt.Errorf("rename: %w", err)
	}
	checksum := m.Full.Sha256
	_ = os.WriteFile(dst+".sha256", []byte(checksum+"\n"), 0o644)
	if ft, err := os.ReadFile(dst + ".feedtype"); err == nil && strings.TrimSpace(string(ft)) != "" {
		_ = os.WriteFile(dst+".feedtype", ft, 0o644)
	} else {
		_ = os.WriteFile(dst+".feedtype", []byte(feedProduction+"\n"), 0o644)
	}
	acceptManifestTimestamp(tsPath, m.GeneratedAt)
	fmt.Printf("update: applied delta (+%d -%d ~%d) — %s\n", st.Added, st.Removed, st.Updated, dst)
	return true, nil
}

// productionAssetURL resolves the browser download URL of the production
// feed asset from the latest onyx-db release.
func productionAssetURL() (string, error) {
	fmt.Printf("update: fetching latest database from %s...\n", productionRepo)

	// 1. Latest release metadata
	relURL := "https://api.github.com/repos/" + productionRepo + "/releases/latest"
	req, err := http.NewRequest("GET", relURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "onyx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("release lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("release lookup: HTTP %d", resp.StatusCode)
	}

	rel, err := latestReleaseAssets(relURL)
	if err != nil {
		return "", err
	}
	for _, a := range rel.Assets {
		if a.Name == productionAsset {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("asset %s not found in release %s", productionAsset, rel.TagName)
}

// releaseAsset is one GitHub release asset entry.
type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// releaseInfo is the subset of GitHub release metadata onyx needs.
type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

// latestReleaseAssets fetches and decodes the latest onyx-db release
// metadata (shared by the feed download and the optional data assets).
func latestReleaseAssets(relURL string) (*releaseInfo, error) {
	req, err := http.NewRequest("GET", relURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "onyx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release lookup: HTTP %d", resp.StatusCode)
	}
	var rel releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("release decode: %w", err)
	}
	return &rel, nil
}

// updateOptionalAssets mirrors the optional data assets (popular-list and
// core-fingerprint table) next to the database. Every failure is a
// warning: scans work fine without them (the scanner falls back to the
// built-in lists and disables fingerprinting).
func updateOptionalAssets(dst string, rel *releaseInfo) {
	if rel == nil {
		return
	}
	dir := filepath.Dir(dst)
	for _, asset := range []struct {
		name, out string
	}{
		{"popular.json.gz", "popular.json"},
		{"fingerprints.json.gz", "fingerprints.json"},
	} {
		var url string
		for _, a := range rel.Assets {
			if a.Name == asset.name {
				url = a.BrowserDownloadURL
				break
			}
		}
		if url == "" {
			continue // mirror does not publish this asset yet
		}
		outPath := filepath.Join(dir, asset.out)
		tmp, err := os.CreateTemp(dir, ".onyx-aux-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s download: %v\n", asset.name, err)
			continue
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		if err := downloadToFile(url, tmpName); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s download: %v\n", asset.name, err)
			continue
		}
		if pub := dbPubKeyPath(); pub != "" {
			sigTmp := tmpName + ".sig"
			if dErr := downloadToFile(url+".minisig", sigTmp); dErr != nil {
				fmt.Fprintf(os.Stderr, "[WARN] %s signature fetch: %v — skipping\n", asset.name, dErr)
				continue
			}
			if vErr := dbupdate.VerifyMinisign(pub, sigTmp, tmpName); vErr != nil {
				fmt.Fprintf(os.Stderr, "[WARN] %s signature verification FAILED: %v — skipping\n", asset.name, vErr)
				continue
			}
		}
		zr, gErr := gzip.NewReader(tmp)
		if gErr != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s gzip: %v\n", asset.name, gErr)
			continue
		}
		if _, cErr := io.Copy(tmp, zr); cErr != nil {
			zr.Close()
			fmt.Fprintf(os.Stderr, "[WARN] %s unpack: %v\n", asset.name, cErr)
			continue
		}
		zr.Close()
		tmp.Close()
		if rErr := os.Rename(tmpName, outPath); rErr != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s rename: %v\n", asset.name, rErr)
			continue
		}
		fmt.Printf("update: %s -> %s\n", asset.name, outPath)
	}
}

// updateFromURL downloads url into dst, unpacking a gzip payload when gz is
// set. The raw downloaded bytes are SHA-256 hashed into dst+".sha256";
// when the digest matches a previous download the database file is not
// rewritten. The feed name is recorded in dst+".feedtype" so scans can
// report which feed produced the database.
//
// When $ONYX_DB_PUBKEY is set, the RAW published artifact (the exact bytes
// on the mirror) is verified against url+".minisig" BEFORE unpacking —
// signatures cover the artifact as published, not its decompressed form.
func updateFromURL(dst, url string, gz bool, feed string, force bool) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	raw, err := os.CreateTemp(filepath.Dir(dst), ".onyx-raw-*")
	if err != nil {
		return err
	}
	defer os.Remove(raw.Name())

	checksum, err := downloadFeed(url, false, raw)
	if err != nil {
		return err
	}
	if cErr := raw.Close(); cErr != nil {
		return cErr
	}

	// Signature gate: hard error when a pubkey is configured and the
	// artifact is unsigned or fails verification.
	if pub := dbPubKeyPath(); pub != "" {
		sigTmp := raw.Name() + ".sig"
		defer os.Remove(sigTmp)
		if dErr := downloadToFile(url+".minisig", sigTmp); dErr != nil {
			return fmt.Errorf("signature fetch (pubkey configured): %w", dErr)
		}
		if vErr := dbupdate.VerifyMinisign(pub, sigTmp, raw.Name()); vErr != nil {
			return fmt.Errorf("database signature verification FAILED: %w (database removed from trust: delete %s or update the key)", vErr, dst)
		}
		fmt.Println("update: signature verified")
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".onyx-db-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if gz {
		rawFile, oErr := os.Open(raw.Name())
		if oErr != nil {
			return oErr
		}
		zr, gErr := gzip.NewReader(rawFile)
		if gErr != nil {
			rawFile.Close()
			return fmt.Errorf("gzip: %w", gErr)
		}
		_, cErr := io.Copy(tmp, zr)
		zr.Close()
		rawFile.Close()
		if cErr != nil {
			return fmt.Errorf("unpack: %w", cErr)
		}
	} else if cErr := copyFile(raw.Name(), tmp.Name()); cErr != nil {
		return cErr
	}

	// Incremental check: the same checksum as the last successful download
	// means the feed has not changed — leave the database untouched.
	if !force {
		if prev, rErr := os.ReadFile(dst + ".sha256"); rErr == nil && strings.TrimSpace(string(prev)) == checksum {
			fmt.Printf("update: already up to date — %s\n", dst)
			return nil
		}
	}

	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if err := os.WriteFile(dst+".sha256", []byte(checksum+"\n"), 0o644); err != nil {
		return fmt.Errorf("checksum write: %w", err)
	}
	if err := os.WriteFile(dst+".feedtype", []byte(feed+"\n"), 0o644); err != nil {
		return fmt.Errorf("feed type write: %w", err)
	}

	if fi, err := os.Stat(dst); err == nil {
		fmt.Printf("update: done — %s (%d bytes)\n", dst, fi.Size())
	}
	return nil
}

// downloadFeed GETs url and streams the payload into out (unpacking a
// gzip file first when gz is set). It returns the hex SHA-256 of the raw
// downloaded bytes — the gzip file for the production feed, the JSON body
// for the scanner feed — so repeated downloads can be compared cheaply.
func downloadFeed(url string, gz bool, out io.Writer) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "onyx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("feed download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("feed download: HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	raw := io.TeeReader(resp.Body, h)
	stream := io.Reader(raw)
	if gz {
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return "", fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		stream = zr
	}
	if _, err := io.Copy(out, stream); err != nil {
		return "", fmt.Errorf("unpack: %w", err)
	}
	// Drain whatever the decompressor did not consume so every raw byte
	// contributes to the digest.
	_, _ = io.Copy(io.Discard, raw) // intentional drain; errors surface via the digest check
	return hex.EncodeToString(h.Sum(nil)), nil
}

// mediaIDsFor returns the attachment-ID probe cap for the "m" enumerate
// token: 15 by default, 0 (legacy presence-only) when media is disabled.
func mediaIDsFor(enum string) int {
	if strings.Contains(enum, "m") {
		return 15
	}
	return 0
}

// runVersionCheck fetches the latest GitHub release tag and compares it
// to the running binary, printing a human line and returning non-nil
// when an update is available (caller exits 2).
func runVersionCheck() error {
	rel, err := latestReleaseAssets("https://api.github.com/repos/" + productionRepo + "/releases/latest")
	if err != nil {
		return fmt.Errorf("version check failed: %w", err)
	}
	latest := strings.TrimSpace(rel.TagName)
	if latest == "" {
		return fmt.Errorf("version check: empty tag in release metadata")
	}
	latest = strings.TrimPrefix(latest, "v")
	if latest == onyxVersion {
		fmt.Printf("onyx %s is up to date (latest: %s)\n", onyxVersion, rel.TagName)
		return nil
	}
	fmt.Printf("onyx %s — update available: %s (https://github.com/%s/releases/tag/%s)\n",
		onyxVersion, rel.TagName, productionRepo, rel.TagName)
	return nil
}
