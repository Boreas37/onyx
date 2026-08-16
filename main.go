package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"onyx/internal/db"
	"onyx/internal/report"
	"onyx/internal/scanner"
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
	dbPath   string
	threads  int
	timeout  int
	asJSON   bool
	apiOnly  bool
	stealth  bool
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
		case a == "--db" && i+1 < len(args):
			i++
			o.dbPath = args[i]
		case a == "--threads" && i+1 < len(args):
			i++
			o.threads = atoi(args[i], 5)
		case a == "--timeout" && i+1 < len(args):
			i++
			o.timeout = atoi(args[i], 10)
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
  --db PATH      database file (default: %s)
  --threads N    concurrent requests (default: 5)
  --timeout S    per-request timeout in seconds (default: 10)
  --json         print results as JSON
  --api          only query the REST API, skip brute-force enumeration
  --stealth      one request per second
`, defaultDB)
}

func runScan(target string, o scanOptions) {
	if _, err := os.Stat(o.dbPath); err != nil {
		fmt.Fprintln(os.Stderr, "error: database not found at", o.dbPath)
		fmt.Fprintln(os.Stderr, "run 'onyx update' to fetch it first")
		os.Exit(1)
	}

	database, err := db.Load(o.dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		os.Exit(1)
	}

	sc, err := scanner.NewScanner(database, target, scanner.Options{
		Threads: o.threads,
		Timeout: time.Duration(o.timeout) * time.Second,
		APIOnly: o.apiOnly,
		Stealth: o.stealth,
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
	report.PrintTable(res)
}

func update(dst string) error {
	fmt.Println("update: fetching latest database from GitHub...")
	// TODO: pull the newest release asset from the onyx-db repo and unpack it to dst.
	// Until then, point --db at a local copy of the Wordfence feed.
	return nil
}
