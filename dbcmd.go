package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/db"
)

// runDB drives the `onyx db` inspection subcommands: read-only queries
// over the local vulnerability database, no network involved.
//
//	onyx db stats [--db PATH]
//	onyx db lookup SLUG [--db PATH]
//	onyx db top [N] [--db PATH]
//	onyx db search QUERY [--db PATH]
func runDB(args []string) int {
	if len(args) == 0 {
		dbUsage()
		return 2
	}
	cmd := args[0]
	rest := args[1:]
	dbPath := defaultDB
	for i := 0; i < len(rest)-1; {
		if rest[i] == "--db" {
			dbPath = rest[i+1]
			rest = append(rest[:i:i], rest[i+2:]...)
			continue
		}
		i++
	}

	database, err := db.Load(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return 2
	}

	switch cmd {
	case "stats":
		return dbStats(database, dbPath)
	case "lookup":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: onyx db lookup SLUG")
			return 2
		}
		return dbLookup(database, strings.ToLower(rest[0]))
	case "top":
		n := 10
		if len(rest) == 1 {
			if _, pErr := fmt.Sscanf(rest[0], "%d", &n); pErr != nil || n <= 0 {
				fmt.Fprintln(os.Stderr, "usage: onyx db top [N]")
				return 2
			}
		}
		return dbTop(database, n)
	case "search":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: onyx db search QUERY")
			return 2
		}
		return dbSearch(database, rest[0])
	default:
		fmt.Fprintf(os.Stderr, "unknown db command %q\n\n", cmd)
		dbUsage()
		return 2
	}
}

func dbUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  onyx db stats [--db PATH]
  onyx db lookup SLUG [--db PATH]
  onyx db top [N] [--db PATH]
  onyx db search QUERY [--db PATH]`)
}

// dbStats prints an overview of the local database: record counts by
// software type, informational share and freshness.
func dbStats(d *db.DB, path string) int {
	byType := map[string]int{}
	informational := 0
	newest := ""
	for i := range d.Records {
		rec := &d.Records[i]
		if rec.Informational {
			informational++
		}
		seenType := map[string]bool{}
		for _, s := range rec.Software {
			t := strings.ToLower(s.Type)
			if t == "" || seenType[t] {
				continue
			}
			seenType[t] = true
			byType[t]++
		}
		if rec.PublishedAt > newest {
			newest = rec.PublishedAt
		}
	}
	fmt.Printf("database:     %s (%d bytes)\n", path, fileSize(path))
	fmt.Printf("records:      %d (%d informational)\n", d.Count(), informational)
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Printf("  %-9s %d records\n", t+":", byType[t])
	}
	if newest != "" {
		fmt.Printf("newest entry: %s\n", newest)
	}
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > 14*24*time.Hour {
		fmt.Printf("WARNING:      downloaded %.0f days ago — run 'onyx update'\n", time.Since(fi.ModTime()).Hours()/24)
	}
	return 0
}

// dbLookup prints every vulnerability recorded for one plugin/theme/core
// slug, most severe first.
func dbLookup(d *db.DB, slug string) int {
	vulns := d.Lookup(slug)
	if len(vulns) == 0 {
		fmt.Printf("no vulnerabilities recorded for %q\n", slug)
		return 0
	}
	sort.SliceStable(vulns, func(i, j int) bool { return vulns[i].CVSS.Score > vulns[j].CVSS.Score })
	fmt.Printf("%s: %d recorded vulnerabilities (%s)\n\n", slug, len(vulns), d.SlugType(slug))
	for _, v := range vulns {
		rating := strings.ToLower(v.CVSS.Rating)
		score := ""
		if v.CVSS.Score > 0 {
			score = fmt.Sprintf(" %.1f", v.CVSS.Score)
		}
		cve := v.CVE
		if cve == "" {
			cve = "no CVE"
		}
		fmt.Printf("[%s%s] %s — %s\n", rating, score, cve, v.Title)
		labels := affectedLabels(v)
		if len(labels) > 0 {
			fmt.Printf("    affected: %s\n", strings.Join(labels, ", "))
		}
		if v.Software[0].Patched {
			fmt.Printf("    patched in: %s\n", strings.Join(v.Software[0].PatchedVersions, ", "))
		}
	}
	return 0
}

// dbTop prints the N slugs with the most recorded vulnerabilities.
func dbTop(d *db.DB, n int) int {
	slugs := d.TopSlugs(n)
	if len(slugs) == 0 {
		fmt.Println("database has no indexed slugs")
		return 0
	}
	fmt.Printf("%-32s %s\n", "slug", "vulnerabilities")
	for _, s := range slugs {
		fmt.Printf("%-32s %d\n", s, len(d.Lookup(s)))
	}
	return 0
}

// dbSearch greps titles and CVE ids; at most 20 matches are printed.
func dbSearch(d *db.DB, query string) int {
	q := strings.ToLower(query)
	shown := 0
	for i := range d.Records {
		rec := &d.Records[i]
		if !strings.Contains(strings.ToLower(rec.Title), q) &&
			!strings.Contains(strings.ToLower(rec.CVE), q) {
			continue
		}
		cve := rec.CVE
		if cve == "" {
			cve = "-"
		}
		fmt.Printf("[%s] %s | %s\n", strings.ToLower(rec.CVSS.Rating), cve, rec.Title)
		if shown++; shown >= 20 {
			fmt.Println("… output capped at 20 matches")
			break
		}
	}
	if shown == 0 {
		fmt.Printf("no matches for %q\n", query)
	}
	return 0
}

// affectedLabels collects the human-readable affected-version labels of a
// vulnerability's first software entry.
func affectedLabels(v db.Vuln) []string {
	if len(v.Software) == 0 {
		return nil
	}
	labels := make([]string, 0, len(v.Software[0].AffectedVersions))
	for label := range v.Software[0].AffectedVersions {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
