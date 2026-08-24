package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/dbupdate"
)

// runDB drives the `onyx db` inspection subcommands: read-only queries
// over the local vulnerability database, no network involved.
//
//	onyx db stats [--db PATH]
//	onyx db lookup SLUG [--db PATH]
//	onyx db top [N] [--db PATH]
//	onyx db search QUERY [--db PATH]
//	onyx db diff B.json [--db PATH]
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

	database, err := db.LoadCached(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading database:", err)
		return 2
	}

	switch cmd {
	case "stats":
		return dbStats(database, dbPath)
	case "diff":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: onyx db diff B.json  (A is the --db database)")
			return 2
		}
		return dbDiff(database, rest[0])
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

// dbDiff compares the loaded database with a second feed file and prints
// per-type and slug-level differences: records added/removed/updated
// (by id), plus slugs that newly appear or disappear. Exit code is 0.
func dbDiff(d *db.DB, pathB string) int {
	b, err := db.Load(pathB)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db diff:", err)
		return 2
	}
	ids := func(dd *db.DB) map[string]bool {
		m := make(map[string]bool, len(dd.Records))
		for _, r := range dd.Records {
			m[r.ID] = true
		}
		return m
	}
	slugs := func(dd *db.DB) map[string]bool {
		m := make(map[string]bool)
		for i := range dd.Records {
			for j := range dd.Records[i].Software {
				m[dd.Records[i].Software[j].Slug] = true
			}
		}
		return m
	}
	ma, mb := ids(d), ids(b)
	var added, removed []string
	for id := range mb {
		if !ma[id] {
			added = append(added, id)
		}
	}
	for id := range ma {
		if !mb[id] {
			removed = append(removed, id)
		}
	}
	sa, sb := slugs(d), slugs(b)
	var slugsAdded, slugsRemoved []string
	for s := range sb {
		if !sa[s] {
			slugsAdded = append(slugsAdded, s)
		}
	}
	for s := range sa {
		if !sb[s] {
			slugsRemoved = append(slugsRemoved, s)
		}
	}
	shared := 0
	for id := range ma {
		if mb[id] {
			shared++
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(slugsAdded)
	sort.Strings(slugsRemoved)

	fmt.Printf("db diff: %d records vs %d records\n", len(ma), len(mb))
	fmt.Printf("  shared ids:      %d\n", shared)
	fmt.Printf("  records added:   %d\n", len(added))
	fmt.Printf("  records removed: %d\n", len(removed))
	fmt.Printf("  slugs added:     %d\n", len(slugsAdded))
	fmt.Printf("  slugs removed:   %d\n", len(slugsRemoved))
	fmt.Printf("  per-type A:      %s\n", typeCounts(d))
	fmt.Printf("  per-type B:      %s\n", typeCounts(b))
	// Record-level detail, capped so huge feeds stay readable.
	show := func(title string, list []string, from *db.DB) {
		if len(list) == 0 {
			return
		}
		fmt.Printf("  %s (first %d):\n", title, min(len(list), 50))
		for i, id := range list {
			if i >= 50 {
				break
			}
			if r := recordByID(from, id); r != nil {
				cve := r.CVE
				if cve == "" {
					cve = "no CVE"
				}
				fmt.Printf("    %s %s (%s)\n", id, cve, r.Title)
			} else {
				fmt.Printf("    %s\n", id)
			}
		}
	}
	show("added records", added, b)
	show("removed records", removed, d)
	for _, l := range slugsAdded {
		fmt.Printf("  + %s\n", l)
	}
	for _, l := range slugsRemoved {
		fmt.Printf("  - %s\n", l)
	}
	return 0
}

// typeCounts tallies records by their first software type.
func typeCounts(dd *db.DB) string {
	counts := make(map[string]int)
	for i := range dd.Records {
		if len(dd.Records[i].Software) > 0 {
			counts[dd.Records[i].Software[0].Type]++
		} else {
			counts["unknown"]++
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}

// recordByID returns the record with the given id, or nil.
func recordByID(dd *db.DB, id string) *db.Vuln {
	for i := range dd.Records {
		if dd.Records[i].ID == id {
			return &dd.Records[i]
		}
	}
	return nil
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
		if v.Software[0].Remediation != "" {
			fmt.Printf("    remediation: %s\n", v.Software[0].Remediation)
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

// runDoctor runs local health checks for the tool and its data. Offline by
// default; --network also verifies the mirror manifest (and its minisign
// signature when ONYX_DB_PUBKEY is set). Exit code is 1 when any check
// fails, 0 otherwise.
func runDoctor(args []string) int {
	dbPath := defaultDB
	network := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--db" && i+1 < len(args):
			i++
			dbPath = args[i]
		case args[i] == "--network":
			network = true
		default:
			fmt.Fprintln(os.Stderr, "usage: onyx doctor [--db PATH] [--network]")
			return 2
		}
	}
	fail := false
	ok := func(cond bool, label, detail string) {
		if cond {
			fmt.Printf("[OK]    %s\n", label)
		} else {
			fmt.Printf("[ERROR] %s\n", label)
			if detail != "" {
				fmt.Printf("        %s\n", detail)
			}
			fail = true
		}
	}
	warn := func(label, detail string) {
		fmt.Printf("[WARN]  %s", label)
		if detail != "" {
			fmt.Printf(" — %s", detail)
		}
		fmt.Println()
	}

	_, statErr := os.Stat(dbPath)
	ok(statErr == nil, fmt.Sprintf("database file exists (%s)", dbPath), "run 'onyx update' first")
	if statErr != nil {
		return 1
	}

	d, err := db.LoadCached(dbPath)
	if err != nil {
		ok(false, "database loads", err.Error())
	} else {
		ok(true, "database loads", "")
		fmt.Printf("        %d records, %d skipped (unparseable)\n", d.Count(), d.Skipped())
	}
	if _, err := os.Stat(dbPath + ".sha256"); err == nil {
		ok(true, "checksum sidecar (.sha256)", "")
	} else {
		ok(false, "checksum sidecar (.sha256)", "no .sha256 sidecar — run 'onyx update'")
	}
	if b, err := os.ReadFile(dbPath + ".feedtype"); err == nil {
		fmt.Printf("        feed: %s\n", strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile(dbPath + ".manifest-ts"); err == nil {
		if ts, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); perr == nil {
			days := int(time.Since(ts).Hours() / 24)
			ok(true, "manifest timestamp recorded", "")
			if days > 14 {
				warn("manifest is stale", fmt.Sprintf("%d days old — run 'onyx update'", days))
			}
		} else {
			ok(false, "manifest timestamp parses", string(b))
		}
	} else {
		warn("no manifest timestamp sidecar", "expected after 'onyx update'")
	}

	if pub := os.Getenv("ONYX_DB_PUBKEY"); pub != "" {
		if b, perr := os.ReadFile(pub); perr != nil {
			ok(false, "minisign public key readable", perr.Error())
		} else if len(b) == 0 || !strings.Contains(strings.SplitN(string(b), "\n", 2)[0], "untrusted comment") {
			ok(false, "minisign public key looks valid", "file is empty or not a minisign key")
		} else {
			ok(true, "minisign public key configured", "")
		}
	} else {
		warn("ONYX_DB_PUBKEY unset", "signature verification is off")
	}

	if base, err := os.UserCacheDir(); err == nil {
		cdir := filepath.Join(base, "onyx", "http")
		if entries, e := os.ReadDir(cdir); e == nil {
			fmt.Printf("[OK]    HTTP cache (%s): %d entries\n", cdir, len(entries))
		} else {
			warn("HTTP cache dir absent", cdir)
		}
	}

	if network {
		murl := manifestURL()
		raw, merr := dbupdate.FetchManifestRaw(http.DefaultClient, murl)
		if merr != nil {
			ok(false, "mirror manifest reachable", merr.Error())
		} else {
			m, perr := dbupdate.ParseManifest(raw)
			if perr != nil {
				ok(false, "mirror manifest parses", perr.Error())
			} else {
				fmt.Printf("[OK]    mirror manifest (%s)\n", m.GeneratedAt)
				fmt.Printf("        full sha256: %s (%d delta entries)\n",
					shortHash(m.Full.Sha256), len(m.Deltas))
			}
			if pub := os.Getenv("ONYX_DB_PUBKEY"); pub != "" {
				sigTmp := murl + ".minisig"
				if sErr := dbupdate.VerifyManifest(pub, raw, sigTmp); sErr != nil {
					ok(false, "manifest signature verifies", sErr.Error())
				} else {
					ok(true, "manifest signature verifies", "")
				}
			}
		}
	}

	if fail {
		return 1
	}
	return 0
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
