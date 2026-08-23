// Package report renders scan results as a human-readable table.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Boreas37/onyx/internal/pocs"
	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/scanner"
)

// useColor is true only when stdout is a terminal (ANSI codes would corrupt
// piped output otherwise).
var useColor = func() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}()

// NoColor forces plain output without ANSI codes even when stdout is a
// terminal (used by --format cli-no-colour).
var NoColor bool

// severityColor wraps a severity label in ANSI color codes. Returns the
// plain label when the output is not a terminal or NoColor is set.
func severityColor(rating string) string {
	plain := strings.ToLower(rating)
	var code string
	switch plain {
	case "critical":
		code = "\x1b[31;1m" // bold red
	case "high":
		code = "\x1b[33m" // orange/yellow
	case "medium":
		code = "\x1b[33;1m" // bold yellow
	case "low":
		code = "\x1b[34m" // blue
	default:
		return rating
	}
	if !useColor || NoColor {
		return rating
	}
	return code + rating + "\x1b[0m"
}

// PrintBanner prints the startup banner (nuclei-style MOTD).
func PrintBanner(version string, dbRecords int) {
	fmt.Printf(`____  ____  __  ___  __
 / __ \/ __ \/ / / / |/_/
/ /_/ / / / / /_/ />  <
\____/_/ /_/\__, /_/|_|
           /____/  v%s

`, version)
	if dbRecords > 0 {
		fmt.Printf("                     %d records in local database\n", dbRecords)
	}
	fmt.Println()
}

// PrintTable prints res to stdout. Default is a compact per-component
// summary; pass verbose=true for the full one-line-per-finding listing.
// minSeverity filters findings below the given rating ("critical", "high",
// "medium", "low").
func PrintTable(res *scanner.Result, verbose bool, minSeverity string) {
	writeTable(os.Stdout, res, verbose, minSeverity)
}

// writeTable renders res into w; split from PrintTable so tests can point
// it at a bytes.Buffer instead of capturing os.Stdout.
func writeTable(w io.Writer, res *scanner.Result, verbose bool, minSeverity string) {
	if !res.IsWordPress {
		fmt.Fprintf(w, "Target %s does not look like WordPress.\n", res.Target)
		return
	}

	fmt.Fprintf(w, "Target: %s\n", res.Target)
	if res.WordPressVersion != "" {
		fmt.Fprintf(w, "WordPress core: %s\n", res.WordPressVersion)
	}
	if res.XMLRPC {
		fmt.Fprintf(w, "XML-RPC: enabled\n")
	}
	if res.AuthStatus != "" {
		fmt.Fprintf(w, "REST auth: %s\n", res.AuthStatus)
	}
	if len(res.Interesting) > 0 {
		fmt.Fprintf(w, "Interesting:\n")
		for _, item := range res.Interesting {
			fmt.Fprintf(w, "  - %s\n", item)
		}
		fmt.Fprintln(w)
	}

	if len(res.Users) > 0 {
		fmt.Fprintf(w, "Users:\n")
		for _, u := range res.Users {
			id := ""
			if u.ID > 0 {
				id = fmt.Sprintf(" (ID %d)", u.ID)
			}
			name := ""
			if u.Name != "" && u.Name != u.Slug {
				name = fmt.Sprintf(" (%s)", u.Name)
			}
			fmt.Fprintf(w, "  - %s%s%s\n", u.Slug, id, name)
		}
		fmt.Fprintln(w)
	}

	if len(res.LoginBrutes) > 0 {
		// lb.User/lb.Password come from operator-supplied wordlists, not
		// from the target, so they are printed verbatim.
		fmt.Fprintf(w, "Valid credentials:\n")
		for _, lb := range res.LoginBrutes {
			fmt.Fprintf(w, "  - %s:%s%s\n", lb.User, lb.Password, lb.URL)
		}
		fmt.Fprintln(w)
	}

	threshold := severityRank(minSeverity)

	// Group findings by component, filtered by severity.
	type comp struct {
		f     *scanner.Finding
		vulns []scanner.Vulnerability
	}
	var comps []comp
	for i := range res.Findings {
		f := &res.Findings[i]
		var kept []scanner.Vulnerability
		for _, v := range f.Vulnerabilities {
			if severityRank(v.Rating) >= threshold {
				kept = append(kept, v)
			}
		}
		if len(kept) > 0 {
			comps = append(comps, comp{f: f, vulns: kept})
		}
	}

	if len(comps) == 0 {
		if res.RateLimitHits > 0 {
			fmt.Fprintf(w, "\nNo matching vulnerabilities found. (%d request(s) were rate limited — results may be incomplete)\n", res.RateLimitHits)
		} else {
			fmt.Fprintln(w, "\nNo matching vulnerabilities found.")
		}
	} else {
		if res.RateLimitHits > 0 {
			fmt.Fprintf(w, "Note: %d request(s) were rate limited (HTTP 429) — results may be incomplete. Try --rate-limit N or --stealth.\n", res.RateLimitHits)
		}

		fmt.Fprintln(w)
		if verbose {
			for _, c := range comps {
				for _, v := range c.vulns {
					sev := severityColor(sevClass(v.Rating))
					cve := v.CVE
					if cve == "" {
						cve = v.ID
					}
					fmt.Fprintf(w, "[%s] [%s:%s:%s] %s (%s)\n",
						sev, c.f.Type, c.f.Slug, c.f.InstalledVersion, v.Title, cve)
				}
			}
		} else {
			// Compact summary: one line per component.
			for _, c := range comps {
				maxRank := 0
				var worst scanner.Vulnerability
				for _, v := range c.vulns {
					if severityRank(v.Rating) > maxRank {
						maxRank = severityRank(v.Rating)
						worst = v
					}
				}
				worstSev := severityColor(sevClass(worst.Rating))
				fmt.Fprintf(w, "[%s] [%s:%s:%s] %d vulnerabilities (worst: %s)\n",
					worstSev, c.f.Type, c.f.Slug, c.f.InstalledVersion, len(c.vulns), worst.Title)
			}
		}
		fmt.Fprintln(w)
	}

	if len(res.Nuclei) > 0 {
		// Nuclei fields come from parsing external JSON output (template
		// metadata echoes target responses), so strip control characters
		// and cap length before printing.
		fmt.Fprintln(w, "Nuclei verification:")
		for _, n := range res.Nuclei {
			id := sanitize.Text(n.CVE, 200)
			if id == "" {
				id = sanitize.Text(n.TemplateID, 200)
			}
			fmt.Fprintf(w, "  [%s] [%s] %s (matched at %s)\n",
				severityColor(sevClass(n.Severity)), strings.ToLower(id),
				sanitize.Text(n.Name, 200), sanitize.Text(n.MatchedAt, 200))
		}
		fmt.Fprintln(w)
	}

	if len(res.PoCs) > 0 {
		fmt.Fprintln(w, "PoC references (from CVE-PoC-Tracker):")
		lastCVE := ""
		for _, p := range res.PoCs {
			if p.CVE != lastCVE {
				if lastCVE != "" {
					fmt.Fprintln(w)
				}
				fmt.Fprintf(w, "  %s:\n", p.CVE)
				lastCVE = p.CVE
			}
			fmt.Fprintf(w, "    \u2b50 %-5d %s\n", p.Stars, p.URL)
		}
		fmt.Fprintf(w, "more: %s\n", pocs.TrackerURL)
		fmt.Fprintln(w)
	}
}

// severityRank maps a rating to a numeric level for filtering/sorting.
func severityRank(rating string) int {
	switch strings.ToLower(rating) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// sevClass maps a vulnerability rating onto the closed set of severity
// labels rendered by the report formats ({critical,high,medium,low,info}).
// Anything else — including markup, formulas or feed garbage that slipped
// past the load-time whitelist — collapses to "unknown", so neither the
// CSS class attribute nor the cell text can carry attacker-controlled
// content. Mirrors db's ratingWhitelist; informational aliases to info.
func sevClass(rating string) string {
	switch strings.ToLower(rating) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(rating)
	case "info", "informational":
		return "info"
	default:
		return "unknown"
	}
}

// csvHeader is the CSV column order for --format csv output.
var csvHeader = []string{
	"slug", "type", "installed_version", "cve", "severity", "title", "affected_versions",
}

// csvSafe neutralizes spreadsheet formula injection: a field that starts
// with =, +, - or @ (or a tab/CR that Excel also treats as formula start)
// gets a leading single quote so opening the CSV in Excel/Sheets cannot
// execute it. Target-controlled fields (slugs, versions, titles from feeds)
// make this reachable in practice.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// WriteCSV writes res as CSV to w: one row per vulnerability with the
// columns slug,type,installed_version,cve,severity,title,affected_versions.
// Values containing commas (or quotes/newlines) are quoted by encoding/csv.
// Target-controlled fields make this reachable in practice; severity and
// CVE are feed-controlled too, so they pass through sevClass/csvSafe as
// well.
func WriteCSV(w io.Writer, res *scanner.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		for _, v := range f.Vulnerabilities {
			// AffectedLabels: join first, then csvSafe — spreadsheet
			// formula execution only triggers on the first character of
			// the whole cell, so neutralizing the joined field once is
			// sufficient.
			if err := cw.Write([]string{
				csvSafe(f.Slug),
				f.Type,
				csvSafe(f.InstalledVersion),
				csvSafe(v.CVE),
				csvSafe(sevClass(v.Rating)),
				csvSafe(v.Title),
				csvSafe(strings.Join(v.AffectedLabels, "; ")),
			}); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// PrintCSV writes res as CSV to stdout.
func PrintCSV(res *scanner.Result) {
	if err := WriteCSV(os.Stdout, res); err != nil {
		fmt.Fprintln(os.Stderr, "csv output:", err)
	}
}

// PrintSummary prints the scan summary section (table formats).
func PrintSummary(res *scanner.Result) {
	if res.Summary == nil {
		return
	}
	if res.RateLimitedAbort {
		fmt.Println("\n[!] Target enforces aggressive rate limiting — enumeration stopped early.")
		fmt.Println("    Results may be incomplete. Retry politely, e.g.:")
		fmt.Println("    onyx scan <target> --stealth --rate-limit 0.5 --max-requests 100 --max-scan-duration 10m")
	}
	s := res.Summary
	line := func(label, value string) {
		fmt.Printf("  %-12s %s\n", label+":", value)
	}
	requests := fmt.Sprintf("%d", s.Requests)
	if s.RateLimited > 0 {
		requests = fmt.Sprintf("%d (%d rate-limited)", s.Requests, s.RateLimited)
	}
	findings := fmt.Sprintf("%d vulnerabilities", s.Findings)
	var sev []string
	if s.Critical > 0 {
		sev = append(sev, fmt.Sprintf("%d critical", s.Critical))
	}
	if s.High > 0 {
		sev = append(sev, fmt.Sprintf("%d high", s.High))
	}
	if s.Medium > 0 {
		sev = append(sev, fmt.Sprintf("%d medium", s.Medium))
	}
	if s.Low > 0 {
		sev = append(sev, fmt.Sprintf("%d low", s.Low))
	}
	if len(sev) > 0 {
		findings += " (" + strings.Join(sev, ", ") + ")"
	}
	fmt.Println("Scan summary:")
	line("Duration", fmt.Sprintf("%.1fs", float64(s.DurationMS)/1000))
	line("Requests", requests)
	line("Detected", fmt.Sprintf("%d components", s.Detected))
	line("Findings", findings)
	line("Users found", fmt.Sprintf("%d", s.Users))
}

// PrintJSONL prints res as JSON Lines: one compact JSON object per finding.
func PrintJSONL(res *scanner.Result) {
	enc := json.NewEncoder(os.Stdout)
	for i := range res.Findings {
		_ = enc.Encode(&res.Findings[i])
	}
}

// sarifLevel maps a CVSS rating to a SARIF result level.
func sarifLevel(rating string) string {
	switch strings.ToLower(rating) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

// PrintSARIF writes res as a minimal SARIF 2.1.0 report: a single run whose
// tool driver is "onyx" and whose results are the scan findings.
func PrintSARIF(version string, res *scanner.Result) {
	type location struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []location `json:"locations"`
	}
	type run struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	out := sarif{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []run{{}},
	}
	out.Runs[0].Tool.Driver.Name = "onyx"
	out.Runs[0].Tool.Driver.Version = version
	for i := range res.Findings {
		f := &res.Findings[i]
		for _, v := range f.Vulnerabilities {
			ruleID := v.CVE
			if ruleID == "" {
				ruleID = v.ID
			}
			r := result{
				RuleID:    ruleID,
				Level:     sarifLevel(v.Rating),
				Locations: []location{{}},
			}
			r.Message.Text = v.Title
			r.Locations[0].ArtifactLocation.URI = res.Target
			out.Runs[0].Results = append(out.Runs[0].Results, r)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
