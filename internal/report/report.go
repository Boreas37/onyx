// Package report renders scan results as a human-readable table.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

// severityColor wraps a severity label in ANSI color codes. Returns the
// plain label when the output is not a terminal.
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
	if !useColor {
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
	if !res.IsWordPress {
		fmt.Printf("Target %s does not look like WordPress.\n", res.Target)
		return
	}

	fmt.Printf("Target: %s\n", res.Target)
	if res.WordPressVersion != "" {
		fmt.Printf("WordPress core: %s\n", res.WordPressVersion)
	}

	if len(res.Users) > 0 {
		fmt.Printf("Users:\n")
		for _, u := range res.Users {
			id := ""
			if u.ID > 0 {
				id = fmt.Sprintf(" (ID %d)", u.ID)
			}
			name := ""
			if u.Name != "" && u.Name != u.Slug {
				name = fmt.Sprintf(" (%s)", u.Name)
			}
			fmt.Printf("  - %s%s%s\n", u.Slug, id, name)
		}
		fmt.Println()
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
			fmt.Printf("\nNo matching vulnerabilities found. (%d request(s) were rate limited — results may be incomplete)\n", res.RateLimitHits)
		} else {
			fmt.Println("\nNo matching vulnerabilities found.")
		}
		return
	}

	if res.RateLimitHits > 0 {
		fmt.Printf("Note: %d request(s) were rate limited (HTTP 429) — results may be incomplete. Try --rate-limit N or --stealth.\n", res.RateLimitHits)
	}

	fmt.Println()
	if verbose {
		for _, c := range comps {
			for _, v := range c.vulns {
				sev := severityColor(v.Rating)
				cve := v.CVE
				if cve == "" {
					cve = v.ID
				}
				fmt.Printf("[%s] [%s:%s:%s] %s (%s)\n",
					sev, c.f.Type, c.f.Slug, c.f.InstalledVersion, v.Title, cve)
			}
		}
		fmt.Println()
		return
	}

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
		worstSev := severityColor(worst.Rating)
		fmt.Printf("[%s] [%s:%s:%s] %d vulnerabilities (worst: %s)\n",
			worstSev, c.f.Type, c.f.Slug, c.f.InstalledVersion, len(c.vulns), worst.Title)
	}
	fmt.Println()
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
