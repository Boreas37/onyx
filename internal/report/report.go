// Package report renders scan results as a human-readable table.
package report

import (
	"fmt"
	"strings"

	"github.com/Boreas37/onyx/internal/scanner"
)

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
	return code + rating + "\x1b[0m"
}

// PrintTable prints res to stdout as a plain-text table.
func PrintTable(res *scanner.Result) {
	if !res.IsWordPress {
		fmt.Printf("Target %s does not look like WordPress.\n", res.Target)
		return
	}

	fmt.Printf("Target: %s\n", res.Target)
	if res.WordPressVersion != "" {
		fmt.Printf("WordPress core: %s\n", res.WordPressVersion)
	}

	if len(res.Findings) == 0 {
		fmt.Println("\nNo known vulnerable components found.")
		return
	}

	fmt.Println("\nVulnerable components:")
	for _, f := range res.Findings {
		fmt.Printf("\n  %s %s (installed %s)\n", f.Type, f.Slug, f.InstalledVersion)
		for _, v := range f.Vulnerabilities {
			sev := severityColor(v.Rating)
			cve := v.CVE
			if cve == "" {
				cve = v.ID
			}
			fmt.Printf("    [%s] %s (%s)\n", sev, v.Title, cve)
			if len(v.AffectedLabels) > 0 {
				fmt.Printf("           affected: %s\n", strings.Join(v.AffectedLabels, ", "))
			}
		}
	}
	fmt.Println()
}
