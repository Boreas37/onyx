// Package report renders scan results as a human-readable table.
package report

import (
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
	fmt.Printf(`  _____  ____  __   ____
 / ___/ / __ \/ /  / __ \
/ /__  / /_/ / /__/ /_/ /
\___/  \____/____/\____/  v%s

`, version)
	if dbRecords > 0 {
		fmt.Printf("                     %d records in local database\n", dbRecords)
	}
	fmt.Println()
}

// PrintTable prints res to stdout in a nuclei-style one-line-per-finding
// format, e.g.:
//
//	[medium] [plugin:elementor:3.24.0] Elementor <= 3.30.2 - Arbitrary File Read (CVE-2025-8081)
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

	fmt.Println()
	for _, f := range res.Findings {
		for _, v := range f.Vulnerabilities {
			sev := severityColor(v.Rating)
			cve := v.CVE
			if cve == "" {
				cve = v.ID
			}
			fmt.Printf("[%s] [%s:%s:%s] %s (%s)\n",
				sev, f.Type, f.Slug, f.InstalledVersion, v.Title, cve)
		}
	}
	fmt.Println()
}
