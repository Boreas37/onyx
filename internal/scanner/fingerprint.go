// Package scanner implements the read-only HTTP scan engine: WordPress
// detection, plugin/theme enumeration via readme.txt/style.css/wp-json, and
// version comparison against an indexed local database.
package scanner

import "regexp"

var (
	stableTagRe = regexp.MustCompile(`(?im)^\s*stable\s*tag\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	styleVerRe  = regexp.MustCompile(`(?im)^\s*version\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	genMetaRe   = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9][0-9a-zA-Z.-]*)`)
)

// ExtractVersionFromReadme parses the "Stable tag:" line of a WordPress
// plugin readme.txt and returns the version string. found is false when no
// parseable stable tag exists.
func ExtractVersionFromReadme(body string) (version string, found bool) {
	m := stableTagRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ExtractVersionFromStyleCSS parses the "Version:" header of a WordPress
// theme style.css and returns the version string. found is false when no
// parseable version exists.
func ExtractVersionFromStyleCSS(body string) (version string, found bool) {
	m := styleVerRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ExtractWordPressVersion parses the WordPress version from the generator
// meta tag in the homepage HTML. found is false when absent.
func ExtractWordPressVersion(html string) (version string, found bool) {
	m := genMetaRe.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return m[1], true
}