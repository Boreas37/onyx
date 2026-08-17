// Package scanner implements the read-only HTTP scan engine: WordPress
// detection, plugin/theme enumeration via readme.txt/style.css/wp-json, and
// version comparison against an indexed local database.
package scanner

import (
	"regexp"
	"sort"
)

var (
	stableTagRe = regexp.MustCompile(`(?im)^\s*stable\s*tag\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	styleVerRe  = regexp.MustCompile(`(?im)^\s*version\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	genMetaRe   = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9][0-9a-zA-Z.-]*)`)
	// wpscan-style passive references in HTML: /wp-content/plugins/<slug>/ and
	// /wp-content/themes/<slug>/
	passivePluginRe = regexp.MustCompile(`(?i)wp-content/plugins/([a-z0-9_-]+)/`)
	passiveThemeRe  = regexp.MustCompile(`(?i)wp-content/themes/([a-z0-9_-]+)/`)
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

// ExtractPassiveSlugs parses plugin and theme slugs from HTML the way WPScan
// does passive detection: any reference to wp-content/plugins/<slug>/ or
// wp-content/themes/<slug>/ counts as evidence the component is installed.
// Returns deduplicated, sorted plugin slugs and theme slugs.
func ExtractPassiveSlugs(html string) (plugins, themes []string) {
	return ExtractPassiveSlugsIn(html, "wp-content")
}

// ExtractPassiveSlugsIn is ExtractPassiveSlugs with a custom wp-content
// directory name: references to <contentDir>/plugins/<slug>/ or
// <contentDir>/themes/<slug>/ count as evidence the component is installed.
// Returns deduplicated, sorted plugin slugs and theme slugs.
func ExtractPassiveSlugsIn(html, contentDir string) (plugins, themes []string) {
	dir := regexp.QuoteMeta(contentDir)
	pluginRe := regexp.MustCompile(`(?i)` + dir + `/plugins/([a-z0-9_-]+)/`)
	themeRe := regexp.MustCompile(`(?i)` + dir + `/themes/([a-z0-9_-]+)/`)
	seenP := make(map[string]bool)
	seenT := make(map[string]bool)
	for _, m := range pluginRe.FindAllStringSubmatch(html, -1) {
		seenP[m[1]] = true
	}
	for _, m := range themeRe.FindAllStringSubmatch(html, -1) {
		seenT[m[1]] = true
	}
	for s := range seenP {
		plugins = append(plugins, s)
	}
	for s := range seenT {
		themes = append(themes, s)
	}
	sort.Strings(plugins)
	sort.Strings(themes)
	return plugins, themes
}
