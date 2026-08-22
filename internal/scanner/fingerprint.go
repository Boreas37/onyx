// Package scanner implements the read-only HTTP scan engine: WordPress
// detection, plugin/theme enumeration via readme.txt/style.css/wp-json, and
// version comparison against an indexed local database.
package scanner

import (
	"regexp"
	"sort"

	"github.com/Boreas37/onyx/internal/sanitize"
)

const (
	// maxVersionLen caps version strings taken from target responses. A
	// hostile server can put megabytes of data on a "Stable tag:" line;
	// real versions never come close to this.
	maxVersionLen = 64
	// maxSlugLen and maxNameLen cap slugs and display names read from
	// target-controlled responses (REST inventory, author archives).
	maxSlugLen = 200
	maxNameLen = 200
	// maxPassiveVersions caps how many distinct ?ver= versions are
	// extracted from a single page so a pathological document cannot
	// balloon the result map.
	maxPassiveVersions = 200
)

var (
	stableTagRe = regexp.MustCompile(`(?im)^\s*stable\s*tag\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	styleVerRe  = regexp.MustCompile(`(?im)^\s*version\s*[:=]\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	genMetaRe   = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9][0-9a-zA-Z.-]*)`)
	// rssGenRe parses the WordPress version out of an RSS feed generator
	// element in its URL form: <generator>https://wordpress.org/?v=X.Y.Z</generator>.
	rssGenRe = regexp.MustCompile(`(?i)<generator>[^<]*wordpress\.org/\?v=([0-9][0-9a-zA-Z.-]*)`)
	// opmlGenRe parses the WordPress version from the generator attribute
	// of wp-links-opml.php: generator="WordPress/X.Y".
	opmlGenRe = regexp.MustCompile(`(?i)generator=["']WordPress/([0-9][0-9a-zA-Z.-]*)`)
	// wpscan-style passive references in HTML: /wp-content/plugins/<slug>/ and
	// /wp-content/themes/<slug>/
	passivePluginRe = regexp.MustCompile(`(?i)wp-content/plugins/([a-z0-9_-]+)/`)
	passiveThemeRe  = regexp.MustCompile(`(?i)wp-content/themes/([a-z0-9_-]+)/`)
)

// sanitizeText makes a target-supplied string safe to embed in reports.
// See the sanitize package for the rules; kept here as a thin wrapper so
// call sites stay readable.
func sanitizeText(s string, maxLen int) string {
	return sanitize.Text(s, maxLen)
}

// sanitizeVersion is sanitizeText with the tighter version-string cap.
func sanitizeVersion(s string) string {
	return sanitizeText(s, maxVersionLen)
}

// ExtractVersionFromReadme parses the "Stable tag:" line of a WordPress
// plugin readme.txt and returns the version string. found is false when no
// parseable stable tag exists.
func ExtractVersionFromReadme(body string) (version string, found bool) {
	m := stableTagRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// ExtractVersionFromStyleCSS parses the "Version:" header of a WordPress
// theme style.css and returns the version string. found is false when no
// parseable version exists.
func ExtractVersionFromStyleCSS(body string) (version string, found bool) {
	m := styleVerRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// ExtractWordPressVersion parses the WordPress version from the generator
// meta tag in the homepage HTML. found is false when absent.
func ExtractWordPressVersion(html string) (version string, found bool) {
	m := genMetaRe.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// ExtractRSSVersion parses the WordPress core version from an RSS feed
// generator element in its URL form
// (<generator>https://wordpress.org/?v=X.Y.Z</generator>). found is false
// when absent.
func ExtractRSSVersion(body string) (version string, found bool) {
	m := rssGenRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// ExtractOPMLVersion parses the WordPress core version from the generator
// attribute of a wp-links-opml.php document (generator="WordPress/X.Y").
// found is false when absent.
func ExtractOPMLVersion(body string) (version string, found bool) {
	m := opmlGenRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// ExtractPassiveVersions parses plugin and theme versions from asset URLs
// in HTML: any wp-content/plugins/<slug>/...?ver=1.2.3 or
// wp-content/themes/<slug>/...?ver=1.2.3 reference counts as evidence of
// the installed version. The result maps slug to version; when a slug is
// referenced with several versions the first one in document order wins.
// The map is capped at maxPassiveVersions entries.
func ExtractPassiveVersions(html string) map[string]string {
	return ExtractPassiveVersionsIn(html, "wp-content")
}

// ExtractPassiveVersionsIn is ExtractPassiveVersions with a custom
// wp-content directory name, mirroring ExtractPassiveSlugsIn.
func ExtractPassiveVersionsIn(html, contentDir string) map[string]string {
	dir := regexp.QuoteMeta(contentDir)
	verRe := regexp.MustCompile(`(?i)` + dir + `/(plugins|themes)/([a-z0-9_-]+)/[^\s"'<>]*?(?:\?|&(?:amp;|#0*38;)?)ver=((?:v|V)?\d[0-9a-zA-Z.+-]*)`)
	out := make(map[string]string)
	for _, m := range verRe.FindAllStringSubmatch(html, -1) {
		slug := m[2]
		if _, ok := out[slug]; ok {
			continue // first reference in document order wins
		}
		ver := sanitizeVersion(m[3])
		if ver == "" {
			continue
		}
		out[slug] = ver
		if len(out) >= maxPassiveVersions {
			break
		}
	}
	return out
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
