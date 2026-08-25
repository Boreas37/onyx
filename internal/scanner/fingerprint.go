// Package scanner implements the read-only HTTP scan engine: WordPress
// detection, plugin/theme enumeration via readme.txt/style.css/wp-json, and
// version comparison against an indexed local database.
package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Boreas37/onyx/internal/sanitize"
	"github.com/Boreas37/onyx/internal/version"
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
	// maxRESTRoutePlugins caps how many plugin namespaces
	// ExtractRESTRoutePlugins reports from a single wp-json route index,
	// and how long each candidate slug may be, so a hostile route list
	// cannot balloon the result.
	maxRESTRoutePlugins = 50
)

// changelogSectionRe matches the line that opens a readme.txt Changelog
// section in either the classic "== Changelog ==" or markdown
// "## Changelog" spelling.
var changelogSectionRe = regexp.MustCompile(`(?im)^\s*(?:={2,}|#{2,})\s*changelog\s*(?:={2,}|#{2,})?\s*$`)

// changelogHeadingRe matches one changelog entry heading and captures the
// version token at its head. The accepted spellings are the classic
// "= 3.24.0 =" form, the markdown "### 3.24.0" form and the bare
// "3.24.0 - ..." first line. The heading must start on its own line; an
// optional "v" prefix is tolerated like every other version extractor.
var changelogHeadingRe = regexp.MustCompile(`(?im)^\s*(?:={1,3}|#{1,3})?\s*((?:v|V)?\d[0-9a-zA-Z.+-]*)\s*(?:={1,3})?(?:\s*$|\s+-\s+[^\r\n]*$)`)

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
	// testedUpToRe matches a readme.txt / style.css header line
	// "Tested up to: X" (case-insensitive, "=" separator tolerated,
	// trailing spaces trimmed).
	testedUpToRe = regexp.MustCompile(`(?im)^\s*tested\s*up\s*to\s*[:=]\s*(.+?)\s*$`)
	// requiresAtLeastRe matches a readme.txt / style.css header line
	// "Requires at least: Y" (case-insensitive, "=" separator tolerated,
	// trailing spaces trimmed).
	requiresAtLeastRe = regexp.MustCompile(`(?im)^\s*requires\s*at\s*least\s*[:=]\s*(.+?)\s*$`)
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

// ExtractTestedUpTo parses the "Tested up to:" header line of a WordPress
// readme.txt (or theme style.css header) and returns the WordPress version
// the component was tested against, sanitized. It returns "" when the
// header is absent. The match is case-insensitive, tolerates trailing
// spaces (and the historical "Tested up to = X" separator spelling), and
// never spans lines.
func ExtractTestedUpTo(body string) string {
	m := testedUpToRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return sanitizeVersion(strings.TrimSpace(m[1]))
}

// ExtractRequiresAtLeast parses the "Requires at least:" header line of a
// WordPress readme.txt or theme style.css and returns the minimum WordPress
// version required, sanitized. It returns "" when the header is absent. The
// match is case-insensitive, tolerates trailing spaces (and the "Requires
// at least = Y" separator spelling), and never spans lines.
func ExtractRequiresAtLeast(body string) string {
	m := requiresAtLeastRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return sanitizeVersion(strings.TrimSpace(m[1]))
}

// ExtractVersionFromChangelog parses the first version heading inside a
// readme.txt Changelog section ("== Changelog ==" or "## Changelog"): the
// classic "= X.Y.Z =" heading, the markdown "### X.Y.Z" heading, or a
// "X.Y.Z - ..." first line. The candidate is sanitized and must parse as a
// numeric version (internal/version.Parse). found is false when there is no
// Changelog section or no parseable heading — readmes whose only version is
// buried in the changelog (no "Stable tag:" line) still get detected.
func ExtractVersionFromChangelog(body string) (string, bool) {
	sec := changelogSectionRe.FindStringIndex(body)
	if sec == nil {
		return "", false
	}
	m := changelogHeadingRe.FindStringSubmatch(body[sec[1]:])
	if m == nil {
		return "", false
	}
	v := sanitizeVersion(m[1])
	if v == "" {
		return "", false
	}
	if _, ok := version.Parse(v); !ok {
		return "", false
	}
	return v, true
}

// maxFingerprintProbes caps how many asset files fingerprintCore fetches
// from the optional --fingerprint-db table, bounding the extra request cost.
const maxFingerprintProbes = 5

// fingerprintTable is the decoded shape of the --fingerprint-db JSON file:
//
//	{"files": {"wp-includes/js/wp-emoji-release.min.js": {"<md5hex>": ["6.1","6.2"]}}}
//
// Each file path maps an md5 hex digest of its release content onto the
// core versions known to carry it.
type fingerprintTable struct {
	Files map[string]map[string][]string `json:"files"`
}

// fingerprintCore probes well-known core asset files from the optional
// --fingerprint-db table and returns the first version whose md5 digest
// matches a served file. Paths are probed in sorted order, capped at
// maxFingerprintProbes requests. A missing, unparseable or empty table is a
// soft skip (returns found=false, never an error) so a broken DB file never
// aborts a scan.
func (s *Scanner) fingerprintCore() (string, bool) {
	table, err := s.fingerprintTable()
	if err != nil || table == nil || len(table.Files) == 0 {
		return "", false
	}
	paths := make([]string, 0, len(table.Files))
	for p := range table.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for i, p := range paths {
		if i >= maxFingerprintProbes {
			break
		}
		code, body, err := s.fetch("/" + strings.TrimLeft(p, "/"))
		if err != nil || code != http.StatusOK {
			continue
		}
		sum := md5.Sum(body)
		if vers, ok := table.Files[p][hex.EncodeToString(sum[:])]; ok && len(vers) > 0 {
			if v := sanitizeVersion(vers[0]); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// fingerprintTable loads (once, cached) and decodes the --fingerprint-db
// JSON table. Any read or parse failure is returned as an error so callers
// can treat a broken table as a soft skip; the first failure is remembered
// so a malformed file is not re-read on every probe.
func (s *Scanner) fingerprintTable() (*fingerprintTable, error) {
	s.fingerprintOnce.Do(func() {
		if s.opts.FingerprintDB == "" {
			return
		}
		data, err := os.ReadFile(s.opts.FingerprintDB)
		if err != nil {
			s.fingerprintErr = err
			return
		}
		var t fingerprintTable
		if err := json.Unmarshal(data, &t); err != nil {
			s.fingerprintErr = err
			return
		}
		s.fingerprintTab = &t
	})
	return s.fingerprintTab, s.fingerprintErr
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

// coreAssetVerRe matches the ?ver= cache-buster WordPress appends to core
// asset files it ships with every release: wp-emoji-release.min.js,
// wp-embed.js, wp-util.js and wp-a11y.js (the js/ directory prefix covers
// older releases that kept them under wp-includes/js/). Because these files
// are released together with core, their ?ver= tracks the core version even
// when the generator meta tag and feeds are stripped or rewritten.
var coreAssetVerRe = regexp.MustCompile(`(?i)wp-includes/(?:js/)?(?:wp-emoji-release\.min|wp-embed|wp-util|wp-a11y)\.js[^"']*\?ver=([0-9][0-9a-zA-Z.-]*)`)

// ExtractCoreVersionFromAssets parses the WordPress core version from the
// ?ver= query string on core-released asset references (see coreAssetVerRe).
// found is false when no such asset reference carries a version.
func ExtractCoreVersionFromAssets(html string) (version string, found bool) {
	m := coreAssetVerRe.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return sanitizeVersion(m[1]), true
}

// readmeH1VersionRe matches the version heading of a stock WordPress
// readme.html: <h1 id="version">Version X.Y.Z</h1>. The capture starts at
// a digit and tolerates letters, dots and dashes afterwards so pre-release
// suffixes ("6.5-RC2") survive intact.
var readmeH1VersionRe = regexp.MustCompile(`(?i)<h1[^>]*id="version"[^>]*>\s*Version\s+([0-9][0-9a-zA-Z.-]*)`)

// looseReadmeVersionRe is the fallback for older readme.html releases that
// stamp the version without the id="version" anchor ("Version X.Y.Z" inside
// any element): the version token must sit between an element boundary and
// the next tag, so prose mentioning a version never matches.
var looseReadmeVersionRe = regexp.MustCompile(`(?i)>\s*Version\s+([0-9][0-9a-zA-Z.-]*)<`)

// ExtractCoreVersionFromReadmeHTML parses the WordPress core version out of
// a served readme.html document: the canonical <h1 id="version"> heading
// first, then the looser ">Version X.Y.Z<" element form used by older
// releases. The candidate is sanitized via sanitizeVersion (control
// characters stripped, capped at maxVersionLen runes). found is false when
// neither marker matches or the sanitized result is empty.
func ExtractCoreVersionFromReadmeHTML(body string) (string, bool) {
	for _, re := range []*regexp.Regexp{readmeH1VersionRe, looseReadmeVersionRe} {
		m := re.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		if v := sanitizeVersion(m[1]); v != "" {
			return v, true
		}
	}
	return "", false
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

// restRouteVersionRe matches the "/v<digit>" namespace-version marker
// WordPress appends to REST route namespaces ("contact-form-7/v1/..."). A
// route's plugin slug is everything before this marker — or before the
// first plain "/" when the namespace carries no version marker at all
// ("acme/endpoint" -> "acme").
var restRouteVersionRe = regexp.MustCompile(`/v[0-9]`)

// restSlugRe is the strict character set for REST-route plugin slugs.
// Route namespaces are lowercase by WordPress convention; anything with
// an uppercase letter, a dot or other punctuation is not a slug.
var restSlugRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

// restKnownPrefixes are the route-index namespaces WordPress core and its
// bundled features register ("wp/v2/...", "oembed/1.0/...",
// "wp-site-health/v1/...", "wp/block-directory/v1/..."). Everything else
// under the first namespace segment is treated as a plugin slug candidate.
// Only these exact prefixes are dropped: a plugin named "wp" or
// "oembed" would be a false negative, but none exists in the wild and the
// core routes vastly outweigh that risk.
var restKnownPrefixes = []string{"wp", "oembed", "wp-site-health", "wp/block-directory"}

// restRouteSlug reduces one REST route key to its candidate plugin slug:
// everything up to the first "/v<digit>" marker, or up to the first "/"
// when no version marker exists ("contact-form-7/v1/contact-forms" ->
// "contact-form-7", "elementor/v1" -> "elementor", "acme/endpoint" ->
// "acme"). Routes without any slash ("hello") pass through unchanged.
func restRouteSlug(route string) string {
	if i := restRouteVersionRe.FindStringIndex(route); i != nil {
		return route[:i[0]]
	}
	if i := strings.IndexByte(route, '/'); i >= 0 {
		return route[:i]
	}
	return route
}

// ExtractRESTRoutePlugins parses the WordPress REST API root index
// (/wp-json/) for plugin namespaces: when the body parses as
// {"routes": {...}} the route keys are the candidate list, and a plain
// array of route strings is accepted too. Each route key is reduced to
// its first namespace segment (see restRouteSlug); segments matching the
// exact known core prefixes (wp, oembed, wp-site-health,
// wp/block-directory) are dropped and anything not matching
// ^[a-z0-9_-]+$ or longer than maxRESTRoutePlugins runes is rejected.
// The surviving slugs are deduplicated, sorted and capped at
// maxRESTRoutePlugins entries. A body that parses as neither shape (or
// carries no routes at all) returns nil.
func ExtractRESTRoutePlugins(body []byte) []string {
	var routes []string
	var doc struct {
		Routes map[string]json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal(body, &doc); err == nil && len(doc.Routes) > 0 {
		for route := range doc.Routes {
			routes = append(routes, route)
		}
	} else {
		var arr []string
		if err := json.Unmarshal(body, &arr); err == nil {
			routes = arr
		} else {
			return nil
		}
	}
	seen := make(map[string]bool)
	out := make([]string, 0, min(len(routes), maxRESTRoutePlugins))
	// Deterministic processing order: the routes map iterates randomly,
	// so the 50-entry cap must apply over a sorted list or the survivors
	// would vary between runs.
	sort.Strings(routes)
	for _, route := range routes {
		slug := restRouteSlug(route)
		if len(slug) > maxRESTRoutePlugins || !restSlugRe.MatchString(slug) || seen[slug] {
			continue
		}
		if isRestKnownPrefix(slug) {
			continue
		}
		seen[slug] = true
		out = append(out, slug)
		if len(out) >= maxRESTRoutePlugins {
			break
		}
	}
	sort.Strings(out)
	return out
}

// isRestKnownPrefix reports whether slug is one of the exact core
// route-index prefixes (wp, oembed, wp-site-health, wp/block-directory).
func isRestKnownPrefix(slug string) bool {
	for _, p := range restKnownPrefixes {
		if slug == p {
			return true
		}
	}
	return false
}

// timthumbVersionRe matches the version markers common TimThumb builds
// embed: the "TimThumb version X.Y.Z" banner line, a JSON-style
// "version": "X.Y.Z" field and the $version = 'X.Y.Z' PHP assignment.
// The captured version is deliberately digits-and-dots only, so prose or
// code that merely mentions a version never matches a full release. The
// whole expression is case-insensitive.
var timthumbVersionRe = regexp.MustCompile(`(?i)(?:timthumb\s+version\s+([0-9.]+)|"version"\s*:\s*"([0-9.]+)"|\$version\s*=\s*['"]([0-9.]+)['"])`)

// ExtractTimthumbVersion parses the version out of a TimThumb source or
// info body using the common release markers (see timthumbVersionRe). The
// first marker present wins and the result is sanitized via
// sanitizeVersion (control characters stripped, capped at maxVersionLen
// runes). found is false when the body carries no recognizable marker.
func ExtractTimthumbVersion(body string) (string, bool) {
	for _, m := range timthumbVersionRe.FindAllStringSubmatch(body, -1) {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			if v := sanitizeVersion(g); v != "" {
				return v, true
			}
		}
	}
	return "", false
}
