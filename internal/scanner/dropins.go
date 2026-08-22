package scanner

import (
	"net/http"
	"strings"
)

// maxDropinFindings caps how many Interesting entries the drop-in/cache
// detection may add to a single scan result.
const maxDropinFindings = 5

// cacheHeaderHints maps HTTP response header names emitted by common
// page-cache layers to the static Interesting entry they produce. All
// strings are constants: no target-controlled data flows into the output.
var cacheHeaderHints = []struct {
	header  string
	finding string
}{
	{"X-Cache", "Page cache detected: cache layer (X-Cache header)"},
	{"X-Varnish", "Page cache detected: Varnish"},
	{"X-WP-Super-Cache", "Page cache detected: WP Super Cache"},
	{"W3TC", "Page cache detected: W3 Total Cache"},
	{"X-LiteSpeed-Cache", "Page cache detected: LiteSpeed Cache"},
	{"X-Proxy-Cache", "Page cache detected: cache layer (X-Proxy-Cache header)"},
	{"CF-Cache-Status", "Page cache detected: Cloudflare"},
}

// muPluginsListingMarkers identify an Apache/nginx-style directory listing.
var muPluginsListingMarkers = []string{
	"Index of",
	"Parent Directory",
	"<title>Directory listing",
}

// dropinFinder detects drop-in components that are not plugins or themes:
//
//  1. Page-cache layers, sniffed from the response headers of a fresh
//     homepage GET (fetch() discards headers, so this uses fetchHeaders).
//  2. An exposed wp-content/mu-plugins/ directory listing (must-drop-in
//     plugins are invisible to the REST inventory, so a listing is the
//     only way to see them). The configured content directory is used,
//     not a hardcoded wp-content.
//
// At most maxDropinFindings entries are returned, deduplicated; every
// string is a static constant built from matched header names.
func (s *Scanner) dropinFinder() []string {
	var out []string
	seen := make(map[string]bool)
	add := func(msg string) {
		if len(out) >= maxDropinFindings || seen[msg] {
			return
		}
		seen[msg] = true
		out = append(out, msg)
	}

	var (
		code int
		hdr  http.Header
		body []byte
		err  error
	)
	code, hdr, _, err = s.fetchHeaders("/")
	if err == nil && code > 0 {
		for _, h := range cacheHeaderHints {
			if hdr.Get(h.header) != "" {
				add(h.finding)
			}
		}
	}

	code, body, err = s.fetch("/" + s.contentDir + "/mu-plugins/")
	if err == nil && code == http.StatusOK {
		b := string(body)
		for _, marker := range muPluginsListingMarkers {
			if strings.Contains(b, marker) {
				add("mu-plugins directory exposed")
				break
			}
		}
	}
	return out
}
