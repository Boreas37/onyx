package scanner

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
)

// maxSitemapLocs caps the <loc> entries parsed from a single sitemap
// document so a hostile multi-megabyte feed cannot balloon memory.
const maxSitemapLocs = 1000

// discoverViaSitemap crawls the site's sitemap for passive discovery. It
// fetches /wp-sitemap.xml first and /sitemap.xml as a fallback, expands
// sitemap index documents (<sitemap><loc>) exactly one level deep, then
// fetches up to maxPages content page URLs (.xml/.xsl locations are
// treated as child sitemaps, never as pages). Every fetched page body is
// mined with ExtractPassiveSlugsIn/ExtractPassiveVersionsIn and merged
// into the discovery results exactly like homepage references. Returns
// the content page paths that were fetched.
//
// All requests go through the scanner's normal fetch machinery (rate
// limiting, UA, timeouts) and are counted in s.sitemapRequests so they
// draw from the --max-requests budget; crawling stops as soon as the
// budget is exhausted or --max-scan-duration expires.
func (s *Scanner) discoverViaSitemap(maxPages int) []string {
	if maxPages <= 0 {
		return nil
	}
	pages := make([]string, 0, maxPages)
	seen := make(map[string]bool)
	var queue []string // content page URLs awaiting fetch

	// collect maps <loc> entries onto site-relative paths: .xml documents
	// are returned as child sitemaps, .xsl locations are dropped, and
	// everything else joins the content-page fetch queue.
	collect := func(locs []string) (children []string) {
		for _, loc := range locs {
			p, ok := sitemapSitePath(loc, s.base)
			if !ok || seen[p] {
				continue
			}
			seen[p] = true
			switch {
			case strings.HasSuffix(strings.ToLower(p), ".xml"):
				children = append(children, p)
			case isSitemapDoc(p): // .xsl and friends: neither page nor doc
			default:
				queue = append(queue, p)
			}
		}
		return children
	}
	fetchDoc := func(path string) ([]string, bool) {
		code, body, err := s.fetch(path)
		s.sitemapRequests++
		if err != nil || code != http.StatusOK {
			return nil, false
		}
		return parseSitemapLocs(body), true
	}

	// Root sitemap: wp-sitemap.xml first, sitemap.xml as fallback. The
	// first reachable document wins; its child sitemaps are expanded one
	// level deep (their own .xml references are ignored).
	for _, root := range []string{"/wp-sitemap.xml", "/sitemap.xml"} {
		locs, ok := fetchDoc(root)
		if !ok {
			continue
		}
		for _, kid := range collect(locs) {
			if s.scanDone() || s.sitemapRequests >= s.maxRequests {
				break // index expansion stays inside the request budget
			}
			kidLocs, _ := fetchDoc(kid)
			collect(kidLocs)
		}
		break
	}

	for _, p := range queue {
		if len(pages) >= maxPages || s.scanDone() || s.sitemapRequests >= s.maxRequests {
			break
		}
		code, body, err := s.fetch(p)
		s.sitemapRequests++
		if err != nil || code != http.StatusOK {
			continue
		}
		pages = append(pages, p)
		s.collectSitemapRefs(string(body))
	}
	return pages
}

// collectSitemapRefs extracts passive plugin/theme slugs and ?ver= versions
// from one fetched page body, merging them into the discovery results.
func (s *Scanner) collectSitemapRefs(html string) {
	plugs, themes := ExtractPassiveSlugsIn(html, s.contentDir)
	s.sitemapPlugins = unique(append(s.sitemapPlugins, plugs...))
	s.sitemapThemes = unique(append(s.sitemapThemes, themes...))
	if s.sitemapVersions == nil {
		s.sitemapVersions = make(map[string]string)
	}
	for slug, ver := range ExtractPassiveVersionsIn(html, s.contentDir) {
		if _, ok := s.sitemapVersions[slug]; !ok {
			s.sitemapVersions[slug] = ver
		}
	}
}

// parseSitemapLocs extracts every <loc> value from a sitemap urlset or
// sitemap index document. A token-based encoding/xml walk keeps namespace
// prefixes irrelevant; malformed documents degrade to whatever was parsed
// before the error instead of failing.
func parseSitemapLocs(body []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	var (
		locs  []string
		inLoc bool
		buf   strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			return locs
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "loc" {
				inLoc = true
				buf.Reset()
			}
		case xml.CharData:
			if inLoc {
				buf.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "loc" && inLoc {
				inLoc = false
				if v := strings.TrimSpace(buf.String()); v != "" {
					locs = append(locs, v)
					if len(locs) >= maxSitemapLocs {
						return locs
					}
				}
			}
		}
	}
}

// isSitemapDoc reports whether a collected location looks like another
// sitemap document (.xml/.xsl) rather than a content page.
func isSitemapDoc(p string) bool {
	l := strings.ToLower(p)
	return strings.HasSuffix(l, ".xml") || strings.HasSuffix(l, ".xsl")
}

// sitemapSitePath maps a <loc> entry onto a site-relative path usable with
// the scanner's fetch helper. Absolute URLs are accepted only when they
// point at the scanned host over http(s); anything else (foreign hosts,
// mailto:, fragments, bare relative paths without a leading slash) is
// skipped.
func sitemapSitePath(loc, base string) (string, bool) {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return "", false
	}
	u, err := url.Parse(loc)
	if err != nil || u.User != nil {
		return "", false
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", false
		}
		b, berr := url.Parse(base)
		if berr != nil || !strings.EqualFold(u.Host, b.Host) {
			return "", false
		}
	}
	p := u.Path
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}
