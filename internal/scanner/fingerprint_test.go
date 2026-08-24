package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

func TestExtractPassiveVersions(t *testing.T) {
	cases := []struct {
		name string
		html string
		want map[string]string
	}{
		{
			name: "plugin script reference",
			html: `<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.1"></script>`,
			want: map[string]string{"contact-form-7": "5.8.1"},
		},
		{
			name: "theme stylesheet reference",
			html: `<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />`,
			want: map[string]string{"twentytwentyfour": "1.2"},
		},
		{
			name: "plugin and theme together",
			html: `<script src="/wp-content/plugins/a/assets/x.js?ver=1.0"></script>
<link href="/wp-content/themes/b/style.css?ver=2.0" />`,
			want: map[string]string{"a": "1.0", "b": "2.0"},
		},
		{
			name: "first reference wins on conflicting versions",
			html: `<script src="/wp-content/plugins/a/x.js?ver=1.0"></script>
<script src="/wp-content/plugins/a/y.js?ver=9.9"></script>`,
			want: map[string]string{"a": "1.0"},
		},
		{
			name: "html-escaped ampersand before ver",
			html: `<script src="/wp-content/plugins/a/x.js?m=1&amp;ver=3.1"></script>`,
			want: map[string]string{"a": "3.1"},
		},
		{
			name: "raw ampersand before ver",
			html: `<script src="/wp-content/plugins/a/x.js?m=1&ver=3.2"></script>`,
			want: map[string]string{"a": "3.2"},
		},
		{
			name: "version stops at next query parameter",
			html: `<script src="/wp-content/plugins/a/x.js?ver=1.2&#038;m=y"></script>`,
			want: map[string]string{"a": "1.2"},
		},
		{
			name: "case-insensitive path and slug charset",
			html: `<SCRIPT SRC="/WP-Content/Plugins/My_Plugin-2/A.JS?VER=4.5"></SCRIPT>`,
			want: map[string]string{"My_Plugin-2": "4.5"},
		},
		{
			name: "no version query means no entry",
			html: `<link href="/wp-content/plugins/a/style.css" />`,
			want: map[string]string{},
		},
		{
			name: "query without ver is ignored",
			html: `<link href="/wp-content/plugins/a/style.css?foo=1.2.3" />`,
			want: map[string]string{},
		},
		{
			name: "empty version is ignored",
			html: `<link href="/wp-content/plugins/a/style.css?ver=" />`,
			want: map[string]string{},
		},
		{
			name: "empty html",
			html: "",
			want: map[string]string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractPassiveVersions(c.html)
			if len(got) != len(c.want) {
				t.Fatalf("ExtractPassiveVersions = %v, want %v", got, c.want)
			}
			for slug, wantVer := range c.want {
				if got[slug] != wantVer {
					t.Errorf("versions[%s] = %q, want %q", slug, got[slug], wantVer)
				}
			}
		})
	}
}

// TestExtractPassiveVersionsHostileVersionCapped verifies a hostile page
// cannot smuggle an oversized version string through the ?ver= extractor.
func TestExtractPassiveVersionsHostileVersionCapped(t *testing.T) {
	html := `<script src="/wp-content/plugins/evil/x.js?ver=1.` + strings.Repeat("9", 10000) + `"></script>`
	got := ExtractPassiveVersions(html)
	v, ok := got["evil"]
	if !ok {
		t.Fatal("expected a version for evil")
	}
	if len(v) > maxVersionLen {
		t.Fatalf("version not capped: %d chars", len(v))
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control char %q survived in version %q", r, v)
		}
	}
}

func TestExtractPassiveVersionsIn(t *testing.T) {
	html := `<img src="https://example.com/my-content/plugins/elementor/x.js?ver=3.1" />
<link href="/my-content/themes/astra/style.css?ver=4.0" />`
	got := ExtractPassiveVersionsIn(html, "my-content")
	if got["elementor"] != "3.1" || got["astra"] != "4.0" {
		t.Fatalf("custom dir versions = %v, want elementor 3.1 + astra 4.0", got)
	}
	if p := ExtractPassiveVersionsIn(html, "wp-content"); len(p) != 0 {
		t.Errorf("default dir must not match custom dir refs, got %v", p)
	}
}

// TestExtractPassiveVersionsCap verifies the result map is capped at
// maxPassiveVersions entries so pathological pages stay bounded.
func TestExtractPassiveVersionsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 250; i++ {
		b.WriteString(`<script src="/wp-content/plugins/slug-` + itoa(i) + `/x.js?ver=1.0"></script>`)
	}
	got := ExtractPassiveVersions(b.String())
	if len(got) != maxPassiveVersions {
		t.Fatalf("got %d versions, want cap %d", len(got), maxPassiveVersions)
	}
}

func TestExtractRSSAndOPMLVersions(t *testing.T) {
	cases := []struct {
		name string
		body string
		fn   func(string) (string, bool)
		want string
		ok   bool
	}{
		{"rss url form", `<generator>https://wordpress.org/?v=6.4.3</generator>`, ExtractRSSVersion, "6.4.3", true},
		{"rss with site url prefix", `<generator>https://example.com/wordpress.org/?v=5.9</generator>`, ExtractRSSVersion, "5.9", true},
		{"rss no match", `<generator>Some Other Generator</generator>`, ExtractRSSVersion, "", false},
		{"opml attribute", `<opml version="2.0" generator="WordPress/6.5">`, ExtractOPMLVersion, "6.5", true},
		{"opml single quotes", `<head generator='WordPress/6.5.1'>`, ExtractOPMLVersion, "6.5.1", true},
		{"opml no match", `<opml version="2.0"></opml>`, ExtractOPMLVersion, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.fn(c.body)
			if ok != c.ok || got != c.want {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}

	long := `<generator>https://wordpress.org/?v=6.` + strings.Repeat("4", 10000) + `</generator>`
	if v, ok := ExtractRSSVersion(long); !ok || len(v) > maxVersionLen {
		t.Errorf("hostile rss version not capped: len=%d ok=%v", len(v), ok)
	}
	longOPML := `generator="WordPress/6.` + strings.Repeat("5", 10000) + `"`
	if v, ok := ExtractOPMLVersion(longOPML); !ok || len(v) > maxVersionLen {
		t.Errorf("hostile opml version not capped: len=%d ok=%v", len(v), ok)
	}
}

// passiveVerServer serves a homepage whose asset URLs carry ?ver=
// cache-busters for one plugin and one theme, and counts any request to
// their readme.txt / style.css probe paths.
func passiveVerServer() (*httptest.Server, *atomic.Int64) {
	var probes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body>
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.24.0"></script>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.1" />
</body></html>`))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.24.0\n"))
	})
	mux.HandleFunc("/wp-content/themes/twentytwentyfour/style.css", func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		_, _ = w.Write([]byte("/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.1\n*/\n"))
	})
	return httptest.NewServer(mux), &probes
}

// TestScanPassiveVerDetectionWithoutExtraRequests proves homepage ?ver=
// references produce Detected entries with versions without probing
// readme.txt/style.css: enumeration is disabled (--enumerate m), so the
// only possible source is the homepage HTML itself. The versioned entries
// also feed DB matching, producing the elementor finding.
func TestScanPassiveVerDetectionWithoutExtraRequests(t *testing.T) {
	srv, probes := passiveVerServer()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := probes.Load(); n != 0 {
		t.Errorf("readme.txt/style.css probed %d times, want 0 (passive detection must be free)", n)
	}
	bySlug := make(map[string]Detected)
	for _, det := range res.Detected {
		bySlug[det.Slug] = det
	}
	for slug, wantVer := range map[string]string{
		"elementor":        "3.24.0",
		"twentytwentyfour": "1.1",
	} {
		det, ok := bySlug[slug]
		if !ok {
			t.Errorf("expected %s in detected components, got %+v", slug, res.Detected)
			continue
		}
		if det.Version != wantVer {
			t.Errorf("%s version = %q, want %q", slug, det.Version, wantVer)
		}
		if det.Source != "passive-ver" {
			t.Errorf("%s source = %q, want passive-ver", slug, det.Source)
		}
	}

	// The passive version feeds DB matching: elementor 3.24.0 sits inside
	// the feed's affected range.
	found := false
	for _, f := range res.Findings {
		if f.Slug == "elementor" {
			found = true
			if f.InstalledVersion != "3.24.0" || len(f.Vulnerabilities) != 1 {
				t.Errorf("elementor finding = %+v, want version 3.24.0 with 1 vulnerability", f)
			}
		}
	}
	if !found {
		t.Errorf("expected elementor finding from passive version, got %+v", res.Findings)
	}
}

// itoa avoids strconv imports in test-only helpers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// coreSourceHits counts requests to the optional core-version endpoints so
// tests can verify the fallback chain short-circuits.
type coreSourceHits struct {
	rss2 atomic.Int64 // /?feed=rss2
	feed atomic.Int64 // /feed/
	opml atomic.Int64 // /wp-links-opml.php
}

// coreSourceServer serves a WordPress site whose core-version sources are
// individually enabled: an empty body means the endpoint 404s. The
// homepage carries metaHTML verbatim inside <head>.
func coreSourceServer(metaHTML, rss2Body, feedBody, opmlBody string) (*httptest.Server, *coreSourceHits) {
	hits := &coreSourceHits{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>` + metaHTML + `</head><body></body></html>`))
	})
	serve := func(path string, counter *atomic.Int64, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			counter.Add(1)
			if body == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(body))
		})
	}
	const rssGen = `<?xml version="1.0"?><rss version="2.0"><channel><title>T</title><generator>https://wordpress.org/?v=6.4.3</generator></channel></rss>`
	const opmlDoc = `<?xml version="1.0"?><opml version="2.0" generator="WordPress/6.5"><head/><body/></opml>`
	serve("/?feed=rss2", &hits.rss2, or404(rss2Body, rssGen))
	mux.HandleFunc("/feed/", func(w http.ResponseWriter, r *http.Request) {
		hits.feed.Add(1)
		if feedBody == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(rssGen))
	})
	serve("/wp-links-opml.php", &hits.opml, or404(opmlBody, opmlDoc))
	return httptest.NewServer(mux), hits
}

// or404 maps a case flag ("on"/"") onto the served document body.
func or404(flag, doc string) string {
	if flag == "" {
		return ""
	}
	return doc
}

// TestDetectWPCoreVersionFallbackOrder pins down the multi-source core
// version discovery: generator meta tag first, then the RSS feed
// generators (/?feed=rss2 then /feed/), then wp-links-opml.php — each
// tried only when every earlier source failed, and whichever source wins
// is recorded in CoreEvidence.
func TestDetectWPCoreVersionFallbackOrder(t *testing.T) {
	cases := []struct {
		name        string
		meta        bool
		rss2On      bool
		feedOn      bool
		opmlOn      bool
		wantVersion string
		wantSource  string
	}{
		{name: "meta wins over everything", meta: true, rss2On: true, feedOn: true, opmlOn: true,
			wantVersion: "6.4.2", wantSource: "meta"},
		{name: "rss2 when no meta", meta: false, rss2On: true, feedOn: true, opmlOn: true,
			wantVersion: "6.4.3", wantSource: "rss"},
		{name: "feed/ when rss2 missing", meta: false, rss2On: false, feedOn: true, opmlOn: true,
			wantVersion: "6.4.3", wantSource: "rss"},
		{name: "opml last resort", meta: false, rss2On: false, feedOn: false, opmlOn: true,
			wantVersion: "6.5", wantSource: "opml"},
		{name: "no source answers", meta: false, rss2On: false, feedOn: false, opmlOn: false,
			wantVersion: "", wantSource: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			metaHTML := ""
			if c.meta {
				metaHTML = `<meta name="generator" content="WordPress 6.4.2" />`
			}
			srv, hits := coreSourceServer(metaHTML, onOff(c.rss2On), onOff(c.feedOn), onOff(c.opmlOn))
			defer srv.Close()

			d, _ := db.Load(minimalFeed(t))
			sc, err := NewScanner(d, srv.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			ver, ev, err := sc.detectWP()
			if err != nil {
				t.Fatalf("detectWP: %v", err)
			}
			if ver != c.wantVersion {
				t.Errorf("core version = %q, want %q", ver, c.wantVersion)
			}
			switch c.wantSource {
			case "":
				if len(sc.coreEvidence) != 0 {
					t.Errorf("coreEvidence = %+v, want empty", sc.coreEvidence)
				}
			default:
				if len(sc.coreEvidence) != 1 ||
					sc.coreEvidence[0].Source != c.wantSource ||
					sc.coreEvidence[0].Version != c.wantVersion {
					t.Errorf("coreEvidence = %+v, want [{%s %s}]", sc.coreEvidence, c.wantSource, c.wantVersion)
				}
				foundEv := false
				for _, e := range ev {
					if strings.Contains(e, c.wantVersion) {
						foundEv = true
					}
				}
				if !foundEv {
					t.Errorf("evidence %v does not mention version %q", ev, c.wantVersion)
				}
			}

			// Fallback short-circuit: sources before the winner must never
			// have been requested, sources after it must stay untouched.
			switch c.wantSource {
			case "meta":
				if hits.rss2.Load() != 0 || hits.feed.Load() != 0 || hits.opml.Load() != 0 {
					t.Errorf("fallback endpoints hit despite meta tag: rss2=%d feed=%d opml=%d",
						hits.rss2.Load(), hits.feed.Load(), hits.opml.Load())
				}
			case "rss":
				if hits.opml.Load() != 0 {
					t.Errorf("wp-links-opml.php hit despite RSS success (%d)", hits.opml.Load())
				}
			}
		})
	}
}

// onOff converts a case flag into the server helper's ""/"on" scheme.
func onOff(on bool) string {
	if on {
		return "on"
	}
	return ""
}

func TestExtractVersionFromChangelog(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{
			name: "classic heading",
			body: "=== My Plugin ===\nStable tag: 2.0\n\n== Changelog ==\n\n= 3.1.4 =\n* Fixed things\n",
			want: "3.1.4", ok: true,
		},
		{
			name: "markdown heading",
			body: "## Changelog\n\n### 4.2.0\n\n* release notes\n",
			want: "4.2.0", ok: true,
		},
		{
			name: "bare version dash first line",
			body: "== Changelog ==\n\n1.2.3 - Initial release\n\n* notes\n",
			want: "1.2.3", ok: true,
		},
		{
			name: "first heading wins",
			body: "== Changelog ==\n= 9.9.9 =\n= 8.8.8 =\n",
			want: "9.9.9", ok: true,
		},
		{
			name: "heading before changelog ignored",
			body: "= 0.0.1 =\n\n== Changelog ==\n= 3.0.0 =\n",
			want: "3.0.0", ok: true,
		},
		{
			name: "no changelog section",
			body: "=== My Plugin ===\nStable tag: 1.0\n",
			want: "", ok: false,
		},
		{
			name: "changelog with no version heading",
			body: "== Changelog ==\n\n* Just notes, no version headings.\n",
			want: "", ok: false,
		},
		{
			name: "empty body",
			body: "",
			want: "", ok: false,
		},
		{
			name: "v prefix tolerated",
			body: "== Changelog ==\n= v1.4.0 =\n",
			want: "v1.4.0", ok: true,
		},
		{
			name: "non-heading version mention not matched",
			body: "== Changelog ==\n\nSome notes mention 1.5.0 inside a sentence.\n",
			want: "", ok: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ExtractVersionFromChangelog(c.body)
			if ok != c.ok || got != c.want {
				t.Errorf("ExtractVersionFromChangelog = (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}

// TestExtractVersionFromChangelogHostileVersionRejected verifies a hostile
// changelog heading whose version overflows the numeric parse (a segment
// longer than 18 digits) is REJECTED outright — fail-closed, never
// truncated into a plausible-looking version string.
func TestExtractVersionFromChangelogHostileVersionRejected(t *testing.T) {
	body := "== Changelog ==\n= 1." + strings.Repeat("9", 10000) + " =\n"
	if v, ok := ExtractVersionFromChangelog(body); ok {
		t.Fatalf("hostile overflowing version must be rejected, got %q", v)
	}
}
