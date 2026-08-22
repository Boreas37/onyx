package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// sitemapHits records which paths an httptest sitemap fixture served, so
// tests can assert exactly how deep the crawler went and what it spent its
// request budget on.
type sitemapHits struct {
	mu   sync.Mutex
	hits map[string]int
}

func newSitemapHits() *sitemapHits {
	return &sitemapHits{hits: make(map[string]int)}
}

func (h *sitemapHits) add(path string) {
	h.mu.Lock()
	h.hits[path]++
	h.mu.Unlock()
}

func (h *sitemapHits) count(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

// totalPageHits sums hits over content-page paths (/blog/*).
func (h *sitemapHits) totalPageHits() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for p, c := range h.hits {
		if strings.HasPrefix(p, "/blog/") {
			n += c
		}
	}
	return n
}

const (
	sitemapPost1HTML = `<!DOCTYPE html><html><head><title>Post 1</title></head><body>
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.20.0"></script>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.1" />
</body></html>`

	sitemapPost2HTML = `<!DOCTYPE html><html><head><title>Post 2</title></head><body>
<script src="/wp-content/plugins/hello-dolly/hello.js?ver=1.6&amp;m=2"></script>
</body></html>`
)

// sitemapServer serves a WordPress site whose discovery works purely via a
// sitemap index: wp-sitemap.xml -> child sitemap -> two content pages. The
// fixtures deliberately include traps: a nested child-of-child sitemap (must
// never be fetched), a foreign-host <loc>, and a relative <loc>.
func sitemapServer() (*httptest.Server, *sitemapHits) {
	hits := newSitemapHits()
	mux := http.NewServeMux()

	index := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<sitemap><loc>%s/wp-sitemap-pages-1.xml</loc></sitemap>
<sitemap><loc>https://evil.example/hostile.xml</loc></sitemap>
</sitemapindex>`

	child := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>%s/blog/post-1/</loc></url>
<url><loc>%s/blog/post-2/</loc></url>
<url><loc>%s/wp-sitemap-pages-2.xml</loc></url>
<url><loc>https://evil.example/page-hijack</loc></url>
<url><loc>relative/no-slash</loc></url>
</urlset>`

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		hits.add("/wp-sitemap.xml")
		base := "http://" + r.Host
		_, _ = fmt.Fprintf(w, index, base)
	})
	mux.HandleFunc("/wp-sitemap-pages-1.xml", func(w http.ResponseWriter, r *http.Request) {
		hits.add("child:/wp-sitemap-pages-1.xml")
		base := "http://" + r.Host
		_, _ = fmt.Fprintf(w, child, base, base, base)
	})
	mux.HandleFunc("/wp-sitemap-pages-2.xml", func(w http.ResponseWriter, r *http.Request) {
		hits.add("deeper:/wp-sitemap-pages-2.xml") // one level too deep
		_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/blog/post-1/</loc></url></urlset>`))
	})
	for _, p := range []struct{ path, html string }{
		{"/blog/post-1/", sitemapPost1HTML},
		{"/blog/post-2/", sitemapPost2HTML},
	} {
		path, html := p.path, p.html
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits.add(path)
			_, _ = w.Write([]byte(html))
		})
	}
	return httptest.NewServer(mux), hits
}

// TestDiscoverViaSitemapIndexToChildPages walks the full index -> child ->
// pages flow and checks every artefact: returned page paths, discovered
// plugin/theme slugs, ?ver= versions, the one-level-deep cap (the nested
// child-of-child document is never fetched) and foreign-host rejection.
func TestDiscoverViaSitemapIndexToChildPages(t *testing.T) {
	srv, hits := sitemapServer()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}

	pages := sc.discoverViaSitemap(10)

	wantPages := []string{"/blog/post-1/", "/blog/post-2/"}
	if len(pages) != len(wantPages) {
		t.Fatalf("pages = %v, want %v", pages, wantPages)
	}
	for i := range wantPages {
		if pages[i] != wantPages[i] {
			t.Errorf("pages[%d] = %q, want %q", i, pages[i], wantPages[i])
		}
	}

	wantPlugins := []string{"elementor", "hello-dolly"}
	if len(sc.sitemapPlugins) != len(wantPlugins) {
		t.Fatalf("plugins = %v, want %v", sc.sitemapPlugins, wantPlugins)
	}
	for i := range wantPlugins {
		if sc.sitemapPlugins[i] != wantPlugins[i] {
			t.Errorf("plugins[%d] = %q, want %q", i, sc.sitemapPlugins[i], wantPlugins[i])
		}
	}
	if len(sc.sitemapThemes) != 1 || sc.sitemapThemes[0] != "twentytwentyfour" {
		t.Errorf("themes = %v, want [twentytwentyfour]", sc.sitemapThemes)
	}

	wantVers := map[string]string{
		"elementor":         "3.20.0",
		"hello-dolly":       "1.6", // html-entity ampersand tolerated
		"twentytwentyfour":  "1.1",
	}
	for slug, want := range wantVers {
		if got := sc.sitemapVersions[slug]; got != want {
			t.Errorf("versions[%s] = %q, want %q", slug, got, want)
		}
	}

	// Exactly four requests spent: index, child sitemap, two pages.
	if got := sc.sitemapRequests; got != 4 {
		t.Errorf("sitemapRequests = %d, want 4", got)
	}
	if hits.count("deeper:/wp-sitemap-pages-2.xml") != 0 {
		t.Error("nested child-of-child sitemap was fetched (must stay one level deep)")
	}
	if hits.count("child:/wp-sitemap-pages-1.xml") != 1 {
		t.Errorf("child sitemap hits = %d, want 1", hits.count("child:/wp-sitemap-pages-1.xml"))
	}
}

// TestDiscoverViaSitemapCapsPages verifies maxPages bounds how many content
// pages are fetched even when more are queued by the child sitemap.
func TestDiscoverViaSitemapCapsPages(t *testing.T) {
	srv, hits := sitemapServer()
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	pages := sc.discoverViaSitemap(1)
	if len(pages) != 1 || pages[0] != "/blog/post-1/" {
		t.Fatalf("pages = %v, want [/blog/post-1/]", pages)
	}
	if got := hits.totalPageHits(); got != 1 {
		t.Errorf("page fetches = %d, want 1 (maxPages cap)", got)
	}
	if _, ok := sc.sitemapVersions["hello-dolly"]; ok {
		t.Error("second page must not have been mined")
	}
}

// TestDiscoverViaSitemapRespectsBudget verifies crawling stops when the
// --max-requests budget is exhausted: the table pins down how many of the
// queued pages may be fetched after the index and child documents spent
// their share.
func TestDiscoverViaSitemapRespectsBudget(t *testing.T) {
	cases := []struct {
		name      string
		maxReqs   int
		wantPages int
	}{
		{"budget exhausted before pages", 2, 0},
		{"budget for exactly one page", 3, 1},
		{"ample budget", 500, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, hits := sitemapServer()
			defer srv.Close()

			d, _ := db.Load(minimalFeed(t))
			sc, err := NewScanner(d, srv.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			sc.maxRequests = c.maxReqs

			pages := sc.discoverViaSitemap(10)
			if len(pages) != c.wantPages {
				t.Fatalf("pages = %v (%d), want %d", pages, len(pages), c.wantPages)
			}
			if got := hits.totalPageHits(); got != c.wantPages {
				t.Errorf("page fetches = %d, want %d", got, c.wantPages)
			}
			if sc.sitemapRequests > c.maxReqs {
				t.Errorf("spent %d requests over the %d budget", sc.sitemapRequests, c.maxReqs)
			}
		})
	}
}

// TestDiscoverViaSitemapIndexExpansionCappedByBudget proves a hostile
// sitemap index listing dozens of children cannot burn requests beyond the
// budget during index expansion itself.
func TestDiscoverViaSitemapIndexExpansionCappedByBudget(t *testing.T) {
	const children = 30
	hits := newSitemapHits()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	for i := 0; i < children; i++ {
		fmt.Fprintf(&b, `<sitemap><loc>/kid-%d.xml</loc></sitemap>`, i)
	}
	b.WriteString(`</sitemapindex>`)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
	})
	mux.HandleFunc("/wp-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(b.String()))
	})
	for i := 0; i < children; i++ {
		path := fmt.Sprintf("/kid-%d.xml", i)
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits.add(path)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sc.maxRequests = 4 // index + 3 children, then stop

	pages := sc.discoverViaSitemap(10)
	if len(pages) != 0 {
		t.Errorf("pages = %v, want none (empty children)", pages)
	}
	fetched := 0
	for i := 0; i < children; i++ {
		fetched += hits.count(fmt.Sprintf("/kid-%d.xml", i))
	}
	if fetched != 3 {
		t.Errorf("children fetched = %d, want 3 (budget-capped expansion)", fetched)
	}
	if sc.sitemapRequests != 4 {
		t.Errorf("sitemapRequests = %d, want 4", sc.sitemapRequests)
	}
}

// TestDiscoverViaSitemapFallsBackToSitemapXml covers the fallback root
// document and the no-sitemap-at-all case.
func TestDiscoverViaSitemapFallsBackToSitemapXml(t *testing.T) {
	t.Run("fallback used", func(t *testing.T) {
		hits := newSitemapHits()
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>`))
		})
		mux.HandleFunc("/wp-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			hits.add("/sitemap.xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>` + "http://" + r.Host + `/blog/post-1/</loc></url>
</urlset>`))
		})
		mux.HandleFunc("/blog/post-1/", func(w http.ResponseWriter, r *http.Request) {
			hits.add("/blog/post-1/")
			_, _ = w.Write([]byte(sitemapPost1HTML))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		d, _ := db.Load(minimalFeed(t))
		sc, err := NewScanner(d, srv.URL, Options{})
		if err != nil {
			t.Fatal(err)
		}
		pages := sc.discoverViaSitemap(5)
		if len(pages) != 1 || pages[0] != "/blog/post-1/" {
			t.Fatalf("pages = %v, want [/blog/post-1/]", pages)
		}
		if hits.count("/sitemap.xml") != 1 {
			t.Errorf("fallback sitemap.xml hits = %d, want 1", hits.count("/sitemap.xml"))
		}
		if sc.sitemapPlugins == nil || len(sc.sitemapPlugins) != 1 || sc.sitemapPlugins[0] != "elementor" {
			t.Errorf("plugins = %v, want [elementor]", sc.sitemapPlugins)
		}
	})

	t.Run("no sitemap anywhere", func(t *testing.T) {
		srv := fakeWordPress() // everything 404s except the fixed handlers
		defer srv.Close()

		d, _ := db.Load(minimalFeed(t))
		sc, err := NewScanner(d, srv.URL, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if pages := sc.discoverViaSitemap(5); len(pages) != 0 {
			t.Errorf("pages = %v, want none when no sitemap exists", pages)
		}
	})
}

// TestScanCrawlPagesEndToEnd runs a full Scan with --crawl-pages: slugs and
// versions found only on sitemap pages surface as Detected entries with
// Source "passive-ver" and feed database matching, while enumeration stays
// idle (--enumerate m). A second scan without CrawlPages must never touch
// the sitemap endpoints (0 = disabled).
func TestScanCrawlPagesEndToEnd(t *testing.T) {
	srv, hits := sitemapServer()
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m", CrawlPages: 5})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	bySlug := make(map[string]Detected)
	for _, det := range res.Detected {
		bySlug[det.Slug] = det
	}
	for slug, wantVer := range map[string]string{
		"elementor":        "3.20.0",
		"hello-dolly":      "1.6",
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

	found := false
	for _, f := range res.Findings {
		if f.Slug == "elementor" {
			found = true
			if f.InstalledVersion != "3.20.0" || len(f.Vulnerabilities) != 1 {
				t.Errorf("elementor finding = %+v, want version 3.20.0 with 1 vulnerability", f)
			}
		}
	}
	if !found {
		t.Errorf("expected elementor finding matched from the sitemap-derived version, got %+v", res.Findings)
	}
	if hits.count("/wp-sitemap.xml") != 1 {
		t.Errorf("root sitemap hits = %d, want 1", hits.count("/wp-sitemap.xml"))
	}

	// CrawlPages = 0 disables sitemap discovery entirely.
	srv2, hitsDisabled := sitemapServer()
	defer srv2.Close()
	sc2, err := NewScanner(d, srv2.URL, Options{Enumerate: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc2.Scan(); err != nil {
		t.Fatalf("Scan without crawl: %v", err)
	}
	if hitsDisabled.count("/wp-sitemap.xml") != 0 {
		t.Error("sitemap crawled although CrawlPages was 0 (disabled)")
	}
	if sc2.sitemapRequests != 0 {
		t.Errorf("sitemapRequests = %d, want 0 when crawling is disabled", sc2.sitemapRequests)
	}
}
