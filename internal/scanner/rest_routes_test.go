package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// routeIndexJSON builds a wp-json root-index body whose "routes" map
// carries the given route keys (each mapped to a minimal namespace
// object, the real shape of the REST route index).
func routeIndexJSON(routes ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"routes":{`)
	for i, r := range routes {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:{\"namespace\":%q}", r, r)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

// TestExtractRESTRoutePluginsMixedRoutes drives the route-index parser
// with a realistic mixed route list: plugin namespaces of every common
// shape survive, exact core prefixes (wp, oembed, wp-site-health,
// wp/block-directory) are dropped, and the output is sorted and
// deduplicated.
func TestExtractRESTRoutePluginsMixedRoutes(t *testing.T) {
	body := routeIndexJSON(
		"contact-form-7/v1/contact-forms",
		"elementor/v1",
		"acme/endpoint",
		"hello-dolly/v2/messages",
		"woocommerce/v3/orders",
		"wp/v2/posts",
		"wp/v1/media",
		"oembed/1.0/embed",
		"wp-site-health/v1/tests",
		"wp/block-directory/v1/items",
		// The same slug reached through two namespaces dedupes to one.
		"contact-form-7/v2/settings",
	)
	got := ExtractRESTRoutePlugins(body)
	want := []string{"acme", "contact-form-7", "elementor", "hello-dolly", "woocommerce"}
	if len(got) != len(want) {
		t.Fatalf("ExtractRESTRoutePlugins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("slugs[%d] = %q, want %q (sorted, deduplicated, core prefixes dropped)", i, got[i], want[i])
		}
	}
}

// TestExtractRESTRoutePluginsArrayShape verifies the array-of-route-strings
// shape of the parser: ["contact-form-7/v1/x", ...] parses exactly like
// the {"routes": {...}} object shape.
func TestExtractRESTRoutePluginsArrayShape(t *testing.T) {
	body := []byte(`["contact-form-7/v1/contact-forms", "wp/v2/posts", "acme/endpoint"]`)
	got := ExtractRESTRoutePlugins(body)
	want := []string{"acme", "contact-form-7"}
	if len(got) != len(want) {
		t.Fatalf("ExtractRESTRoutePlugins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("slugs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractRESTRoutePluginsRejectsBadSlugs verifies the slug filter:
// uppercase, punctuation and over-long namespace segments are rejected,
// and a route with no slash at all passes through as a candidate.
func TestExtractRESTRoutePluginsRejectsBadSlugs(t *testing.T) {
	long := strings.Repeat("x", 60)
	body := routeIndexJSON(
		"Yoast/v1/config",  // uppercase: not a slug
		"acme.plugin/v1/x", // dot in the segment
		"blog-name",        // no slash: candidate verbatim
		long+"/v1/x",       // over the length cap
		"under_score/v1/x", // underscore is legal
		"dash-plugin/v1/x", // hyphen is legal
	)
	got := ExtractRESTRoutePlugins(body)
	want := []string{"blog-name", "dash-plugin", "under_score"}
	if len(got) != len(want) {
		t.Fatalf("ExtractRESTRoutePlugins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("slugs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractRESTRoutePluginsCap verifies the 50-entry cap: a route index
// advertising 60 distinct plugin namespaces yields exactly 50 slugs.
func TestExtractRESTRoutePluginsCap(t *testing.T) {
	routes := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		routes = append(routes, fmt.Sprintf("plugin-%03d/v1/x", i))
	}
	got := ExtractRESTRoutePlugins(routeIndexJSON(routes...))
	if len(got) != maxRESTRoutePlugins {
		t.Fatalf("ExtractRESTRoutePlugins = %d slugs, want capped at %d", len(got), maxRESTRoutePlugins)
	}
	if got[0] != "plugin-000" || got[len(got)-1] != "plugin-049" {
		t.Errorf("cap survivors = %q..%q, want plugin-000..plugin-049", got[0], got[len(got)-1])
	}
}

// TestExtractRESTRoutePluginsNoCrash verifies the parser is inert on
// shapes that are not a route index: non-JSON, empty JSON, a routes map
// with no entries and null bodies all yield nil without panicking.
func TestExtractRESTRoutePluginsNoCrash(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`not json at all`),
		[]byte(`<html>maintenance page</html>`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`{"routes":null}`),
		[]byte(`{"routes":[]}`),
		[]byte(`[]`),
		[]byte(`{"routes":{"wp/v2/posts":{}}}`), // only core: no candidates
	} {
		if got := ExtractRESTRoutePlugins(body); len(got) != 0 {
			t.Errorf("ExtractRESTRoutePlugins(%q) = %v, want nil", body, got)
		}
	}
}

// restRouteServer serves a WordPress-like site whose homepage carries no
// plugin references: the only evidence of an installed plugin is the
// contact-form-7 namespace in the wp-json route index. The plugin readme
// answers 200 but carries no parseable version, so the versionless
// "rest-routes" detection must survive the enumeration pass.
func restRouteServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' type='text' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(routeIndexJSON("contact-form-7/v1/contact-forms", "wp/v2/posts"))
	})
	mux.HandleFunc("/wp-content/plugins/contact-form-7/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		// A real readme shape (so the response-authenticity gate passes)
		// but with no Stable tag / changelog heading and no composer.json
		// fallback: enumeration cannot pin a version.
		_, _ = w.Write([]byte(`=== Contact Form 7 ===
Contributors: takayukister
Tags: contact, form
License: GPLv3

Contact Form 7 can manage multiple contact forms.
`))
	})
	return httptest.NewServer(mux)
}

// TestScanRESTRoutePluginDetection verifies the integration flow: a plugin
// whose ONLY evidence is its wp-json route namespace is reported with
// Source "rest-routes" and confidence 85, while the core wp namespace is
// never reported.
func TestScanRESTRoutePluginDetection(t *testing.T) {
	srv := restRouteServer(t)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Detected) != 1 {
		t.Fatalf("Detected = %+v, want exactly contact-form-7", res.Detected)
	}
	d0 := res.Detected[0]
	if d0.Slug != "contact-form-7" || d0.Type != "plugin" {
		t.Errorf("Detected[0] = %+v, want slug contact-form-7 / type plugin", d0)
	}
	if d0.Source != "rest-routes" || d0.Confidence != confRestRoutes {
		t.Errorf("Detected[0] source/confidence = %q/%d, want rest-routes/%d", d0.Source, d0.Confidence, confRestRoutes)
	}
	if d0.Version != "unknown" {
		t.Errorf("Detected[0] version = %q, want unknown (readme carries no version)", d0.Version)
	}
}

// TestScanRESTRoutePluginGatedByEnumerate verifies the plugin enumerate
// token gates the rest-route materialization: with "t" only, the route
// namespace is ignored.
func TestScanRESTRoutePluginGatedByEnumerate(t *testing.T) {
	srv := restRouteServer(t)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "t"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, det := range res.Detected {
		if det.Slug == "contact-form-7" {
			t.Errorf("contact-form-7 detected without the plugin enumerate token: %+v", det)
		}
	}
}

// TestScanRESTRoutePluginVersionedMerge verifies that a rest-route slug
// carrying a passive ?ver= asset version materializes with the version
// AND the stronger "rest-routes" source/confidence, not the generic
// "passive-ver" label.
func TestScanRESTRoutePluginVersionedMerge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.8"></script></body></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(routeIndexJSON("contact-form-7/v1/contact-forms"))
	})
	mux.HandleFunc("/wp-content/plugins/contact-form-7/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Contact Form 7 ===
Contributors: takayukister
Tags: contact, form
License: GPLv3

Contact Form 7 can manage multiple contact forms.
`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var got *Detected
	for i := range res.Detected {
		if res.Detected[i].Slug == "contact-form-7" {
			got = &res.Detected[i]
		}
	}
	if got == nil {
		t.Fatalf("Detected = %+v, want contact-form-7", res.Detected)
	}
	if got.Version != "5.9.8" {
		t.Errorf("version = %q, want 5.9.8 (?ver= merge)", got.Version)
	}
	if got.Source != "rest-routes" || got.Confidence != confRestRoutes {
		t.Errorf("source/confidence = %q/%d, want rest-routes/%d", got.Source, got.Confidence, confRestRoutes)
	}
}
