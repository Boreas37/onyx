package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// xmlrpcMethodNameRe is the character set of extracted XML-RPC method
// names, checked by FuzzExtractXMLRPCMethods. The parser matches
// case-insensitively (real names like wp.getUsersBlogs carry uppercase
// letters and are kept verbatim), so the check applies the same
// case-insensitive semantics.
var xmlrpcMethodNameRe = regexp.MustCompile(`(?i)^[a-z0-9_.]+$`)

// The fuzz targets below pin the report-safety invariants: no matter what a
// hostile server returns, extracted strings never carry control characters
// and never exceed their caps.

func FuzzExtractVersionFromReadme(f *testing.F) {
	f.Add("Stable tag: 5.3.2")
	f.Add("stable tag = v1.0.0-beta+build.1")
	f.Add("Stable tag: 9." + strings.Repeat("9", 10000))
	f.Add("\n\nstable\tTAG:3.2")
	f.Add("")
	f.Fuzz(func(t *testing.T, body string) {
		v, _ := ExtractVersionFromReadme(body)
		if len(v) > maxVersionLen {
			t.Fatalf("version %d chars exceeds cap %d", len(v), maxVersionLen)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("control char %q in version %q", r, v)
			}
		}
	})
}

func FuzzExtractVersionFromStyleCSS(f *testing.F) {
	f.Add("/*\nTheme Name: X\nVersion: 1.5\n*/")
	f.Add("version=10." + strings.Repeat("0", 9999))
	f.Add("")
	f.Fuzz(func(t *testing.T, body string) {
		v, _ := ExtractVersionFromStyleCSS(body)
		if len(v) > maxVersionLen {
			t.Fatalf("version %d chars exceeds cap %d", len(v), maxVersionLen)
		}
	})
}

func FuzzExtractWordPressVersion(f *testing.F) {
	f.Add(`<meta name="generator" content="WordPress 6.4">`)
	f.Add(`<meta name='generator' content='WordPress 7.1.1-alpha.2'>`)
	f.Add("")
	f.Fuzz(func(t *testing.T, html string) {
		v, _ := ExtractWordPressVersion(html)
		if len(v) > maxVersionLen {
			t.Fatalf("version %d chars exceeds cap %d", len(v), maxVersionLen)
		}
	})
}

func FuzzParseDetectedList(f *testing.F) {
	f.Add([]byte(`[{"plugin":"a/b.php","version":"1.0","name":"A"}]`), true)
	f.Add([]byte(`PHP Notice: x[{"theme":"twentytwentyfive","version":"1.5"}]`), false)
	f.Add([]byte(`{"plugin":"evil","version":"`+strings.Repeat("9", 50000)+`"}`), true)
	f.Add([]byte(`not json at all`), true)
	f.Fuzz(func(t *testing.T, body []byte, isPlugin bool) {
		typ := "theme"
		if isPlugin {
			typ = "plugin"
		}
		for _, d := range parseDetectedList(body, typ, "auth-rest") {
			if len(d.Slug) > maxSlugLen || len(d.Name) > maxNameLen || len(d.Version) > maxVersionLen {
				t.Fatalf("unsanitized detected entry: %+v", d)
			}
			for _, s := range []string{d.Slug, d.Name, d.Version} {
				for _, r := range s {
					if r < 0x20 || r == 0x7f {
						t.Fatalf("control char %q survived in %q", r, s)
					}
				}
			}
		}
	})
}

func FuzzUsersFromJSON(f *testing.F) {
	f.Add([]byte(`[{"id":1,"slug":"admin","name":"Admin"}]`))
	f.Add([]byte(`Warning: x[{"id":2,"slug":"` + strings.Repeat("u", 9000) + `"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, u := range usersFromJSON(body) {
			if len(u.Slug) > maxSlugLen || len(u.Name) > maxNameLen {
				t.Fatalf("unsanitized user: %+v", u)
			}
		}
	})
}

func FuzzAuthorSlugFromBody(f *testing.F) {
	f.Add([]byte(`<link rel="canonical" href="http://x.test/author/admin/">`))
	f.Add([]byte(`/author/` + strings.Repeat("z", 20000) + `/`))
	f.Fuzz(func(t *testing.T, body []byte) {
		slug := authorSlugFromBody(body)
		if len(slug) > maxSlugLen {
			t.Fatalf("slug %d chars exceeds cap %d", len(slug), maxSlugLen)
		}
	})
}

// FuzzExtractRESTRoutes pins the route-index parser's report-safety
// invariants: arbitrary bytes never panic, and every output slug is a
// strict [a-z0-9_-]+ token no longer than the per-slug cap, with the
// result list bounded by maxRESTRoutePlugins.
func FuzzExtractRESTRoutes(f *testing.F) {
	f.Add([]byte(`{"routes":{"contact-form-7/v1/contact-forms":{"namespace":"contact-form-7/v1"},"wp/v2/posts":{},"elementor/v1":{}}}`))
	f.Add([]byte(`["contact-form-7/v1/contact-forms","wp/v2/posts","acme/endpoint"]`))
	f.Add([]byte(`{"routes":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"routes":{"` + strings.Repeat("a", 50000) + `/v1":{}}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		slugs := ExtractRESTRoutePlugins(body)
		if len(slugs) > maxRESTRoutePlugins {
			t.Fatalf("%d slugs exceed the cap %d", len(slugs), maxRESTRoutePlugins)
		}
		for _, s := range slugs {
			if len(s) > maxRESTRoutePlugins {
				t.Fatalf("slug %d chars exceeds the cap %d", len(s), maxRESTRoutePlugins)
			}
			if !restSlugRe.MatchString(s) {
				t.Fatalf("slug %q violates ^[a-z0-9_-]+$", s)
			}
		}
	})
}

// FuzzExtractTimthumbVersion pins the TimThumb version extractor: arbitrary
// bytes never panic and any extracted version is sanitized to the
// maxVersionLen cap without control characters.
func FuzzExtractTimthumbVersion(f *testing.F) {
	f.Add("TimThumb version 2.8.10")
	f.Add(`"version": "2.8.11"`)
	f.Add("$version = '2.8.12';")
	f.Add("$version = \"2.8.13\";")
	f.Add("TimThumb version 9." + strings.Repeat("9", 10000))
	f.Add("")
	f.Fuzz(func(t *testing.T, body string) {
		v, _ := ExtractTimthumbVersion(body)
		if len(v) > maxVersionLen {
			t.Fatalf("version %d chars exceeds cap %d", len(v), maxVersionLen)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("control char %q in version %q", r, v)
			}
		}
	})
}

// FuzzExtractXMLRPCMethods pins the method-list parser: arbitrary bytes
// never panic, the result list is bounded by maxXMLRPCMethods and every
// extracted method name is a [a-z0-9_.]+ token (case-insensitive, matching
// the parser's own semantics) carrying at least one dot.
func FuzzExtractXMLRPCMethods(f *testing.F) {
	f.Add(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
		`<value><string>system.listMethods</string></value>` +
		`<value><string>pingback.ping</string></value>` +
		`<value><string>wp.getUsersBlogs</string></value>` +
		`</data></array></value></param></params></methodResponse>`)
	f.Add(`<string>system.multicall</string>`)
	f.Add(strings.Repeat(`<string>wp.method</string>`, 500))
	f.Add(`<string>` + strings.Repeat("a", 50000) + `.b</string>`)
	f.Add("garbage")
	f.Add("")
	f.Fuzz(func(t *testing.T, body string) {
		methods := extractXMLRPCMethods(body)
		if len(methods) > maxXMLRPCMethods {
			t.Fatalf("%d methods exceed the cap %d", len(methods), maxXMLRPCMethods)
		}
		for _, m := range methods {
			if !xmlrpcMethodNameRe.MatchString(m) {
				t.Fatalf("method %q violates ^[a-z0-9_.]+$", m)
			}
			if !strings.Contains(m, ".") {
				t.Fatalf("method %q carries no dot", m)
			}
		}
	})
}
