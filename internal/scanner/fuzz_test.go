package scanner

import (
	"strings"
	"testing"
)

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
		for _, d := range parseDetectedList(body, typ) {
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
