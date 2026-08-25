package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// authorSitemapServer serves a WordPress-ish site whose user sitemap lists
// the given author slugs (plus a post URL and a foreign-host decoy that
// must both be ignored). The REST user listing and every single-user probe
// answer lockedStatus, and /?author=N redirects to /author/admin/ so tests
// can prove the redirect probing did or did not run. Counters: sitemap hits
// and ?author=N hits.
func authorSitemapServer(t *testing.T, authors []string, lockedStatus int) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var sitemapHits, authorHits atomic.Int64
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("author")
		switch {
		case r.URL.Path == "/wp-sitemap-users-1.xml":
			sitemapHits.Add(1)
			body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`
			for _, au := range authors {
				body += fmt.Sprintf("<url><loc>%s/author/%s/</loc></url>", base, au)
			}
			// Noise that must never become a user: a plain post URL and a
			// foreign-host author archive.
			body += fmt.Sprintf("<url><loc>%s/2024/06/hello-world/</loc></url>", base)
			body += "<url><loc>https://foreign.example/author/mallory/</loc></url>"
			body += "</urlset>"
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(body))
		case r.URL.Query().Get("rest_route") == "/wp/v2/users":
			w.WriteHeader(lockedStatus)
			_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view","message":"nope"}`))
		case r.URL.Path == "/wp-json/wp/v2/users":
			w.WriteHeader(lockedStatus)
			_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view","message":"nope"}`))
		case a != "":
			authorHits.Add(1)
			w.Header().Set("Location", base+"/author/admin/")
			w.WriteHeader(http.StatusMovedPermanently)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`))
		}
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv, &sitemapHits, &authorHits
}

// TestUsersFromAuthorSitemap verifies the sitemap parser turns /author/<slug>/
// locations into sanitized users, skipping non-author locations and foreign
// hosts, deduplicating and leaving IDs at 0 (unknown from this source).
func TestUsersFromAuthorSitemap(t *testing.T) {
	srv, _, _ := authorSitemapServer(t, []string{"jane", "bob"}, http.StatusForbidden)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users := sc.usersFromAuthorSitemap()
	if len(users) != 2 {
		t.Fatalf("users = %+v, want jane + bob", users)
	}
	if users[0].Slug != "jane" || users[1].Slug != "bob" {
		t.Errorf("users = %+v, want [jane bob] in document order", users)
	}
	for _, u := range users {
		if u.ID != 0 {
			t.Errorf("user %+v must carry ID 0 from the sitemap source", u)
		}
	}
}

// TestScanSitemapUsersFoundAndAuthorProbingSkipped wires the sitemap
// discovery into a full scan with the REST listing AND single-user probes
// locked down: both authors come from the sitemap, exactly one sitemap
// request is spent, and the expensive ?author=N probing is skipped entirely.
func TestScanSitemapUsersFoundAndAuthorProbingSkipped(t *testing.T) {
	srv, sitemapHits, authorHits := authorSitemapServer(t, []string{"jane", "bob"}, http.StatusForbidden)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Users) != 2 {
		t.Fatalf("users = %+v, want jane + bob from the sitemap", res.Users)
	}
	if res.Users[0].Slug != "bob" || res.Users[1].Slug != "jane" {
		t.Errorf("users = %+v, want sorted [bob jane]", res.Users)
	}
	if n := sitemapHits.Load(); n != 1 {
		t.Errorf("sitemap fetched %d times, want exactly 1", n)
	}
	if n := authorHits.Load(); n != 0 {
		t.Errorf("?author=N probing ran %d times, want 0 (skipped when the sitemap yields users)", n)
	}
}

// TestScanSitemapMissingFallsThroughToAuthors verifies the soft-failure
// path: a 404 sitemap costs one silent request and leaves the classic
// ?author=N redirect probing fully intact.
func TestScanSitemapMissingFallsThroughToAuthors(t *testing.T) {
	var sitemapHits, authorHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("author")
		switch {
		case r.URL.Path == "/wp-sitemap-users-1.xml":
			sitemapHits.Add(1)
			http.NotFound(w, r)
		case r.URL.Query().Get("rest_route") == "/wp/v2/users":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view"}`))
		case r.URL.Path == "/wp-json/wp/v2/users":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view"}`))
		case a != "":
			n, _ := strconv.Atoi(a)
			authorHits.Add(1)
			if n == 1 {
				w.Header().Set("Location", "/author/admin/")
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			http.NotFound(w, r)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := sitemapHits.Load(); n != 1 {
		t.Errorf("sitemap probed %d times, want exactly 1", n)
	}
	if n := authorHits.Load(); n != maxAuthorChecks {
		t.Errorf("author checks = %d, want %d (probing unchanged on a missing sitemap)", n, maxAuthorChecks)
	}
	if len(res.Users) != 1 || res.Users[0].Slug != "admin" || res.Users[0].ID != 1 {
		t.Errorf("users = %+v, want admin/1 via ?author=N", res.Users)
	}
}

// TestScanSitemapSkippedWithAPIOnly verifies --api-only never spends the
// sitemap request (user enumeration is REST-only there).
func TestScanSitemapSkippedWithAPIOnly(t *testing.T) {
	srv, sitemapHits, authorHits := authorSitemapServer(t, []string{"jane"}, http.StatusForbidden)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "u", APIOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := sitemapHits.Load(); n != 0 {
		t.Errorf("sitemap fetched %d times with APIOnly, want 0", n)
	}
	if n := authorHits.Load(); n != 0 {
		t.Errorf("author probing ran %d times with APIOnly, want 0", n)
	}
}
