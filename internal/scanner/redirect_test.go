package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestFetchBlocksForeignRedirectByDefault verifies the SSRF hardening: a
// redirect whose target host:port differs from the scanned authority is
// rejected by default and surfaces as a fetch error.
func TestFetchBlocksForeignRedirectByDefault(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("other host"))
	}))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, _, ferr := sc.fetch("/")
	if ferr == nil {
		t.Fatalf("fetch = (%d, nil), want an error for a foreign redirect", code)
	}
	if !strings.Contains(ferr.Error(), "redirect") {
		t.Errorf("error %q does not mention the redirect", ferr)
	}
}

// TestFetchFollowsForeignRedirectWhenAllowed verifies --allow-foreign-redirect
// opts the scanner into following cross-host redirects.
func TestFetchFollowsForeignRedirectWhenAllowed(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("other host"))
	}))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{AllowForeignRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	code, body, ferr := sc.fetch("/")
	if ferr != nil || code != http.StatusOK || string(body) != "other host" {
		t.Fatalf("fetch = (%d, %q, %v), want (200, other host, nil)", code, body, ferr)
	}
}

// TestFetchFollowsSameHostRedirectByDefault verifies redirects that stay on
// the scanned target's authority still follow by default.
func TestFetchFollowsSameHostRedirectByDefault(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("same host"))
	}))
	defer target.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, body, ferr := sc.fetch("/a")
	if ferr != nil || code != http.StatusOK || string(body) != "same host" {
		t.Fatalf("fetch = (%d, %q, %v), want (200, same host, nil)", code, body, ferr)
	}
}

// TestScanHomepageForeignRedirectAborts verifies the hardening reaches real
// scans: a homepage that redirects to a foreign host makes detectWP fail
// and Scan report a hard error instead of silently following.
func TestScanHomepageForeignRedirectAborts(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not wordpress"))
	}))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err == nil {
		t.Fatal("Scan must fail when the homepage redirects to a foreign host")
	}
}

// TestFetchRedirectLoopStopsAfterTenHops verifies the hop limit: a redirect
// chain that never lands (same-host loop) is cut off instead of looping
// forever, and the error surfaces from fetch.
func TestFetchRedirectLoopStopsAfterTenHops(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ferr := sc.fetch("/loop"); ferr == nil {
		t.Fatal("a redirect loop must terminate with an error after 10 hops")
	}
}
