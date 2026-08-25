package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// deniedJSON is the stock REST rejection body reused across the fixtures.
const deniedJSON = `{"code":"rest_user_cannot_view","message":"nope"}`

// usersMux returns an empty mux for single-user fixtures: each test
// registers its own user-endpoint handlers plus a "/" catch-all delegating
// to homepageHandler.
func usersMux() *http.ServeMux {
	return http.NewServeMux()
}

// homepageHandler serves the WordPress-like page every fixture falls back
// to for non-user endpoints.
func homepageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`))
}

// TestUsersFromAPISingleUserFallback verifies the locked-listing fallback:
// with the users LIST rejected 403 on both spellings, a public /users/2
// account is still discovered through the single-user probes and the auth
// error notes are replaced by the found user. Probes for ids without a
// registration answer 404 and stay silent.
func TestUsersFromAPISingleUserFallback(t *testing.T) {
	var listHits, singleHits atomic.Int64
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		listHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(deniedJSON))
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		singleHits.Add(1)
		if r.URL.Path == "/wp-json/wp/v2/users/2" {
			_, _ = w.Write([]byte(`{"id":2,"name":"Admin","slug":"admin"}`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if rr := r.URL.Query().Get("rest_route"); strings.HasPrefix(rr, "/wp/v2/users") {
			if rr == "/wp/v2/users" {
				listHits.Add(1)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(deniedJSON))
				return
			}
			singleHits.Add(1)
			if strings.TrimPrefix(rr, "/wp/v2/users/") == "2" {
				_, _ = w.Write([]byte(`{"id":2,"name":"Admin","slug":"admin"}`))
				return
			}
			http.NotFound(w, r)
			return
		}
		homepageHandler(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(users) != 1 || users[0].Slug != "admin" || users[0].ID != 2 || users[0].Name != "Admin" {
		t.Fatalf("users = %+v, want the admin object from /users/2", users)
	}
	if len(errs) != 0 {
		t.Errorf("errors = %+v, want none once a user was found", errs)
	}
	if n := singleHits.Load(); n < 1 || n > maxSingleUserProbes*2 {
		t.Errorf("single-user probes = %d, want between 1 and %d (both spellings)", n, maxSingleUserProbes*2)
	}
}

// TestUsersFromAPISingleUserArrayShape verifies a single-user probe that
// answers with an ARRAY payload (some security plugins rewrite the route)
// parses too.
func TestUsersFromAPISingleUserArrayShape(t *testing.T) {
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(deniedJSON))
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":3,"name":"Editor","slug":"editor"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if rr := r.URL.Query().Get("rest_route"); strings.HasPrefix(rr, "/wp/v2/users/") {
			_, _ = w.Write([]byte(`[{"id":3,"name":"Editor","slug":"editor"}]`))
			return
		}
		homepageHandler(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(errs) != 0 {
		t.Errorf("errors = %+v, want none once a user was found", errs)
	}
	if len(users) < 1 || users[0].Slug != "editor" {
		t.Errorf("users = %+v, want editor from the array-shaped probe", users)
	}
}

// TestUsersFromAPIListSuccessSkipsSingles verifies a healthy listing means
// NO single-user probes are spent at all.
func TestUsersFromAPIListSuccessSkipsSingles(t *testing.T) {
	var singleHits atomic.Int64
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"name":"Administrator","slug":"admin"}]`))
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		singleHits.Add(1)
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(errs) != 0 || len(users) != 1 || users[0].Slug != "admin" {
		t.Fatalf("users = %+v errors = %+v, want admin via the plain listing", users, errs)
	}
	if n := singleHits.Load(); n != 0 {
		t.Errorf("single-user probed %d times despite a working listing, want 0", n)
	}
}

// TestUsersFromAPIAllLockedKeepsAuthError verifies the original behaviour
// survives when nothing is public: every single-user probe failing keeps
// the "requires authentication" errors naming both listing spellings.
func TestUsersFromAPIAllLockedKeepsAuthError(t *testing.T) {
	var singleHits atomic.Int64
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(deniedJSON))
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		singleHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(deniedJSON))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if rr := r.URL.Query().Get("rest_route"); strings.HasPrefix(rr, "/wp/v2/users/") {
			singleHits.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(deniedJSON))
			return
		}
		if r.URL.Query().Get("rest_route") == "/wp/v2/users" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(deniedJSON))
			return
		}
		homepageHandler(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(users) != 0 {
		t.Errorf("users = %+v, want none when everything is locked", users)
	}
	if len(errs) == 0 {
		t.Fatal("expected the requires-authentication errors to be preserved")
	}
	joined := strings.Join(errs, "; ")
	for _, want := range []string{"/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users", "requires authentication"} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors = %+v, want %q named", errs, want)
		}
	}
	if n := singleHits.Load(); n != maxSingleUserProbes {
		t.Errorf("single-user probes = %d, want exactly %d (the first rejected spelling wins)", n, maxSingleUserProbes)
	}
}

// TestUsersFromAPISingleUsesRestRouteSpelling verifies the single-user
// probes reuse the URL spelling that reached the locked listing: when only
// the ?rest_route= form answered 403 (the pretty form 404s), the probes go
// out under ?rest_route= too — and succeed there.
func TestUsersFromAPISingleUsesRestRouteSpelling(t *testing.T) {
	var prettySingleHits, restRouteSingleHits atomic.Int64
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // pretty spelling: no rewrites on this install
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		prettySingleHits.Add(1)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch rr := r.URL.Query().Get("rest_route"); {
		case rr == "/wp/v2/users":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(deniedJSON))
		case strings.HasPrefix(rr, "/wp/v2/users/"):
			restRouteSingleHits.Add(1)
			if strings.TrimPrefix(rr, "/wp/v2/users/") == "1" {
				_, _ = w.Write([]byte(`{"id":1,"name":"Admin","slug":"admin"}`))
				return
			}
			http.NotFound(w, r)
		default:
			homepageHandler(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, errs := sc.usersFromAPI()
	if len(users) != 1 || users[0].ID != 1 || users[0].Slug != "admin" {
		t.Fatalf("users = %+v, want admin via the rest_route single probe", users)
	}
	if len(errs) != 0 {
		t.Errorf("errors = %+v, want none once a user was found", errs)
	}
	if n := prettySingleHits.Load(); n != 0 {
		t.Errorf("pretty-form single probes = %d, want 0 (wrong spelling)", n)
	}
	if n := restRouteSingleHits.Load(); n != maxSingleUserProbes {
		t.Errorf("?rest_route= single probes = %d, want %d", n, maxSingleUserProbes)
	}
}

// TestUsersFromAPISingleProbesCappedAtFive verifies the probe budget: ids
// beyond maxSingleUserProbes are never requested even when every probe
// answers 200 with the same account.
func TestUsersFromAPISingleProbesCappedAtFive(t *testing.T) {
	var singleHits atomic.Int64
	mux := usersMux()
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(deniedJSON))
	})
	mux.HandleFunc("/wp-json/wp/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		singleHits.Add(1)
		_, _ = w.Write([]byte(`{"id":1,"slug":"admin"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := sc.usersFromAPI()
	if len(users) == 0 {
		t.Fatalf("users = %+v, want at least one", users)
	}
	if n := singleHits.Load(); n != maxSingleUserProbes {
		t.Errorf("single-user probes = %d, want capped at %d", n, maxSingleUserProbes)
	}
}

// TestUsersFromJSONSingleShapes unit-tests the shared single-user parser:
// array shape, object shape, slug-less payloads and garbage.
func TestUsersFromJSONSingleShapes(t *testing.T) {
	users, err := usersFromJSONSingle([]byte(`[{"id":1,"slug":"a"},{"id":2,"slug":"b","name":"B"}]`))
	if err != nil || len(users) != 2 || users[0].Slug != "a" || users[1].Name != "B" {
		t.Errorf("array shape: users = %+v err = %v, want two users", users, err)
	}

	users, err = usersFromJSONSingle([]byte(`{"id":7,"slug":"solo","name":"Solo"}`))
	if err != nil || len(users) != 1 || users[0].ID != 7 || users[0].Slug != "solo" {
		t.Errorf("object shape: users = %+v err = %v, want one user id 7", users, err)
	}

	users, err = usersFromJSONSingle([]byte(`{"id":8,"slug":""}`))
	if err != nil || len(users) != 0 {
		t.Errorf("object without slug: users = %+v err = %v, want empty but no error", users, err)
	}

	if _, err = usersFromJSONSingle([]byte("<html>not json</html>")); err == nil {
		t.Error("garbage must return an error")
	}
}
