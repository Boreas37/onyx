package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// loginOracleServer returns a wp-login.php handler whose #login_error body
// is chosen per submitted username from the exists map. Usernames not in
// the map get the "invalid username" message; when the map is nil every
// probe answers with a login page that carries no login_error element (the
// protection-plugin variant).
func loginOracleServer(exists map[string]bool) (*httptest.Server, *atomic.Int64) {
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = r.ParseForm()
		log := r.PostForm.Get("log")
		if exists == nil {
			// Protection plugin / disabled login: no #login_error element.
			_, _ = w.Write([]byte(`<div id="loginform">User Login</div>`))
			return
		}
		if exists[log] {
			_, _ = w.Write([]byte(`<div id="login_error">ERROR: The password you entered for the username <strong>` + log + `</strong> is incorrect.</div>`))
			return
		}
		_, _ = w.Write([]byte(`<div id="login_error">ERROR: Invalid username. Check again or try your email address.</div>`))
	})
	return httptest.NewServer(mux), &hits
}

// TestLoginOracleUsernameExists confirms an account whose login_error says
// "the password you entered for the username" is reported as existing, and
// probing continues past a missing account.
func TestLoginOracleUsernameExists(t *testing.T) {
	srv, hits := loginOracleServer(map[string]bool{"admin": true})
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{RateLimit: 1000})
	found := sc.loginOracleUsernames([]string{"ghost", "admin", "editor"})
	if len(found) != 1 || found[0] != "admin" {
		t.Fatalf("found = %+v, want [admin]", found)
	}
	if hits.Load() != 3 {
		t.Errorf("probes = %d, want 3 (ghost invalid, admin exists, editor invalid)", hits.Load())
	}
}

// TestLoginOracleInvalidUsername continues past missing accounts and finds
// nothing when every candidate is unknown.
func TestLoginOracleInvalidUsername(t *testing.T) {
	srv, hits := loginOracleServer(map[string]bool{})
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{RateLimit: 1000})
	found := sc.loginOracleUsernames([]string{"ghost", "nobody"})
	if len(found) != 0 {
		t.Fatalf("found = %+v, want none", found)
	}
	if hits.Load() != 2 {
		t.Errorf("probes = %d, want 2", hits.Load())
	}
}

// TestLoginOracleStopsOnProtectionPlugin verifies the protection-plugin
// variant: an empty/absent #login_error aborts probing entirely, returning
// whatever was already found (here nothing) and only spending one request.
func TestLoginOracleStopsOnProtectionPlugin(t *testing.T) {
	srv, hits := loginOracleServer(nil)
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{RateLimit: 1000})
	found := sc.loginOracleUsernames([]string{"admin", "administrator"})
	if len(found) != 0 {
		t.Fatalf("found = %+v, want none", found)
	}
	if hits.Load() != 1 {
		t.Errorf("probes = %d, want 1 (probing must stop on the first masked response)", hits.Load())
	}
}

// TestLoginOracleStopsAfterFoundMasked verifies that accounts confirmed
// BEFORE a masked response are returned, and probing stops at the mask.
func TestLoginOracleStopsAfterFoundMasked(t *testing.T) {
	var mu sync.Mutex
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		n := hits
		mu.Unlock()
		_ = r.ParseForm()
		switch n {
		case 1: // admin confirmed first
			_, _ = w.Write([]byte(`<div id="login_error">ERROR: The password you entered for the username <strong>admin</strong> is incorrect.</div>`))
		case 2: // then the login page goes quiet (protection plugin)
			_, _ = w.Write([]byte(`<div id="loginform">User Login</div>`))
		default:
			_, _ = w.Write([]byte(`<div id="login_error">ERROR: Invalid username.</div>`))
		}
	}))
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{RateLimit: 1000})
	found := sc.loginOracleUsernames([]string{"admin", "administrator", "editor"})
	if len(found) != 1 || found[0] != "admin" {
		t.Fatalf("found = %+v, want [admin] (confirmed before the mask)", found)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Errorf("probes = %d, want 2 (mask stops probing on the second probe)", hits)
	}
}

// TestLoginOracleFormShape verifies each oracle probe carries the expected
// form fields and the wp-login cookie header.
func TestLoginOracleFormShape(t *testing.T) {
	var mu sync.Mutex
	var gotLog, gotPwd, gotSubmit, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		mu.Lock()
		gotLog, gotPwd, gotSubmit = r.PostForm.Get("log"), r.PostForm.Get("pwd"), r.PostForm.Get("wp-submit")
		gotCookie = r.Header.Get("Cookie")
		mu.Unlock()
		_, _ = w.Write([]byte(`<div id="login_error">ERROR: Invalid username.</div>`))
	}))
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{RateLimit: 1000})
	sc.loginOracleUsernames([]string{"admin"})

	mu.Lock()
	defer mu.Unlock()
	if gotLog != "admin" || gotSubmit != "Log In" || gotPwd == "" || gotPwd == gotLog {
		t.Errorf("form = log:%q pwd:%q submit:%q, want admin / non-empty random / Log In", gotLog, gotPwd, gotSubmit)
	}
	if !strings.Contains(gotCookie, "wordpress_test_cookie=WP Cookie check") {
		t.Errorf("Cookie = %q, want wordpress_test_cookie=WP Cookie check", gotCookie)
	}
}

// oracleScanServer is a full WordPress-ish site whose REST and author
// enumeration find no users but whose wp-login.php confirms "admin" through
// the oracle.
func oracleScanServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("log") == "admin" {
			_, _ = w.Write([]byte(`<div id="login_error">ERROR: The password you entered for the username <strong>admin</strong> is incorrect.</div>`))
			return
		}
		_, _ = w.Write([]byte(`<div id="login_error">ERROR: Invalid username.</div>`))
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"rest_user_cannot_view"}`))
	})
	return httptest.NewServer(mux)
}

// TestScanLoginOracleWiresIntoUserEnumeration verifies the oracle runs when
// REST and author enumeration find nothing (and brute force is enabled),
// confirming the default admin account into res.Users.
func TestScanLoginOracleWiresIntoUserEnumeration(t *testing.T) {
	srv := oracleScanServer()
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{Enumerate: "u"})
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Users) != 1 || res.Users[0].Slug != "admin" {
		t.Fatalf("users = %+v, want [admin] via login oracle", res.Users)
	}
}

// TestScanLoginOracleRespectsNoBrute verifies --no-brute disables the
// oracle: with no REST/author users found, res.Users stays empty.
func TestScanLoginOracleRespectsNoBrute(t *testing.T) {
	srv := oracleScanServer()
	defer srv.Close()

	sc := exploitScanner(t, srv, Options{Enumerate: "u", NoBrute: true})
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Users) != 0 {
		t.Fatalf("users = %+v, want none with --no-brute", res.Users)
	}
}
