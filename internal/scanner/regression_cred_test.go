package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

func TestAuditCredsNotLeakedOnForeignRedirect(t *testing.T) {
	var gotAuth, gotCookie, gotCustom string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotCustom = r.Header.Get("X-Api-Key")
		w.WriteHeader(200)
	}))
	defer foreign.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, foreign.URL+"/x", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer target.Close()
	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, target.URL, Options{
		AllowForeignRedirect: true,
		BasicAuthUser:        "u",
		BasicAuthPass:        "p",
		Cookie:               "sess=abc",
		Headers:              map[string]string{"X-Api-Key": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ := sc.fetch("/redir-probe")
	_ = code
	// fetch() builds path via base+path; to force redirect we call fetch on "/" which redirects
	// Actually trigger via fetch("/") to follow foreign
	// Re-run explicitly:
	_, _, _ = sc.fetch("/")
	if gotAuth != "" {
		t.Errorf("Authorization leaked to foreign host: %q", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("Cookie leaked to foreign host: %q", gotCookie)
	}
	if gotCustom != "" {
		t.Errorf("custom header leaked to foreign host: %q", gotCustom)
	}
}
