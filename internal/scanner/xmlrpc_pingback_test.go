package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// pingbackServer serves a WordPress-ish site whose xmlrpc.php answers
// system.listMethods with the given status and body, so tests can control
// whether pingback.ping appears in the method list.
func pingbackServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	})
	return httptest.NewServer(mux)
}

const methodsWithPingback = `<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
	`<value><string>system.listMethods</string></value>` +
	`<value><string>pingback.ping</string></value>` +
	`<value><string>wp.getUsersBlogs</string></value>` +
	`</data></array></value></param></params></methodResponse>`

const methodsWithoutPingback = `<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
	`<value><string>system.listMethods</string></value>` +
	`<value><string>wp.getUsersBlogs</string></value>` +
	`</data></array></value></param></params></methodResponse>`

// TestCheckXMLRPCReturnsPingback drives the new checkXMLRPC signature
// directly: enabled reflects a methodResponse payload and pingback reflects
// whether pingback.ping appears in the method list.
func TestCheckXMLRPCReturnsPingback(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	t.Run("pingback exposed", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK, methodsWithPingback)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		enabled, pingback := sc.checkXMLRPC()
		if !enabled {
			t.Error("enabled = false, want true for a responding xmlrpc.php")
		}
		if !pingback {
			t.Error("pingback = false, want true when pingback.ping is listed")
		}
	})

	t.Run("no pingback method", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK, methodsWithoutPingback)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		enabled, pingback := sc.checkXMLRPC()
		if !enabled {
			t.Error("enabled = false, want true")
		}
		if pingback {
			t.Error("pingback = true, want false when pingback.ping is absent")
		}
	})

	t.Run("unavailable endpoint", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusNotFound, "")
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		enabled, pingback := sc.checkXMLRPC()
		if enabled || pingback {
			t.Errorf("404 must report enabled=%v pingback=%v, want false,false", enabled, pingback)
		}
	})
}

// TestScanXMLRPCPingbackResult verifies the pingback flag and the static
// Interesting entry surface through a full Scan when pingback.ping is
// exposed.
func TestScanXMLRPCPingbackResult(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	t.Run("pingback exposed in scan", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK, methodsWithPingback)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		res, err := sc.Scan()
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !res.XMLRPC {
			t.Fatal("XMLRPC = false, want true")
		}
		if !res.XMLRPCPingback {
			t.Error("XMLRPCPingback = false, want true")
		}
		found := false
		for _, i := range res.Interesting {
			if strings.Contains(i, "XML-RPC pingback enabled") {
				found = true
			}
		}
		if !found {
			t.Errorf("Interesting does not mention pingback: %+v", res.Interesting)
		}
	})

	t.Run("no pingback in scan", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK, methodsWithoutPingback)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		res, err := sc.Scan()
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !res.XMLRPC {
			t.Fatal("XMLRPC = false, want true")
		}
		if res.XMLRPCPingback {
			t.Error("XMLRPCPingback = true, want false")
		}
	})

	t.Run("404 in scan", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusNotFound, "")
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		res, err := sc.Scan()
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if res.XMLRPC || res.XMLRPCPingback {
			t.Errorf("404 must leave XMLRPC=%v XMLRPCPingback=%v, want false,false", res.XMLRPC, res.XMLRPCPingback)
		}
	})
}
