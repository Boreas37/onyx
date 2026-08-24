package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// targetRedirectServer 301s the homepage to other so the scanner has to
// reach a second host, and 404s everything else.
func targetRedirectServer(other string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", other+"/")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
}

// wpPage is a minimal WordPress-looking homepage.
const wpPage = `<!DOCTYPE html>
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body><link rel="https://api.w.org/" href="/wp-json/" /></body></html>`

// TestProxyTargetOnlySocks5 verifies --proxy-target-only with a SOCKS5
// proxy: requests to the scanned target host go through the proxy, while
// traffic to any other host (the redirect target) is dialed directly — the
// proxy log never sees the other host.
func TestProxyTargetOnlySocks5(t *testing.T) {
	var otherHits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wpPage))
	}))
	defer other.Close()
	target := targetRedirectServer(other.URL)
	defer target.Close()

	proxyAddr, plog := fakeSocks5Proxy(t, false, "", "")
	d, _ := db.Load(minimalFeed(t))
	// The homepage redirect crosses to a second host, so the SSRF redirect
	// guard must be opted out of for this proxy-routing test.
	sc, err := NewScanner(d, target.URL, Options{Proxy: "socks5://" + proxyAddr, ProxyTargetOnly: true, Enumerate: "p", AllowForeignRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection (homepage reached via redirect)")
	}

	wantHost := target.Listener.Addr().String()
	conns := plog.snapshot()
	if len(conns) == 0 {
		t.Fatal("no CONNECT requests reached the SOCKS5 proxy")
	}
	for i, c := range conns {
		if c.target != wantHost {
			t.Errorf("CONNECT[%d] target = %q, want only the scanned host %q", i, c.target, wantHost)
		}
	}
	if otherHits.Load() == 0 {
		t.Error("the other host was never reached directly")
	}
}

// TestProxyTargetOnlyHTTP verifies the same routing for an HTTP proxy:
// absolute-URI requests only arrive at the proxy for the scanned target
// host; the redirect target is fetched directly.
func TestProxyTargetOnlyHTTP(t *testing.T) {
	var otherHits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wpPage))
	}))
	defer other.Close()
	target := targetRedirectServer(other.URL)
	defer target.Close()

	var mu sync.Mutex
	var proxiedHosts []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxiedHosts = append(proxiedHosts, r.Host)
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Location", other.URL+"/")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, target.URL, Options{Proxy: proxy.URL, ProxyTargetOnly: true, Enumerate: "p", AllowForeignRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(proxiedHosts) == 0 {
		t.Fatal("no requests reached the HTTP proxy")
	}
	wantHost := target.Listener.Addr().String()
	for i, h := range proxiedHosts {
		if h != wantHost {
			t.Errorf("proxied request[%d] host = %q, want only the scanned host %q", i, h, wantHost)
		}
	}
	if otherHits.Load() == 0 {
		t.Error("the other host was never reached directly")
	}
}

// TestProxyTargetOnlyDirectWithoutFlag makes sure the flag actually changes
// behavior: without it the socks5 proxy relays every host, including the
// redirect target.
func TestProxyTargetOnlyDirectWithoutFlag(t *testing.T) {
	var otherHits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wpPage))
	}))
	defer other.Close()
	target := targetRedirectServer(other.URL)
	defer target.Close()

	proxyAddr, plog := fakeSocks5Proxy(t, false, "", "")
	d, _ := db.Load(minimalFeed(t))
	// The redirect guard is opted out of here too: this test proves the
	// proxy relays the foreign redirect target, which only happens if the
	// redirect is followed in the first place.
	sc, err := NewScanner(d, target.URL, Options{Proxy: "socks5://" + proxyAddr, Enumerate: "p", AllowForeignRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	otherHost := other.Listener.Addr().String()
	found := false
	for _, c := range plog.snapshot() {
		if strings.HasPrefix(c.target, otherHost) {
			found = true
		}
	}
	if !found {
		t.Error("without --proxy-target-only the redirect target must also be proxied")
	}
}
