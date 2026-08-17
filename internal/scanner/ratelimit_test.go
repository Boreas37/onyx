package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/db"
)

// TestPerHostRateLimitSeparateLimiters verifies --per-host-rate-limit keeps
// one independent limiter per host (scheme://host:port): while host A is
// throttled, host B's fresh limiter passes immediately. A single shared
// limiter would have made host B wait.
func TestPerHostRateLimitSeparateLimiters(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvB.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srvA.URL, Options{PerHostRateLimit: 10}) // 100ms per host
	if err != nil {
		t.Fatal(err)
	}
	a := srvA.URL + "/"
	b := srvB.URL + "/"

	// Warm host A's limiter: the second wait must already be throttled.
	sc.perHostWait(a)
	sc.perHostWait(a)

	start := time.Now()
	sc.perHostWait(a)
	elapsedA := time.Since(start)
	if elapsedA < 75*time.Millisecond {
		t.Errorf("host A waited %v, want >= 75ms (10 req/s per host)", elapsedA)
	}

	start = time.Now()
	sc.perHostWait(b)
	elapsedB := time.Since(start)
	if elapsedB > 40*time.Millisecond {
		t.Errorf("host B waited %v, want ~0ms (its own fresh limiter, not host A's)", elapsedB)
	}
}

// TestPerHostRateLimitThrottlesFetch verifies per-host pacing applies to
// real scan requests, both alone and combined with the global --rate-limit
// (with both flags the effective pace is at least the slower limiter).
func TestPerHostRateLimitThrottlesFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()

	cases := []struct {
		name      string
		rateLimit float64
		perHost   float64
		wantMinEl time.Duration
	}{
		{"global only", 10, 0, 150 * time.Millisecond},
		{"per-host only", 0, 10, 150 * time.Millisecond},
		{"both", 10, 10, 150 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := db.Load(minimalFeed(t))
			sc, err := NewScanner(d, srv.URL, Options{RateLimit: c.rateLimit, PerHostRateLimit: c.perHost})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for i := 0; i < 3; i++ {
				if _, _, err := sc.fetch("/"); err != nil {
					t.Fatalf("fetch %d: %v", i, err)
				}
			}
			if elapsed := time.Since(start); elapsed < c.wantMinEl {
				t.Errorf("3 fetches took %v, want >= %v (10 req/s limiter active)", elapsed, c.wantMinEl)
			}
		})
	}
}

// TestPerHostRateLimitKeyedBySchemeHostPort verifies the limiter map keys
// follow the scheme://host:port shape from the spec and distinct hosts get
// distinct entries.
func TestPerHostRateLimitKeyedBySchemeHostPort(t *testing.T) {
	if got := perHostKey("http://example.com/readme.txt"); got != "http://example.com" {
		t.Errorf("perHostKey = %q, want http://example.com", got)
	}
	if got := perHostKey("https://example.com:8443/x"); got != "https://example.com:8443" {
		t.Errorf("perHostKey = %q, want https://example.com:8443", got)
	}

	d, _ := db.Load(minimalFeed(t))
	sc, _ := NewScanner(d, "http://example.test", Options{PerHostRateLimit: 5})
	if sc.perHostLim == nil {
		t.Fatal("per-host limiter map not initialized")
	}
	sc.perHostWait("http://example.com/")
	sc.perHostWait("https://example.com/")
	if len(sc.perHostLim) != 2 {
		t.Errorf("perHostLim has %d entries, want 2 distinct hosts", len(sc.perHostLim))
	}

	// Without the flag no limiters exist at all.
	sc, _ = NewScanner(d, "http://example.test", Options{})
	if sc.perHostLim != nil {
		t.Error("per-host limiter map must stay nil when --per-host-rate-limit is off")
	}
}
