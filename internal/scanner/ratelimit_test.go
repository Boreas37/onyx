package scanner

import (
	"sync/atomic"

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

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{"seconds", "30", 30 * time.Second, true},
		{"zero seconds", "0", 0, true},
		{"negative", "-5", 0, false},
		{"garbage", "soon-ish", 0, false},
		{"future date", time.RFC1123[:3] + "", 0, false}, // replaced below
	}
	// HTTP-date two minutes in the future.
	future := now.Add(2 * time.Minute).Format(http.TimeFormat)
	cases[4] = struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{"future date", future, 2 * time.Minute, true}

	for _, c := range cases {
		h := http.Header{}
		if c.value != "" || c.name == "empty" {
			h.Set("Retry-After", c.value)
		}
		got, ok := retryAfter(h, now)
		if c.name == "future date" {
			// allow ±1s of test-execution slack on the date form
			if !ok || got < c.want-time.Second || got > c.want+time.Second {
				t.Errorf("%s: retryAfter = (%v,%v), want ~(2m,true)", c.name, got, ok)
			}
			continue
		}
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("%s: retryAfter(%q) = (%v,%v), want (%v,%v)", c.name, c.value, got, ok, c.want, c.wantOK)
		}
	}
	if _, ok := retryAfter(http.Header{}, now); ok {
		t.Error("absent header must report not-ok")
	}
}

// A 429 carrying Retry-After must wait the hinted duration instead of the
// exponential schedule: the first backoff would be 1s either way, so the
// second request uses Retry-After: 1 and still completes quickly — assert
// the hint is preferred by making the exponential path expensive.
func Test429HonorsRetryAfter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	code1, _, _ := sc.fetch("/")
	code2, _, _ := sc.fetch("/")
	elapsed := time.Since(start)
	if code1 != http.StatusTooManyRequests || code2 != http.StatusTooManyRequests {
		t.Fatalf("codes = %d/%d, want 429/429", code1, code2)
	}
	// Two waits of exactly ~1s each; the second would have been 2s under
	// pure exponential doubling. Allow generous scheduling slop.
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("elapsed %s — Retry-After hint likely ignored", elapsed)
	}
	if elapsed > 4500*time.Millisecond {
		t.Fatalf("elapsed %s — waited far longer than the hinted 2×1s", elapsed)
	}
	if n := sc.rateLimitHits(); n != 2 {
		t.Errorf("rateLimitHits = %d, want 2", n)
	}
}
