package scanner

import (
	"sync"
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

// With the global-cooldown retry design, a single fetch call transparently
// waits out 429 cooldowns and retries itself. This test proves the happy
// path: two rate-limited responses followed by success produce one 200,
// three upstream hits and roughly the hinted waits in between.
func Test429RetriesThenSucceeds(t *testing.T) {
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
	code, body, ferr := sc.fetch("/")
	elapsed := time.Since(start)
	if code != http.StatusOK || ferr != nil || len(body) == 0 && false {
		t.Fatalf("fetch = (%d, %v), want (200, nil)", code, ferr)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("upstream hits = %d, want 3 (initial + 2 retries)", got)
	}
	// Cooldowns of ~1s + ~1s (hinted) between attempts.
	if elapsed < 1800*time.Millisecond {
		t.Errorf("elapsed %s — cooldowns not honored", elapsed)
	}
	if n := sc.rateLimitHits(); n != 2 {
		t.Errorf("rateLimitHits = %d, want 2", n)
	}
}

// When every attempt is throttled the job eventually gives up — but only
// after its retry budget, and each attempt respects the growing cooldown.
func Test429GivesUpAfterRetryBudget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, _ := NewScanner(d, srv.URL, Options{Threads: 1})
	start := time.Now()
	code, _, _ := sc.fetch("/")
	elapsed := time.Since(start)
	if code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", code)
	}
	if got := hits.Load(); got != fetchRetriesOn429+1 {
		t.Errorf("upstream hits = %d, want %d", got, fetchRetriesOn429+1)
	}
	// Backoff schedule without hints: 1s + 2s between the three attempts.
	if elapsed < 2500*time.Millisecond {
		t.Errorf("elapsed %s — exponential backoff not applied", elapsed)
	}
}

// The core regression from real-world use: after one worker's request gets
// rate limited, OTHER workers' requests must wait out the global cooldown
// instead of piling onto the throttled server.
func Test429GlobalCooldownSerializesWorkers(t *testing.T) {
	var mu sync.Mutex
	arrivals := map[string]time.Time{}
	testStart := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals[r.URL.Path] = time.Now()
		mu.Unlock()
		if r.URL.Path == "/a" {
			// Rate limit exactly the first probe; everything else is fine.
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, _ := NewScanner(d, srv.URL, Options{Threads: 4})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _, _ = sc.fetch("/a") }()
	time.Sleep(150 * time.Millisecond) // B starts mid-cooldown, after /a's 429
	go func() { defer wg.Done(); _, _, _ = sc.fetch("/b") }()
	wg.Wait()

	mu.Lock()
	bArrival := arrivals["/b"]
	mu.Unlock()
	if bArrival.IsZero() {
		t.Fatal("probe /b never reached the server")
	}
	if d := bArrival.Sub(testStart); d < 900*time.Millisecond {
		t.Errorf("probe /b arrived %dms in — it ignored the global cooldown", d.Milliseconds())
	}
}
