package scanner

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/db"
)

// TestNextSpacingSchedule verifies the exact pacing schedule from the spec:
// 0 → 250ms → 500ms → 1s → 2s, then saturation exactly at maxAdaptiveSpacing.
func TestNextSpacingSchedule(t *testing.T) {
	want := []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		maxAdaptiveSpacing,
		maxAdaptiveSpacing,
	}
	cur := time.Duration(0)
	for i, w := range want {
		cur = nextSpacing(cur)
		if cur != w {
			t.Fatalf("step %d: nextSpacing = %v, want %v", i, cur, w)
		}
	}
}

// TestNextBackoffSchedule verifies the exact backoff schedule from the
// spec: 0 → 1s → 2s → 4s → 8s → 16s → 30s, then saturation exactly at
// maxBackoff.
func TestNextBackoffSchedule(t *testing.T) {
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, maxBackoff, maxBackoff,
	}
	cur := time.Duration(0)
	for i, w := range want {
		cur = nextBackoff(cur)
		if cur != w {
			t.Fatalf("step %d: nextBackoff = %v, want %v", i, cur, w)
		}
	}
}

// TestNextSpacingProperties runs a random walk over nextSpacing asserting
// the two structural invariants: strictly non-decreasing and never above
// the cap. Inputs are drawn from [0, maxAdaptiveSpacing], the only range
// the scanner itself ever feeds in (the cap clamps everything above).
func TestNextSpacingProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	for i := 0; i < 5000; i++ {
		cur := time.Duration(rng.IntN(int(maxAdaptiveSpacing/time.Millisecond))) * time.Millisecond
		next := nextSpacing(cur)
		if next < cur {
			t.Fatalf("nextSpacing(%v) = %v decreased", cur, next)
		}
		if next > maxAdaptiveSpacing {
			t.Fatalf("nextSpacing(%v) = %v exceeds cap %v", cur, next, maxAdaptiveSpacing)
		}
	}
}

// TestNextBackoffProperties runs a random walk over nextBackoff asserting
// the same two structural invariants against maxBackoff. Inputs are drawn
// from [0, maxBackoff], the only range the scanner itself ever feeds in.
func TestNextBackoffProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 5))
	for i := 0; i < 5000; i++ {
		cur := time.Duration(rng.IntN(int(maxBackoff/time.Millisecond))) * time.Millisecond
		next := nextBackoff(cur)
		if next < cur {
			t.Fatalf("nextBackoff(%v) = %v decreased", cur, next)
		}
		if next > maxBackoff {
			t.Fatalf("nextBackoff(%v) = %v exceeds cap %v", cur, next, maxBackoff)
		}
	}
}

// TestNextSpacingSaturatesAtCap verifies the saturation is exact and
// stable: after enough doublings the value is precisely maxAdaptiveSpacing
// and stays there.
func TestNextSpacingSaturatesAtCap(t *testing.T) {
	cur := time.Duration(0)
	for i := 0; i < 100; i++ {
		cur = nextSpacing(cur)
	}
	if cur != maxAdaptiveSpacing {
		t.Errorf("after 100 steps spacing = %v, want exact cap %v", cur, maxAdaptiveSpacing)
	}
	if cur = nextSpacing(cur); cur != maxAdaptiveSpacing {
		t.Errorf("spacing past the cap = %v, want %v", cur, maxAdaptiveSpacing)
	}
}

// TestShouldAbortBoundaries pins the heuristic's documented edges: total 0
// never aborts, hits below rateAbortMinHits never abort, and the percentage
// threshold cuts exactly at rateAbortPct.
func TestShouldAbortBoundaries(t *testing.T) {
	if shouldAbort(0, 0) {
		t.Error("shouldAbort(0,0) must be false (total 0)")
	}
	if shouldAbort(rateAbortMinHits-1, 100) {
		t.Errorf("shouldAbort(%d,100) must be false (below min hits)", rateAbortMinHits-1)
	}
	if shouldAbort(rateAbortMinHits, 100) {
		t.Errorf("shouldAbort(%d,100) must be false (%d%% < %d%%)", rateAbortMinHits, rateAbortMinHits, rateAbortPct)
	}
	// rateAbortMinHits*100/62 = 40.3 → 40, which is >= rateAbortPct.
	if !shouldAbort(rateAbortMinHits, 62) {
		t.Errorf("shouldAbort(%d,62) must be true (40%% >= %d%%)", rateAbortMinHits, rateAbortPct)
	}
	// rateAbortMinHits*100/63 = 39.7 → 39, which is < rateAbortPct.
	if shouldAbort(rateAbortMinHits, 63) {
		t.Errorf("shouldAbort(%d,63) must be false (39%% < %d%%)", rateAbortMinHits, rateAbortPct)
	}
}

// TestShouldAbortMonotone property-tests the heuristic over random
// hit/total pairs: more hits at the same total never flips a true result
// to false, and more total at the same hits never flips a false result to
// true.
func TestShouldAbortMonotone(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 99))
	for i := 0; i < 5000; i++ {
		hits := rng.IntN(120)
		total := rng.IntN(300) + 1
		if shouldAbort(hits, total) && !shouldAbort(hits+1, total) {
			t.Fatalf("shouldAbort(%d,%d)=true but shouldAbort(%d,%d)=false: more hits flipped it off",
				hits, total, hits+1, total)
		}
		if !shouldAbort(hits, total) && shouldAbort(hits, total+1) {
			t.Fatalf("shouldAbort(%d,%d)=false but shouldAbort(%d,%d)=true: more total flipped it on",
				hits, total, hits, total+1)
		}
	}
}

// probeSlugList writes a one-slug-per-line list file with n slugs so the
// enumeration has enough jobs for the abort heuristic to matter.
func probeSlugList(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probes.txt")
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "probe-%03d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rateLimitedMux serves a WordPress homepage, wp-login.php and wp-json/
// normally, and answers every OTHER path with 429 (Retry-After: 1) until
// allowFrom requests have gone out, after which it answers 200. It returns
// the mux plus a counter for the throttled window.
func rateLimitedMux(allowFrom int32) (*http.ServeMux, *atomic.Int32) {
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/wp-login.php", "/wp-json/":
			_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2"/></head><body>wp-content</body></html>`))
			return
		}
		if n.Add(1) <= allowFrom {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux, &n
}

// TestScanRateLimitedAbortHeuristic is the end-to-end heuristic test: a
// server that 429s the first 30 requests then answers 200. The scan must
// complete, the early-abort must fire (30 hits >= rateAbortMinHits at
// >= rateAbortPct of traffic), and the throttling counters must agree.
// Hits are bounded by the server: >= rateAbortMinHits (the heuristic
// cannot fire earlier) and <= 30 (the server stops throttling after 30).
func TestScanRateLimitedAbortHeuristic(t *testing.T) {
	mux, n := rateLimitedMux(30)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{
		Threads:     4,
		PluginsList: probeSlugList(t, 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("fixture must pass the IsWordPress gate")
	}
	if !res.RateLimitedAbort {
		t.Errorf("RateLimitedAbort = false, want true: 30 hits at 429 should trip the documented heuristic")
	}
	hits := res.RateLimitHits
	if hits < rateAbortMinHits || hits > 30 {
		t.Errorf("RateLimitHits = %d, want in [%d, 30] (heuristic floor, server cap)", hits, rateAbortMinHits)
	}
	if res.Summary == nil {
		t.Fatal("Summary missing")
	}
	if res.Summary.RateLimited != hits {
		t.Errorf("Summary.RateLimited = %d, want %d", res.Summary.RateLimited, hits)
	}
	if got := n.Load(); got < rateAbortMinHits {
		t.Errorf("server saw %d throttled requests, want >= %d", got, rateAbortMinHits)
	}
}

// TestScanRateLimitedAlwaysAborts verifies the second integration case: a
// server that 429s everything except the WordPress markers trips the abort
// heuristic and the scan finishes without deadlock. The heuristic needs
// rateAbortMinHits hits and every 429 gates the pool for at least a
// second, so the scan takes a few tens of seconds by design — the point is
// that it TERMINATES (no deadlock) with the abort flag set.
func TestScanRateLimitedAlwaysAborts(t *testing.T) {
	mux, _ := rateLimitedMux(1 << 30) // throttle forever
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{
		Threads:     4,
		PluginsList: probeSlugList(t, 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *Result, 1)
	errs := make(chan error, 1)
	go func() {
		res, err := sc.Scan()
		if err != nil {
			errs <- err
			return
		}
		done <- res
	}()
	select {
	case res := <-done:
		if !res.IsWordPress {
			t.Fatal("fixture must pass the IsWordPress gate")
		}
		if !res.RateLimitedAbort {
			t.Errorf("RateLimitedAbort = false, want true (target kept answering 429)")
		}
		if res.RateLimitHits < rateAbortMinHits {
			t.Errorf("RateLimitHits = %d, want >= %d", res.RateLimitHits, rateAbortMinHits)
		}
	case err := <-errs:
		t.Fatalf("Scan errored: %v", err)
	case <-time.After(150 * time.Second):
		t.Fatal("scan deadlocked: did not finish within 150s despite the abort heuristic")
	}
}
