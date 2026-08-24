package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/db"
)

// flakyHandler panics with http.ErrAbortHandler (abruptly closing the
// connection with no response) for the first failUpTo requests, then serves
// 200 "ok". This produces a genuine transport error from client.Do on each
// failed attempt.
func flakyHandler(failUpTo int, hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= int32(failUpTo) {
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write([]byte("ok"))
	})
}

// TestFetchRetriesTransientErrorsThenSucceeds verifies a fetch whose first
// two attempts fail at the transport layer succeeds after MaxRetries retries
// with backoff: the request counter and the server both see 3 attempts.
func TestFetchRetriesTransientErrorsThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(flakyHandler(2, &hits))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	code, body, ferr := sc.fetch("/")
	if ferr != nil || code != http.StatusOK || string(body) != "ok" {
		t.Fatalf("fetch = (%d, %q, %v), want (200, ok, nil)", code, body, ferr)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (initial + 2 retries)", got)
	}
	if sc.requestCount() != 3 {
		t.Errorf("request counter = %d, want 3 (one per actual attempt)", sc.requestCount())
	}
	// Backoff floor for two retries: 200ms + 400ms (plus jitter).
	if elapsed := time.Since(start); elapsed < 550*time.Millisecond {
		t.Errorf("elapsed %v — exponential backoff not applied", elapsed)
	}
}

// TestFetchGivesUpAfterMaxRetries verifies a permanently failing server
// returns an error after MaxRetries retries, and never retries more.
func TestFetchGivesUpAfterMaxRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(flakyHandler(1<<30, &hits))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ferr := sc.fetch("/"); ferr == nil {
		t.Fatal("fetch must fail against a permanently failing server")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2 (initial + 1 retry)", got)
	}
}

// TestFetchRetriesDisabledByZero verifies MaxRetries=0 (the zero value, i.e.
// retries off) makes a failing fetch give up immediately.
func TestFetchRetriesDisabledByZero(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(flakyHandler(1<<30, &hits))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ferr := sc.fetch("/"); ferr == nil {
		t.Fatal("fetch must fail when retries are disabled")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retries)", got)
	}
}

// TestFetchNoRetryOnHTTPStatus verifies HTTP error statuses are NOT treated
// as retryable: a 500 is returned as-is without any retry.
func TestFetchNoRetryOnHTTPStatus(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	code, _, ferr := sc.fetch("/")
	if ferr != nil || code != http.StatusInternalServerError {
		t.Fatalf("fetch = (%d, %v), want (500, nil)", code, ferr)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (5xx is a valid answer, not a transport error)", got)
	}
}

// TestFetchNoRetryOnContextTimeout verifies a request that expires the
// scan-wide context is never retried: the deadline failure returns
// immediately and only one request reaches the server.
func TestFetchNoRetryOnContextTimeout(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	sc.ctx = ctx
	if _, _, ferr := sc.fetch("/"); ferr == nil {
		t.Fatal("fetch must fail once the context deadline expires")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (context deadline must not retry)", got)
	}
}
