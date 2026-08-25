package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// wpcronServer serves a WordPress-like homepage plus /wp-cron.php answering
// with the given status and body, so tests can pin down exactly which
// response shapes count as an externally triggerable WP-Cron.
func wpcronServer(cronStatus int, cronBody string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`))
	})
	mux.HandleFunc("/wp-cron.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(cronStatus)
		_, _ = w.Write([]byte(cronBody))
	})
	return httptest.NewServer(mux)
}

// scanInteresting scans the given server and returns res.Interesting.
func scanInteresting(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return res.Interesting
}

// hasInteresting reports whether want appears verbatim in list.
func hasInteresting(list []string, want string) bool {
	for _, it := range list {
		if it == want {
			return true
		}
	}
	return false
}

// TestWPCronEmptyAndTinyBodiesFlagged verifies the WPScan wp_cron parity:
// a 200 /wp-cron.php with an empty or tiny (< maxWPCronBodyLen bytes) body
// means external cron triggers are possible and must surface as an
// Interesting entry.
func TestWPCronEmptyAndTinyBodiesFlagged(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"tiny body", "<?php // silence\n"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			srv := wpcronServer(http.StatusOK, c.body)
			defer srv.Close()
			got := scanInteresting(t, srv)
			if !hasInteresting(got, "wp-cron.php reachable (external cron triggers possible)") {
				t.Errorf("Interesting = %+v, want the wp-cron entry", got)
			}
		})
	}
}

// TestWPCronLargeBodyNotFlagged verifies a 200 with a large body does NOT
// count: front-controller rewrite installs land missing-file probes on
// full pages, and a real wp-cron endpoint never emits that much output.
func TestWPCronLargeBodyNotFlagged(t *testing.T) {
	big := "<html><body>" + strings.Repeat("rewritten page filler ", 20) + "</body></html>"
	srv := wpcronServer(http.StatusOK, big)
	defer srv.Close()
	if got := scanInteresting(t, srv); hasInteresting(got, "wp-cron.php reachable (external cron triggers possible)") {
		t.Errorf("Interesting = %+v, the >maxWPCronBodyLen body must not be flagged", got)
	}
}

// TestWPCronBlockedStatusesNotFlagged verifies 403/404 answers (blocked or
// disabled cron) produce no entry.
func TestWPCronBlockedStatusesNotFlagged(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		srv := wpcronServer(status, "denied")
		defer srv.Close()
		if got := scanInteresting(t, srv); hasInteresting(got, "wp-cron.php reachable (external cron triggers possible)") {
			t.Errorf("status %d: Interesting = %+v, want no wp-cron entry", status, got)
		}
	}
}
