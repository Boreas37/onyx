package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// wafInterestingEntry is the static Interesting string appended by the
// WAF/challenge auto-detection rule.
const wafInterestingEntry = "possible WAF/challenge page (403/429/503 or challenge marker)"

// wafChallengeServer serves the given homepage status/body for "/" and
// keeps wp-login.php and wp-json/ answering WordPress evidence, so the
// scan still passes the IsWordPress gate regardless of the homepage.
func wafChallengeServer(t *testing.T, code int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<input name='log' type='text' id='user_login' />"))
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"fake"}`))
	})
	return httptest.NewServer(mux)
}

// TestScanWAFChallengeDetection verifies the always-on WAF/challenge
// rule: a 403/429/503 homepage or a body carrying any challenge marker
// appends the static Interesting entry EXACTLY once (only after the
// target still passed IsWordPress), while a clean homepage stays clean.
func TestScanWAFChallengeDetection(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
		want bool
	}{
		{"403 with challenge marker", http.StatusForbidden,
			"<html><title>Just a moment...</title><body>cf-chl-ldy283...</body></html>", true},
		{"503 without marker", http.StatusServiceUnavailable, "", true},
		{"marker in 200 body", http.StatusOK,
			`<html><head><meta name="generator" content="WordPress 6.4.2"/></head>` +
				`<body>Attention required! Checking your browser before accessing the site...</body></html>`, true},
		{"clean 200", http.StatusOK,
			`<html><head><meta name="generator" content="WordPress 6.4.2"/></head><body>hi</body></html>`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := wafChallengeServer(t, c.code, c.body)
			defer srv.Close()

			d, _ := db.Load(minimalFeed(t))
			sc, err := NewScanner(d, srv.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			res, err := sc.Scan()
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if !res.IsWordPress {
				t.Fatal("fixture must pass the IsWordPress gate for this test to be meaningful")
			}
			count := 0
			for _, i := range res.Interesting {
				if i == wafInterestingEntry {
					count++
				}
			}
			if c.want && count != 1 {
				t.Errorf("WAF entry present %d time(s), want exactly 1 (got %v)", count, res.Interesting)
			}
			if !c.want && count != 0 {
				t.Errorf("clean homepage must not produce the WAF entry, got %v", res.Interesting)
			}
		})
	}
}

// TestWAFChallengeEntryUnit drives the rule helper directly for the
// status/marker/never-fetched combinations without a full scan.
func TestWAFChallengeEntryUnit(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))
	sc, _ := NewScanner(d, "http://example.test", Options{})

	sc.homepageCode = 0
	if got := sc.wafChallengeEntry(); got != "" {
		t.Errorf("unfetched homepage reported %q, want no entry", got)
	}
	sc.homepageCode = http.StatusForbidden
	if got := sc.wafChallengeEntry(); got != wafInterestingEntry {
		t.Errorf("403 without marker = %q, want the entry (status rule)", got)
	}
	sc.homepageCode = http.StatusServiceUnavailable
	if got := sc.wafChallengeEntry(); got != wafInterestingEntry {
		t.Errorf("503 without marker = %q, want the entry (status rule)", got)
	}
	sc.homepageCode = http.StatusTooManyRequests
	if got := sc.wafChallengeEntry(); got != wafInterestingEntry {
		t.Errorf("429 = %q, want the entry (status rule)", got)
	}
	sc.homepageCode = http.StatusOK
	sc.homepage = "<html>unusual traffic from your network</html>"
	if got := sc.wafChallengeEntry(); got != wafInterestingEntry {
		t.Errorf("marker body = %q, want the entry (body rule)", got)
	}
	sc.homepage = "<html>a perfectly normal homepage</html>"
	if got := sc.wafChallengeEntry(); got != "" {
		t.Errorf("clean body = %q, want no entry", got)
	}
}
