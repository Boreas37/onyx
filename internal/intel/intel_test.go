package intel

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

// fixedNow is the clock used by every Load call in these tests.
var fixedNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// failingTransport fails the test if any request escapes; it proves a code
// path made zero network calls.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Helper()
	f.t.Fatal("unexpected network request: fresh cache must be used offline")
	return nil, errors.New("network disabled")
}

// feedServer spins up an httptest server serving epssBody (gzipped CSV) at
// any path and kevBody for the KEV path, and returns a client whose
// transport rewrites the real feed URLs onto the test server.
func feedServer(t *testing.T, epssBody, kevBody []byte) *http.Client {
	t.Helper()
	srv := newTestServer(t, epssBody, kevBody)
	return &http.Client{Transport: rewriteTransport{srv.URL}}
}

// rewriteTransport redirects every request to the test server base URL so
// exported production URLs never leave the process.
type rewriteTransport struct{ base string }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	u := req.URL
	su, err := url.Parse(r.base)
	if err != nil {
		return nil, err
	}
	u.Scheme, u.Host = su.Scheme, su.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestServer(t *testing.T, epssBody, kevBody []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "epss") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(epssBody)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(kevBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// gzCSV compresses csv lines into the gzip stream EPSS serves.
func gzCSV(t *testing.T, lines ...string) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	for _, ln := range lines {
		if _, err := gz.Write([]byte(ln + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

// sampleEPSS is a small well-formed EPSS payload.
func sampleEPSS(t *testing.T) []byte {
	return gzCSV(t,
		"# EPSS Scores Current — synthetic test data",
		"cve,epss,percentile",
		"cve-2024-0001,0.9,0.99",
		"CVE-2024-0002, 0.1 ,0.5",
		"not-a-cve,bogus,0",   // skipped: bad key/score
		"CVE-2024-0003,1.5,1", // skipped: score out of range
	)
}

// sampleKEV is a small well-formed KEV payload.
func sampleKEV() []byte {
	return []byte(`{"title":"CISA Catalog","count":2,
		"vulnerabilities":[{"cveID":"cve-2024-0001"},{"cveID":"CVE-2024-0009"}]}`)
}

// writeCacheFile plants a cache file with the given fetched_at offset.
func writeCacheFile(t *testing.T, dir, name string, age time.Duration, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(body, "FETCHED_AT", fmt.Sprintf("%d", fixedNow.Add(-age).Unix()), 1)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFreshCacheSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	writeCacheFile(t, dir, "epss.json", time.Hour,
		`{"fetched_at":FETCHED_AT,"scores":{"CVE-2024-0001":0.42}}`)
	writeCacheFile(t, dir, "kev.json", 2*time.Hour,
		`{"fetched_at":FETCHED_AT,"cves":["CVE-2024-0002"]}`)

	in, warnings, err := Load(dir, &http.Client{Transport: failingTransport{t}}, fixedNow)
	if err != nil {
		t.Fatalf("fresh cache must load offline: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("fresh cache must not warn, got %v", warnings)
	}
	if s, ok := in.EPSS("cve-2024-0001"); !ok || s != 0.42 {
		t.Errorf("EPSS(cve-2024-0001 lowercase) = %v,%v want 0.42,true (case-insensitive)", s, ok)
	}
	if !in.KEV("CVE-2024-0002") {
		t.Error("KEV(CVE-2024-0002) = false, want true")
	}
	if in.KEV("CVE-9999-9999") || func() bool { _, ok := in.EPSS("CVE-9999-9999"); return ok }() {
		t.Error("unknown CVEs must miss both feeds")
	}
}

func TestLoadStaleCacheRefreshesFromFeeds(t *testing.T) {
	dir := t.TempDir()
	writeCacheFile(t, dir, "epss.json", EpssTTL+time.Hour,
		`{"fetched_at":FETCHED_AT,"scores":{"CVE-2023-OLD":0.01}}`)
	writeCacheFile(t, dir, "kev.json", KevTTL+time.Hour,
		`{"fetched_at":FETCHED_AT,"cves":["CVE-2023-OLD"]}`)

	client := feedServer(t, sampleEPSS(t), sampleKEV())
	in, warnings, err := Load(dir, client, fixedNow)
	if err != nil {
		t.Fatalf("stale cache refresh failed: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("successful refresh must not warn, got %v", warnings)
	}
	if _, ok := in.EPSS("CVE-2023-OLD"); ok {
		t.Error("stale entry must be replaced by downloaded feed")
	}
	if s, ok := in.EPSS("CVE-2024-0001"); !ok || s != 0.9 {
		t.Errorf("EPSS(CVE-2024-0001) = %v,%v want 0.9,true from download", s, ok)
	}
	if !in.KEV("CVE-2024-0009") {
		t.Error("downloaded KEV entry missing")
	}

	// The refresh must have been persisted as fresh cache.
	var ec epssCache
	data, err := os.ReadFile(filepath.Join(dir, "epss.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &ec); err != nil {
		t.Fatalf("rewritten epss.json invalid: %v", err)
	}
	if ec.FetchedAt != fixedNow.Unix() || ec.Scores["CVE-2024-0001"] != 0.9 {
		t.Errorf("rewritten epss.json = %+v", ec)
	}
}

func TestLoadDownloadFailureFallsBackToStaleCache(t *testing.T) {
	dir := t.TempDir()
	writeCacheFile(t, dir, "epss.json", EpssTTL+time.Hour,
		`{"fetched_at":FETCHED_AT,"scores":{"CVE-2024-0001":0.42}}`)
	writeCacheFile(t, dir, "kev.json", KevTTL+time.Hour,
		`{"fetched_at":FETCHED_AT,"cves":["CVE-2024-0002"]}`)

	offline := &http.Client{Transport: failingRT{}}
	in, warnings, err := Load(dir, offline, fixedNow)
	if err != nil {
		t.Fatalf("stale fallback must not error: %v", err)
	}
	if len(warnings) != 2 {
		t.Fatalf("expected one warning per feed, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "epss") || !strings.Contains(warnings[1], "kev") {
		t.Errorf("warnings must name their feed: %v", warnings)
	}
	if s, ok := in.EPSS("CVE-2024-0001"); !ok || s != 0.42 {
		t.Errorf("stale EPSS fallback = %v,%v want 0.42,true", s, ok)
	}
	if !in.KEV("CVE-2024-0002") {
		t.Error("stale KEV fallback missing")
	}
}

// failingRT simulates total network failure without touching the network.
type failingRT struct{}

func (failingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestLoadFailsWhenNothingAvailable(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Load(dir, &http.Client{Transport: failingRT{}}, fixedNow)
	if err == nil {
		t.Fatal("no cache and no network must return an error")
	}
	if !strings.Contains(err.Error(), "epss") {
		t.Errorf("error should identify the failing feed: %v", err)
	}
}

func TestLoadCorruptDownloadFallsBackToStaleCache(t *testing.T) {
	dir := t.TempDir()
	writeCacheFile(t, dir, "epss.json", EpssTTL+time.Hour,
		`{"fetched_at":FETCHED_AT,"scores":{"CVE-2024-0001":0.42}}`)

	// A valid HTTP 200 whose body is not gzip.
	bad := feedServer(t, []byte("definitely not gzip"), sampleKEV())
	in, warnings, err := Load(dir, bad, fixedNow)
	if err != nil {
		t.Fatalf("corrupt download must fall back to stale cache: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "epss") {
		t.Errorf("expected single epss warning, got %v", warnings)
	}
	if s, ok := in.EPSS("CVE-2024-0001"); !ok || s != 0.42 {
		t.Errorf("stale fallback after corrupt download = %v,%v want 0.42,true", s, ok)
	}
}

func TestParseEPSSHostileInputs(t *testing.T) {
	huge := strings.Repeat("A", maxLineLen+1) // over-long line aborts scanning
	hostile := gzCSV(t,
		"# comment",
		"cve,epss,percentile",
		"CVE-2024-00\x01\x02\x1b01,0.5,0.5", // control chars inside the key
		"  cve-2024-0002  ,0.25,0.25",       // whitespace padding
		strings.Repeat("X,", 10)+"0.1",      // garbage columns
		"CVE-2024-0004,nan,0",               // unparseable score
		huge,                                // hostile huge line
		"CVE-2024-0005,0.75,0.9",            // after the huge line: may or may not parse
	)
	scores, err := parseEPSS(hostile)
	if err != nil {
		t.Fatalf("hostile CSV must still yield usable rows: %v", err)
	}
	if s, ok := scores["CVE-2024-0001"]; !ok || s != 0.5 {
		t.Errorf("sanitized key missing: %v,%v", s, ok)
	}
	if s, ok := scores["CVE-2024-0002"]; !ok || s != 0.25 {
		t.Errorf("padded row missing: %v,%v", s, ok)
	}
	for key := range scores {
		if strings.ContainsAny(key, "\x1b\n\r\x00") {
			t.Errorf("control character survived into key %q", key)
		}
	}
}

func TestParseEPSSEntryCap(t *testing.T) {
	lines := []string{"# cap test", "cve,epss,percentile"}
	for i := 0; i <= maxEntries; i++ { // one more than the cap
		lines = append(lines, fmt.Sprintf("CVE-9999-%06d,0.5,0.5", i))
	}
	scores, err := parseEPSS(gzCSV(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != maxEntries {
		t.Errorf("entry cap: got %d entries, want exactly %d", len(scores), maxEntries)
	}
}

func TestParseKEVHostileAndEmptyInputs(t *testing.T) {
	if _, err := parseKEV([]byte(`{"title":"empty","vulnerabilities":[]}`)); err == nil {
		t.Error("KEV feed with no vulnerabilities must error")
	}
	if _, err := parseKEV([]byte("not json")); err == nil {
		t.Error("non-JSON KEV body must error")
	}
	cves, err := parseKEV([]byte("{\"vulnerabilities\":[" +
		"{\"cveID\":\" cve-2024-0001 \"},{\"cveID\":\"CVE-2024-0001\"},{\"cveID\":\"CVE\\u0000-2024-0002\"}," +
		"{\"cveID\":\"garbage\"}]}"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 2 || cves[0] != "CVE-2024-0001" || cves[1] != "CVE-2024-0002" {
		t.Errorf("hostile KEV parse = %v, want deduped normalized [CVE-2024-0001 CVE-2024-0002]", cves)
	}
}

func TestEnrichOrdersFindingsAndVulnerabilities(t *testing.T) {
	in := &Intel{
		epss: map[string]float64{
			"CVE-2024-0001": 0.1,
			"CVE-2024-0002": 0.9,
			"CVE-2024-0003": 0.5,
			"CVE-2024-0004": 0.7,
		},
		kev: map[string]bool{"CVE-2024-0003": true},
	}
	findings := []scanner.Finding{
		{
			Slug: "zebra-plugin", Type: "plugin", InstalledVersion: "1.0",
			Vulnerabilities: []scanner.Vulnerability{
				{CVE: "CVE-2024-0001", CVSSScore: 5.0},
				{CVE: "CVE-2024-0002", CVSSScore: 9.8},
			},
		},
		{
			Slug: "alpha-theme", Type: "theme", InstalledVersion: "2.0",
			Vulnerabilities: []scanner.Vulnerability{
				{CVE: "CVE-2024-0004", CVSSScore: 3.0},
				{CVE: "CVE-2024-0003", CVSSScore: 7.0}, // KEV
			},
		},
		{
			Slug: "middle-plugin", Type: "plugin", InstalledVersion: "3.0",
			Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0004", CVSSScore: 6.0}},
		},
	}

	Enrich(findings, in)

	wantOrder := []string{"alpha-theme", "zebra-plugin", "middle-plugin"}
	for i, slug := range wantOrder {
		if findings[i].Slug != slug {
			t.Fatalf("finding[%d] = %s, want %s (full order %v)", i, findings[i].Slug, slug, findings)
		}
	}

	alpha := findings[0]
	if got := alpha.Vulnerabilities[0].CVE; got != "CVE-2024-0003" {
		t.Errorf("KEV vuln must sort first within finding, got %s", got)
	}
	if !alpha.Vulnerabilities[0].Kev {
		t.Error("KEV flag not stamped on enriched vulnerability")
	}
	if alpha.Vulnerabilities[0].Epss != 0.5 {
		t.Errorf("KEV vuln epss = %v, want 0.5", alpha.Vulnerabilities[0].Epss)
	}
	if got := alpha.Vulnerabilities[1].CVE; got != "CVE-2024-0004" {
		t.Errorf("remaining vuln must follow, got %s", got)
	}

	zebra := findings[1]
	if zebra.Vulnerabilities[0].CVE != "CVE-2024-0002" {
		t.Errorf("higher EPSS must win within finding, got %s", zebra.Vulnerabilities[0].CVE)
	}
	if zebra.Vulnerabilities[0].Epss != 0.9 {
		t.Errorf("epss not stamped: %v", zebra.Vulnerabilities[0].Epss)
	}
	if zebra.Vulnerabilities[1].Kev {
		t.Error("non-KEV vuln must not be flagged")
	}
}

func TestEnrichNilIntelIsSafe(t *testing.T) {
	findings := []scanner.Finding{
		{Slug: "b", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0002", CVSSScore: 5}}},
		{Slug: "a", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0001", CVSSScore: 5}}},
	}
	Enrich(findings, nil) // must not panic
	if findings[0].Slug != "a" || findings[1].Slug != "b" {
		t.Errorf("equal ranks must fall through to slug order, got %s then %s", findings[0].Slug, findings[1].Slug)
	}
	if findings[0].Vulnerabilities[0].Kev || findings[0].Vulnerabilities[0].Epss != 0 {
		t.Error("nil intel must leave enrichment fields untouched")
	}
}

func TestEnrichCVSSThenSlugTiebreak(t *testing.T) {
	findings := []scanner.Finding{
		{Slug: "beta", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0001", CVSSScore: 7.5}}},
		{Slug: "alpha", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0002", CVSSScore: 9.0}}},
		{Slug: "gamma", Vulnerabilities: []scanner.Vulnerability{{CVE: "CVE-2024-0003", CVSSScore: 9.0}}},
	}
	Enrich(findings, &Intel{})
	// CVSS desc puts beta (7.5) last; alpha and gamma tie at 9.0, so the
	// slug-ascending tiebreak orders alpha before gamma.
	want := []string{"alpha", "gamma", "beta"}
	for i, slug := range want {
		if findings[i].Slug != slug {
			t.Fatalf("finding[%d] = %s, want %s (CVSS desc then slug asc)", i, findings[i].Slug, slug)
		}
	}
}
