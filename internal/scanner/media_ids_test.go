package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// mediaProbeServer serves a WordPress-like site whose /?p=N attachments
// carry an uploads reference exactly for the post ids in hit, plus a
// homepage chosen by the caller (with or without an uploads reference for
// the legacy presence check). Every /?p=N request is counted so tests can
// assert the exact probe volume.
func mediaProbeServer(homepage string, hit map[string]bool) (*httptest.Server, *atomic.Int64) {
	var probes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if p := r.URL.Query().Get("p"); p != "" {
			probes.Add(1)
			w.Header().Set("Content-Type", "text/html")
			if hit[p] {
				_, _ = w.Write([]byte(`<html><body><img src="/wp-content/uploads/2025/06/photo.jpg" /></body></html>`))
			} else {
				_, _ = w.Write([]byte(`<html><body>plain post, no media</body></html>`))
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(homepage))
	})
	return httptest.NewServer(mux), &probes
}

var plainHomepage = `<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`

var uploadsHomepage = `<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /></head><body><img src="/wp-content/uploads/2025/06/photo.jpg" /></body></html>`

// TestMediaProbingCountsAttachmentHits verifies the attachment-ID probes:
// with --media-ids 3, /?p=1..3 are fetched, hits on p=1 and p=3 produce
// the summary entry with the exact count, and the legacy homepage entry
// stays absent (the homepage carries no uploads reference).
func TestMediaProbingCountsAttachmentHits(t *testing.T) {
	srv, probes := mediaProbeServer(plainHomepage, map[string]bool{"1": true, "3": true})
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m", MediaIDs: 3})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := probes.Load(); n != 3 {
		t.Errorf("probes = %d, want 3 (/ ?p=1..3)", n)
	}
	want := "media attachments found (2 of 3 probed)"
	found := false
	for _, it := range res.Interesting {
		if it == want {
			found = true
		}
		if it == "media uploads present" {
			t.Error("legacy media uploads entry must not appear (homepage has no uploads reference)")
		}
	}
	if !found {
		t.Errorf("Interesting = %+v, want %q", res.Interesting, want)
	}
}

// TestMediaProbingNoAttachments verifies the no-hit case: probes still run
// (bounded by the cap) but no summary entry is added.
func TestMediaProbingNoAttachments(t *testing.T) {
	srv, probes := mediaProbeServer(plainHomepage, nil)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m", MediaIDs: 4})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := probes.Load(); n != 4 {
		t.Errorf("probes = %d, want 4", n)
	}
	for _, it := range res.Interesting {
		if strings.Contains(it, "media attachments found") {
			t.Errorf("Interesting must not report attachments with zero hits: %q", it)
		}
	}
}

// TestMediaProbingDisabledPreservesLegacy verifies the MediaIDs=0
// behavior: no /?p probes at all (request count unchanged by the option)
// while the legacy homepage-presence entry keeps working.
func TestMediaProbingDisabledPreservesLegacy(t *testing.T) {
	srv, probes := mediaProbeServer(uploadsHomepage, nil)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc0, err := NewScanner(d, srv.URL, Options{Enumerate: "m"})
	if err != nil {
		t.Fatal(err)
	}
	res0, err := sc0.Scan()
	if err != nil {
		t.Fatalf("Scan (MediaIDs=0): %v", err)
	}
	if n := probes.Load(); n != 0 {
		t.Errorf("probes with MediaIDs=0 = %d, want 0", n)
	}
	found := false
	for _, it := range res0.Interesting {
		if it == "media uploads present" {
			found = true
		}
		if strings.Contains(it, "media attachments found") {
			t.Errorf("MediaIDs=0 must keep legacy behavior only: %q", it)
		}
	}
	if !found {
		t.Errorf("Interesting = %+v, want legacy media uploads present", res0.Interesting)
	}

	// The same scan with MediaIDs=3 issues exactly 3 extra requests.
	sc1, err := NewScanner(d, srv.URL, Options{Enumerate: "m", MediaIDs: 3})
	if err != nil {
		t.Fatal(err)
	}
	res1, err := sc1.Scan()
	if err != nil {
		t.Fatalf("Scan (MediaIDs=3): %v", err)
	}
	if got, want := res1.Summary.Requests-res0.Summary.Requests, 3; got != want {
		t.Errorf("extra requests with MediaIDs=3 = %d, want %d", got, want)
	}
	if n := probes.Load(); n != 3 {
		t.Errorf("probes total = %d, want 3", n)
	}
}

// TestMediaProbingCapThirty verifies the hard 30-probe ceiling: a
// --media-ids far beyond 30 issues exactly 30 requests and the summary
// entry names 30, not the configured value.
func TestMediaProbingCapThirty(t *testing.T) {
	srv, probes := mediaProbeServer(plainHomepage, map[string]bool{"1": true})
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Enumerate: "m", MediaIDs: 9999})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := probes.Load(); n != 30 {
		t.Errorf("probes = %d, want capped at 30", n)
	}
	want := "media attachments found (1 of 30 probed)"
	found := false
	for _, it := range res.Interesting {
		if it == want {
			found = true
		}
	}
	if !found {
		t.Errorf("Interesting = %+v, want %q", res.Interesting, want)
	}
}
