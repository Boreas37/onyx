package dbupdate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFetchManifest(t *testing.T) {
	doc := `{
	  "generated_at": "2026-08-21T04:00:00Z",
	  "full": {"sha256": "abc123", "size": 158334981, "path": "wordfence-latest.json.gz"},
	  "deltas": [
	    {"from_sha256": "def456", "path": "delta-def456.json.gz",
	     "records": {"added": 3, "removed": 1, "updated": 12, "result": 39871}}
	  ]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manifest.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(doc))
	}))
	defer srv.Close()

	t.Run("nil client uses default timeout", func(t *testing.T) {
		m, err := FetchManifest(nil, srv.URL+"/manifest.json")
		if err != nil {
			t.Fatalf("FetchManifest: %v", err)
		}
		if m.GeneratedAt != "2026-08-21T04:00:00Z" {
			t.Errorf("generated_at = %q", m.GeneratedAt)
		}
		wantFull := FullEntry{Sha256: "abc123", Size: 158334981, Path: "wordfence-latest.json.gz"}
		if !reflect.DeepEqual(m.Full, wantFull) {
			t.Errorf("full = %+v, want %+v", m.Full, wantFull)
		}
		if len(m.Deltas) != 1 {
			t.Fatalf("len(deltas) = %d, want 1", len(m.Deltas))
		}
		wantDelta := DeltaEntry{
			FromSha256: "def456",
			Path:       "delta-def456.json.gz",
			Records:    DeltaCounts{Added: 3, Removed: 1, Updated: 12, Result: 39871},
		}
		if !reflect.DeepEqual(m.Deltas[0], wantDelta) {
			t.Errorf("delta = %+v, want %+v", m.Deltas[0], wantDelta)
		}
	})

	t.Run("custom client is used", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}
		if _, err := FetchManifest(client, srv.URL+"/manifest.json"); err != nil {
			t.Fatalf("FetchManifest: %v", err)
		}
	})

	t.Run("http error status", func(t *testing.T) {
		_, err := FetchManifest(nil, srv.URL+"/missing")
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("err = %v, want 404 status error", err)
		}
	})
}

func TestFetchManifestBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json at all"))
	}))
	defer srv.Close()
	if _, err := FetchManifest(nil, srv.URL); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFetchManifestConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // shut down immediately: connection refused
	if _, err := FetchManifest(nil, srv.URL); err == nil {
		t.Fatal("expected connection error")
	}
}

// TestManifestJSONRoundTrip pins the exact wire field names the mirror
// contract depends on.
func TestManifestJSONRoundTrip(t *testing.T) {
	m := Manifest{
		GeneratedAt: "t0",
		Full:        FullEntry{Sha256: "s", Size: 1, Path: "p"},
		Deltas:      []DeltaEntry{{FromSha256: "f", Path: "d", Records: DeltaCounts{Added: 1, Removed: 2, Updated: 3, Result: 4}}},
	}
	blob, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"generated_at":"t0"`,
		`"full":{"sha256":"s","size":1,"path":"p"}`,
		`"from_sha256":"f"`,
		`"records":{"added":1,"removed":2,"updated":3,"result":4}`,
	} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("marshalled manifest missing %s:\n%s", want, blob)
		}
	}
}
