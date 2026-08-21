package watch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

// webhookRecorder records every request received by the test webhook.
type webhookRecorder struct {
	mu     sync.Mutex
	hits   int
	method string
	ct     string
	body   notifyPayload
}

func (r *webhookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

// recordingServer returns an httptest server that records every request's
// method, content type, decoded notifyPayload, and hit count.
func recordingServer(t *testing.T) (*httptest.Server, *webhookRecorder) {
	t.Helper()
	rec := &webhookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.hits++
		rec.method = r.Method
		rec.ct = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&rec.body); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func TestNotifyPostsJSON(t *testing.T) {
	srv, rec := recordingServer(t)

	d := &Diff{
		Target:    "https://example.com",
		ScannedAt: testNow,
		New: []Change{
			{Slug: "akismet", Type: "plugin", CVE: "CVE-2025-9999", Title: "Akismet SSRF", Rating: "high"},
		},
		Resolved: []Change{
			{Slug: "hello", CVE: "CVE-2023-3333"},
		},
		Unchanged: 12,
	}
	if err := Notify(srv.URL, d, srv.Client()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits != 1 {
		t.Fatalf("hits = %d, want 1", rec.hits)
	}
	if rec.method != http.MethodPost {
		t.Fatalf("method = %s, want POST", rec.method)
	}
	if !strings.HasPrefix(rec.ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", rec.ct)
	}
	if rec.body.Target != "https://example.com" {
		t.Errorf("payload target = %q", rec.body.Target)
	}
	if !rec.body.ScannedAt.Equal(testNow) {
		t.Errorf("payload scanned_at = %v, want %v", rec.body.ScannedAt, testNow)
	}
	if rec.body.Summary != "1 new, 1 resolved, 12 unchanged" {
		t.Errorf("payload summary = %q", rec.body.Summary)
	}
	if len(rec.body.New) != 1 || rec.body.New[0] != (Change{
		Slug: "akismet", Type: "plugin", CVE: "CVE-2025-9999", Title: "Akismet SSRF", Rating: "high",
	}) {
		t.Errorf("payload new = %+v", rec.body.New)
	}
	if len(rec.body.Resolved) != 1 || rec.body.Resolved[0].Slug != "hello" ||
		rec.body.Resolved[0].CVE != "CVE-2023-3333" {
		t.Errorf("payload resolved = %+v", rec.body.Resolved)
	}
}

func TestNotifyNilClientUsesDefault(t *testing.T) {
	srv, rec := recordingServer(t)
	if err := Notify(srv.URL, &Diff{Target: "t", New: []Change{{Slug: "x"}}}, nil); err != nil {
		t.Fatalf("Notify with nil client: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("hits = %d, want 1", rec.count())
	}
}

func TestNotifyNon2xxReturnsErrorWithStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := Notify(srv.URL, &Diff{Target: "t"}, srv.Client())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error %q does not mention status code", err)
	}
}

func TestStateFileName(t *testing.T) {
	name := stateFileName("https://example.com")
	if len(name) != 16+5 || !strings.HasSuffix(name, ".json") {
		t.Fatalf("name = %q, want 16 hex chars + .json", name)
	}
	for _, r := range name[:16] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("name %q is not lowercase hex", name)
		}
	}
	if again := stateFileName("https://example.com"); again != name {
		t.Fatalf("not deterministic: %q vs %q", again, name)
	}
	if same := stateFileName("https://example.org"); same == name {
		t.Fatal("different targets must map to different files")
	}
}

func TestRunFirstRunAllNewAndPersistsState(t *testing.T) {
	dir := t.TempDir()
	d, err := Run("https://example.com", baseResult(), Options{StateDir: dir}, testNow)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(d.New) != 4 || d.Unchanged != 0 || len(d.Resolved) != 0 {
		t.Fatalf("first run diff = new %d / resolved %d / unchanged %d, want 4/0/0",
			len(d.New), len(d.Resolved), d.Unchanged)
	}
	path := filepath.Join(dir, stateFileName("https://example.com"))
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	if st.Target != "https://example.com" || len(st.Baseline) != 3 {
		t.Fatalf("persisted state = %+v", st)
	}
}

func TestRunSecondRunDiffersAndNotifiesOnce(t *testing.T) {
	dir := t.TempDir()
	srv, rec := recordingServer(t)
	opts := Options{StateDir: dir, Webhook: srv.URL, Client: srv.Client()}

	if _, err := Run("https://example.com", baseResult(), opts, testNow); err != nil {
		t.Fatalf("first run: %v", err)
	}
	d, err := Run("https://example.com", modifiedResult(), opts, testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(d.New) != 2 || len(d.Resolved) != 1 || d.Unchanged != 3 {
		t.Fatalf("second run diff = new %d / resolved %d / unchanged %d, want 2/1/3",
			len(d.New), len(d.Resolved), d.Unchanged)
	}
	// First run (empty baseline -> everything new) and second run both have
	// non-empty diffs, so each notifies once.
	if got := rec.count(); got != 2 {
		t.Fatalf("webhook hits = %d, want 2", got)
	}

	// Third identical scan: everything unchanged, empty diff, no notification.
	d3, err := Run("https://example.com", modifiedResult(), opts, testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if !d3.Empty() {
		t.Fatalf("third run diff should be empty, got %+v", d3)
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("webhook hits after empty diff = %d, want 2", got)
	}
}

func TestRunEmptyFindingsNoNotify(t *testing.T) {
	dir := t.TempDir()
	srv, rec := recordingServer(t)
	opts := Options{StateDir: dir, Webhook: srv.URL, Client: srv.Client()}
	empty := &scanner.Result{Target: "https://example.com"}

	prev := BuildState("https://example.com", empty, testNow)
	if err := SaveState(filepath.Join(dir, stateFileName("https://example.com")), prev); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	d, err := Run("https://example.com", empty, opts, testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("diff should be empty, got %+v", d)
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("webhook called %d times for empty diff, want 0", got)
	}
}

func TestRunMissingStateDirCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "states")
	if _, err := Run("https://example.com", baseResult(), Options{StateDir: dir}, testNow); err != nil {
		t.Fatalf("Run: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("state dir not created: %v", err)
	}
}
