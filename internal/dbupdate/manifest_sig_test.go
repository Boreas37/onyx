package dbupdate

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyManifest pins the bytes-in verifier over raw manifest bytes:
// it shares VerifyMinisign's pipeline, so genuine bytes verify, tampered
// bytes fail the main signature, a wrong key fails, and a comment-less
// (2-line) signature verifies through the main-sig-only path.
func TestVerifyManifest(t *testing.T) {
	dir := t.TempDir()
	pub, sec := GenerateTestKeypair(t, dir)

	rawManifest := []byte(`{"generated_at":"2026-08-21T04:00:00Z","full":{"sha256":"abc","size":5,"path":"f.json.gz"}}`)
	dataPath := filepath.Join(dir, "manifest.json")
	writeFile(t, dataPath, rawManifest)
	sigPath := signTestFile(t, sec, dataPath, dir, "timestamp=2026-08-21T04:00:00Z\tfile:manifest.json")

	if err := VerifyManifest(pub, rawManifest, sigPath); err != nil {
		t.Fatalf("VerifyManifest on genuine bytes: %v", err)
	}

	// Tampered bytes: the main signature no longer covers the message.
	tampered := append([]byte{}, rawManifest...)
	tampered[len(tampered)-5] = 'X'
	if err := VerifyManifest(pub, tampered, sigPath); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("err = %v, want signature verification failed", err)
	}

	// Comment-less signature (untrusted comment + blob only): the
	// main-sig-only path, consistent with VerifyMinisign.
	lines, err := readMinisignLines(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(dir, "bare.minisig")
	writeFile(t, bare, []byte(lines[0]+"\n"+lines[1]+"\n"))
	if err := VerifyManifest(pub, rawManifest, bare); err != nil {
		t.Fatalf("comment-less signature should verify: %v", err)
	}

	// Wrong public key fails.
	otherPub, _ := GenerateTestKeypair(t, filepath.Join(dir, "other"))
	if err := VerifyManifest(otherPub, rawManifest, sigPath); err == nil {
		t.Fatal("VerifyManifest with wrong key succeeded")
	}
}

// TestFetchManifestRaw pins the raw transport layer behind FetchManifest:
// it returns the exact bytes served, and FetchManifest still parses them
// on top.
func TestFetchManifestRaw(t *testing.T) {
	doc := []byte(`{"generated_at":"2026-08-21T04:00:00Z","full":{"sha256":"abc123","size":158334981,"path":"wordfence-latest.json.gz"},"deltas":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(doc)
	}))
	defer srv.Close()

	raw, err := FetchManifestRaw(nil, srv.URL)
	if err != nil {
		t.Fatalf("FetchManifestRaw: %v", err)
	}
	if string(raw) != string(doc) {
		t.Fatalf("raw = %q, want %q", raw, doc)
	}
	m, err := FetchManifest(nil, srv.URL)
	if err != nil {
		t.Fatalf("FetchManifest on FetchManifestRaw-backed fetch: %v", err)
	}
	if m.Full.Sha256 != "abc123" {
		t.Fatalf("parsed sha = %q, want abc123", m.Full.Sha256)
	}
}
