package db

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// indexFixtureFeed writes a raw feed exercising every affected-version
// shape the loader produces: structured from/to fields (whose ranges carry
// an empty version.Range.Label and cannot be reconstructed from labels
// alone), label-parsed ranges including a comma-separated union of
// multiple ranges, a scanner-style title-derived record, and an
// informational record that must stay out of the slug index.
func indexFixtureFeed(t *testing.T) string {
	t.Helper()
	body := `{
  "11111111-0000-0000-0000-000000000001": {
    "id": "11111111-0000-0000-0000-000000000001",
    "title": "Structured Plugin < 1.37 - XSS",
    "description": "Structured fields.",
    "cve": "CVE-2026-1001",
    "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8, "rating": "CRITICAL"},
    "published_at": "2026-01-01T00:00:00+00:00",
    "informational": false,
    "software": [{
      "type": "plugin", "name": "Structured Plugin", "slug": "structured-plugin",
      "affected_versions": {
        "*-1.37": {"from_version": "*", "from_inclusive": true, "to_version": "1.37", "to_inclusive": true}
      }
    }]
  },
  "22222222-0000-0000-0000-000000000002": {
    "id": "22222222-0000-0000-0000-000000000002",
    "title": "Labeled Plugin < 3.0 - XSS",
    "informational": false,
    "software": [{
      "type": "plugin", "name": "Labeled Plugin", "slug": "labeled-plugin",
      "affected_versions": {
        "1.0.0 - 2.9.9, 3.1.0 - 3.5": {"from_version": "", "to_version": ""},
        "[*, 3.7)": {"from_version": "", "to_version": ""}
      }
    }]
  },
  "33333333-0000-0000-0000-000000000003": {
    "id": "33333333-0000-0000-0000-000000000003",
    "title": "Scan Plugin < 4.0.1 - Detection",
    "software": [],
    "informational": false
  },
  "44444444-0000-0000-0000-000000000004": {
    "id": "44444444-0000-0000-0000-000000000004",
    "title": "Info only",
    "informational": true,
    "software": [{
      "type": "theme", "name": "Info Theme", "slug": "info-theme",
      "affected_versions": {"*": {"from_version": "", "to_version": "*"}}
    }]
  }
}`
	path := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// compareDBs asserts that two DBs expose identical lookup/order semantics
// and identical record content (deep comparison, including the unexported
// internals of parsed version ranges).
func compareDBs(t *testing.T, got, want *DB) {
	t.Helper()
	if got.Count() != want.Count() {
		t.Fatalf("Count() = %d, want %d", got.Count(), want.Count())
	}
	if got.Skipped() != want.Skipped() {
		t.Errorf("Skipped() = %d, want %d", got.Skipped(), want.Skipped())
	}
	if !reflect.DeepEqual(got.TopSlugs(100), want.TopSlugs(100)) {
		t.Errorf("TopSlugs differ:\n got %v\nwant %v", got.TopSlugs(100), want.TopSlugs(100))
	}
	if !reflect.DeepEqual(got.Records, want.Records) {
		t.Errorf("Records differ:\n got %+v\nwant %+v", got.Records, want.Records)
	}
	for _, slug := range want.TopSlugs(100) {
		if !reflect.DeepEqual(got.Lookup(slug), want.Lookup(slug)) {
			t.Errorf("Lookup(%q) differs:\n got %+v\nwant %+v", slug, got.Lookup(slug), want.Lookup(slug))
		}
	}
	// Informational-only slugs must stay out of the index on both sides.
	if !reflect.DeepEqual(got.Lookup("info-theme"), want.Lookup("info-theme")) {
		t.Errorf("Lookup(info-theme) differs: %v vs %v", got.Lookup("info-theme"), want.Lookup("info-theme"))
	}
	if len(got.Lookup("nope")) != 0 {
		t.Errorf("Lookup(nope) = %v, want empty", got.Lookup("nope"))
	}
}

func TestIndexRoundTrip(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := SaveIndex(path, want); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	if _, err := os.Stat(path + ".idx"); err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached: %v", err)
	}
	compareDBs(t, got, want)
	// A second load from the cache must agree too.
	got2, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached (2nd): %v", err)
	}
	compareDBs(t, got2, want)
}

// TestIndexCacheHitDoesNotRewrite pins that a fresh sidecar is served
// without being rewritten: LoadCached on a valid cache must leave the
// sidecar's mtime untouched (SaveIndex would stamp it with "now").
func TestIndexCacheHitDoesNotRewrite(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIndex(path, want); err != nil {
		t.Fatal(err)
	}
	idxPath := path + ".idx"
	dataInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	pinned := dataInfo.ModTime().Add(5 * time.Second)
	if err := os.Chtimes(idxPath, pinned, pinned); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCached(path); err != nil {
		t.Fatalf("LoadCached: %v", err)
	}
	idxInfo, err := os.Stat(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	if !idxInfo.ModTime().Equal(pinned) {
		t.Fatalf("LoadCached rewrote a valid sidecar: mtime %v, want %v", idxInfo.ModTime(), pinned)
	}
}

// TestIndexStaleByContentHash replaces the feed content after the sidecar
// was written: the stored source hash no longer matches, so LoadCached
// must fall back to Load and refresh the sidecar for the new content.
func TestIndexStaleByContentHash(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIndex(path, want); err != nil {
		t.Fatal(err)
	}
	replacement := `{
  "99999999-0000-0000-0000-000000000009": {
    "id": "99999999-0000-0000-0000-000000000009",
    "title": "Replaced < 1.0",
    "informational": false,
    "software": [{
      "type": "plugin", "name": "Replaced", "slug": "replaced",
      "affected_versions": {"*": {"from_version": "", "to_version": "*"}}
    }]
  }
}`
	if err := os.WriteFile(path, []byte(replacement), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached after content change: %v", err)
	}
	wantReplaced, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	compareDBs(t, got, wantReplaced)
	// The fallback refreshed the sidecar: it must now validate against
	// the new content.
	if _, err := readIndexFile(path); err != nil {
		t.Fatalf("sidecar not refreshed after fallback: %v", err)
	}
}

// TestIndexStaleByMtime bumps the source mtime into the future with the
// content unchanged. The mtime pre-filter rejects the sidecar even though
// the hash still matches, so LoadCached falls back to Load — which
// rewrites the sidecar (observable via its mtime advancing).
func TestIndexStaleByMtime(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIndex(path, want); err != nil {
		t.Fatal(err)
	}
	idxPath := path + ".idx"
	before, err := os.Stat(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	// Filesystems differ in timestamp granularity. Pin the old sidecar far
	// enough in the past so a synchronous rewrite is always observable.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(idxPath, old, old); err != nil {
		t.Fatal(err)
	}
	before, err = os.Stat(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached after mtime bump: %v", err)
	}
	compareDBs(t, got, want)
	after, err := os.Stat(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().After(before.ModTime()) {
		t.Fatalf("sidecar not rewritten by fallback: mtime %v -> %v", before.ModTime(), after.ModTime())
	}
}

func TestIndexMissingSidecar(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached without sidecar: %v", err)
	}
	compareDBs(t, got, want)
	// The best-effort refresh on the fallback path leaves a sidecar
	// behind.
	if _, err := os.Stat(path + ".idx"); err != nil {
		t.Fatalf("fallback did not write a sidecar: %v", err)
	}
}

func TestIndexCorruptSidecar(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".idx", []byte("this is not a gob stream at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached with corrupt sidecar must fall back, got error: %v", err)
	}
	compareDBs(t, got, want)
}

// TestIndexUnsupportedVersionFallsBack encodes a structurally valid gob
// payload carrying an unknown format version: the decoder accepts the
// stream, readIndexFile rejects it, and LoadCached falls back.
func TestIndexUnsupportedVersionFallsBack(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	legacy := indexFile{Version: indexFormatVersion + 1, SourceSHA: "x"}
	if err := gob.NewEncoder(&buf).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".idx", buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached with unsupported version must fall back, got error: %v", err)
	}
	compareDBs(t, got, want)
}

// TestIndexLegacyUncompressedSidecarIsAMiss hand-builds a payload exactly
// as pre-gzip versions of SaveIndex wrote it: a plain, uncompressed gob
// stream of indexFile with a valid schema version and the correct source
// hash. The modern reader sniffs for the gzip magic instead of decoding,
// so this file is treated as legacy/corrupt — never served — and
// LoadCached falls back to Load, rebuilding correct data and refreshing
// the sidecar in gzip form.
func TestIndexLegacyUncompressedSidecarIsAMiss(t *testing.T) {
	path := indexFixtureFeed(t)
	want, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sha, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	legacy := indexFile{
		Version:   indexFormatVersion,
		SourceSHA: sha,
		Skipped:   want.Skipped(),
		Records: []indexVuln{{
			ID:          "11111111-0000-0000-0000-000000000001",
			Title:       "Structured Plugin < 1.37 - XSS",
			Description: "Structured fields.",
			CVE:         "CVE-2026-1001",
			CVSS:        CVSS{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8, Rating: "critical"},
			PublishedAt: "2026-01-01T00:00:00+00:00",
			Software: []indexSoftware{{
				Type: "plugin",
				Name: "Structured Plugin",
				Slug: "structured-plugin",
				AffectedVersions: map[string]indexAffectedVersion{
					"*-1.37": {
						Label:  "*-1.37",
						Ranges: []indexRange{{FromIncl: true, ToIncl: true}},
					},
				},
			}},
		}},
	}
	if err := gob.NewEncoder(&buf).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".idx", buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIndexFile(path); err == nil {
		t.Fatal("readIndexFile served a legacy uncompressed sidecar; want a cache miss")
	}
	got, err := LoadCached(path)
	if err != nil {
		t.Fatalf("LoadCached over legacy uncompressed sidecar must fall back, got error: %v", err)
	}
	compareDBs(t, got, want)
	idxBytes, err := os.ReadFile(path + ".idx")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(idxBytes, gzipMagic[:]) {
		t.Fatalf("refreshed sidecar does not start with the gzip magic: % X", idxBytes[:min(len(idxBytes), len(gzipMagic))])
	}
}

func TestSaveIndexMissingSource(t *testing.T) {
	// SaveIndex hashes the source feed first, so a missing source is an
	// error rather than a sidecar with a bogus hash.
	if err := SaveIndex("/nonexistent/feed.json", &DB{}); err == nil {
		t.Fatal("SaveIndex on a missing source must fail")
	}
}
