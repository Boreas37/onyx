package dbupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSemanticDigestRoundTrip generates a delta and applies it onto a
// copy of the old feed, then checks the header's result_semantic_sha256
// equals the semantic digest of both the new feed and the reconstructed
// output.
func TestSemanticDigestRoundTrip(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
		idC = "cccccccc-3333-3333-3333-333333333333"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recC := rec(idC, "Plugin C < 3.0.0", "CVE-2026-0003", 6.1, "2026-03-03T00:00:00+00:00", false)

	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	workPath := filepath.Join(dir, "work.json")
	deltaPath := filepath.Join(dir, "d.json.gz")
	resultPath := filepath.Join(dir, "result.json")

	writeFile(t, oldPath, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))
	writeFile(t, newPath, feedJSON([2]string{idA, recA}, [2]string{idB, recB}, [2]string{idC, recC}))
	writeFile(t, workPath, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))

	if _, err := GenerateDelta(oldPath, newPath, deltaPath); err != nil {
		t.Fatalf("GenerateDelta: %v", err)
	}
	header, _, err := readDeltaFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	if header.ResultSemanticSHA256 == "" {
		t.Fatal("generated delta header lacks result_semantic_sha256")
	}
	wantDigest, err := semanticFeedDigest(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if header.ResultSemanticSHA256 != wantDigest {
		t.Fatalf("header digest = %q, want %q", header.ResultSemanticSHA256, wantDigest)
	}

	if _, err := ApplyDelta(workPath, deltaPath, resultPath); err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	gotDigest, err := semanticFeedDigest(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != header.ResultSemanticSHA256 {
		t.Fatalf("reconstructed digest = %q, want %q", gotDigest, header.ResultSemanticSHA256)
	}
}

// TestApplyDeltaRejectsCorruptedOpRecord builds a genuine delta, rewrites
// one op's record bytes while keeping every structural counter valid, and
// asserts ApplyDelta rejects it on the semantic digest alone — and leaves
// no output file behind.
func TestApplyDeltaRejectsCorruptedOpRecord(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recBEvil := rec(idB, "Plugin B < 9.9.9 EVIL", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)

	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	writeFile(t, oldPath, feedJSON([2]string{idA, recA}))
	writeFile(t, newPath, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))

	deltaPath := filepath.Join(dir, "d.json.gz")
	if _, err := GenerateDelta(oldPath, newPath, deltaPath); err != nil {
		t.Fatalf("GenerateDelta: %v", err)
	}
	header, ops, err := readDeltaFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	// Same op count and id set, corrupted record payload: every structural
	// check still passes; only the semantic digest catches the swap.
	evil := append([]deltaOp(nil), ops...)
	for i := range evil {
		if evil[i].ID == idB {
			evil[i].Record = json.RawMessage(recBEvil)
		}
	}
	evilPath := filepath.Join(dir, "evil.json.gz")
	writeTestDelta(t, evilPath, header, evil)

	outPath := filepath.Join(dir, "out.json")
	_, err = ApplyDelta(oldPath, evilPath, outPath)
	if err == nil || !strings.Contains(err.Error(), "semantic") {
		t.Fatalf("err = %v, want semantic digest mismatch", err)
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Fatal("rejected delta left an output file behind")
	}
}

// TestV1DeltaWithoutSemanticFieldStillApplies hand-crafts a v1 delta with
// the optional field absent (zero value + omitempty) and asserts ApplyDelta
// skips the digest check entirely — backward compatible.
func TestV1DeltaWithoutSemanticFieldStillApplies(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	writeFile(t, basePath, feedJSON([2]string{idA, recA}))
	baseSHA, err := fileSHA256(basePath)
	if err != nil {
		t.Fatal(err)
	}
	deltaPath := filepath.Join(dir, "v1.json.gz")
	writeTestDelta(t, deltaPath,
		deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 2, Records: 1},
		[]deltaOp{{Op: opAdd, ID: idB, Record: json.RawMessage(recB)}})

	outPath := filepath.Join(dir, "out.json")
	if _, err := ApplyDelta(basePath, deltaPath, outPath); err != nil {
		t.Fatalf("v1 delta without result_semantic_sha256 must apply: %v", err)
	}
}

// TestSemanticDigestContentSensitiveOrderInsensitive pins the digest's
// defining properties: it changes when any record's content changes even
// if the record count is unchanged, and it is insensitive to the order of
// records within the feed file.
func TestSemanticDigestContentSensitiveOrderInsensitive(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recB2 := rec(idB, "Plugin B < 2.0.1", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)

	dir := t.TempDir()
	feedA := filepath.Join(dir, "a.json")
	feedB := filepath.Join(dir, "b.json")
	feedC := filepath.Join(dir, "c.json")
	writeFile(t, feedA, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))
	writeFile(t, feedB, feedJSON([2]string{idA, recA}, [2]string{idB, recB2}))
	writeFile(t, feedC, feedJSON([2]string{idB, recB}, [2]string{idA, recA}))

	da, err := semanticFeedDigest(feedA)
	if err != nil {
		t.Fatal(err)
	}
	db, err := semanticFeedDigest(feedB)
	if err != nil {
		t.Fatal(err)
	}
	if da == db {
		t.Fatal("digest must change when a record's content changes")
	}
	dc, err := semanticFeedDigest(feedC)
	if err != nil {
		t.Fatal(err)
	}
	if dc != da {
		t.Fatalf("digest is order-sensitive: %q vs %q", da, dc)
	}
}

// TestGenerateDeltaSemanticDigestDiffersAcrossFeeds asserts that two
// deltas generated from different new feeds with the SAME record count
// advertise different result_semantic_sha256 values.
func TestGenerateDeltaSemanticDigestDiffersAcrossFeeds(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recB2 := rec(idB, "Plugin B < 2.0.1", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.json")
	writeFile(t, emptyPath, nil)
	new1 := filepath.Join(dir, "new1.json")
	new2 := filepath.Join(dir, "new2.json")
	writeFile(t, new1, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))
	writeFile(t, new2, feedJSON([2]string{idA, recA}, [2]string{idB, recB2}))

	h1, err := readDeltaFileForGenerate(emptyPath, new1, filepath.Join(dir, "d1.gz"))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := readDeltaFileForGenerate(emptyPath, new2, filepath.Join(dir, "d2.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if h1.ResultRecords != h2.ResultRecords {
		t.Fatalf("fixture counts differ (%d vs %d), want equal", h1.ResultRecords, h2.ResultRecords)
	}
	if h1.ResultSemanticSHA256 == h2.ResultSemanticSHA256 {
		t.Fatal("semantic digests must differ when record content differs")
	}
}

func readDeltaFileForGenerate(oldPath, newPath, deltaPath string) (deltaHeader, error) {
	if _, err := GenerateDelta(oldPath, newPath, deltaPath); err != nil {
		return deltaHeader{}, err
	}
	h, _, err := readDeltaFile(deltaPath)
	return h, err
}
