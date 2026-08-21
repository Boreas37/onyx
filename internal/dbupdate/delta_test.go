package dbupdate

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// rec builds a realistic Wordfence-shaped record body for fixture feeds.
// Structured affected_versions are used so db.Load never has to fall back
// to label parsing.
func rec(id, title, cve string, score float64, published string, informational bool) string {
	return fmt.Sprintf(`{"id":%q,"title":%q,"software":[{"type":"plugin","name":"Akismet","slug":"akismet","patched":false,"patched_versions":[],"remediation":"Update Akismet.","affected_versions":{"*":{"from_version":"","to_version":"*","from_inclusive":true,"to_inclusive":true}}}],"informational":%t,"description":"XSS in %s.","cve":%q,"cvss":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":%v,"rating":"High"},"published_at":%q}`,
		id, title, informational, title, cve, score, published)
}

// feedJSON assembles a feed object from id/record pairs in order.
func feedJSON(pairs ...[2]string) []byte {
	var b strings.Builder
	b.WriteString("{\n")
	for i, p := range pairs {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(&b, "%q:%s", p[0], p[1])
	}
	b.WriteString("\n}\n")
	return []byte(b.String())
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// rawRecords streams a feed file into id -> exact raw value bytes, used to
// assert byte-for-byte preservation of untouched records.
func rawRecords(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage)
	if err := streamFeed(path, func(id string, raw json.RawMessage) error {
		if _, dup := out[id]; dup {
			t.Fatalf("duplicate id %q in %s", id, path)
		}
		out[id] = raw
		return nil
	}); err != nil {
		t.Fatalf("streaming %s: %v", path, err)
	}
	return out
}

// writeTestDelta writes a gzipped delta from parts, for hand-crafted
// corrupt/truncated fixtures.
func writeTestDelta(t *testing.T, path string, header deltaHeader, ops []deltaOp) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if err := writeJSONL(gz, header, ops); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateDeltaTable(t *testing.T) {
	const (
		idA = "11111111-1111-1111-1111-111111111111"
		idB = "22222222-2222-2222-2222-222222222222"
		idC = "33333333-3333-3333-3333-333333333333"
		idD = "44444444-4444-4444-4444-444444444444"
		idE = "55555555-5555-5555-5555-555555555555"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recB2 := rec(idB, "Plugin B < 2.0.1", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recC := rec(idC, "Plugin C < 3.0.0", "", 0, "2026-03-03T00:00:00+00:00", true)

	tests := []struct {
		name        string
		oldContent  []byte
		newContent  []byte
		wantStats   DeltaStats
		wantOpCount int
	}{
		{
			name:        "identical feeds produce zero ops",
			oldContent:  feedJSON([2]string{idA, recA}, [2]string{idB, recB}),
			newContent:  feedJSON([2]string{idA, recA}, [2]string{idB, recB}),
			wantStats:   DeltaStats{BaseRecords: 2, ResultRecords: 2},
			wantOpCount: 0,
		},
		{
			name: "whitespace-only differences are not updates",
			// Same records, pretty-printed differently.
			oldContent:  feedJSON([2]string{idA, recA}),
			newContent:  []byte("{\n  " + fmt.Sprintf("%q:%s", idA, strings.ReplaceAll(recA, ",", ", ")) + "\n}\n"),
			wantStats:   DeltaStats{BaseRecords: 1, ResultRecords: 1},
			wantOpCount: 0,
		},
		{
			name:        "mixed add update remove",
			oldContent:  feedJSON([2]string{idA, recA}, [2]string{idB, recB}, [2]string{idC, recC}),
			newContent:  feedJSON([2]string{idA, recA}, [2]string{idB, recB2}, [2]string{idD, recD(idD)}),
			wantStats:   DeltaStats{Added: 1, Removed: 1, Updated: 1, BaseRecords: 3, ResultRecords: 3},
			wantOpCount: 3,
		},
		{
			name:        "empty old feed yields all adds",
			oldContent:  nil,
			newContent:  feedJSON([2]string{idA, recA}, [2]string{idE, recE(idE)}),
			wantStats:   DeltaStats{Added: 2, BaseRecords: 0, ResultRecords: 2},
			wantOpCount: 2,
		},
		{
			name:        "empty new feed yields all removes",
			oldContent:  feedJSON([2]string{idA, recA}),
			newContent:  nil,
			wantStats:   DeltaStats{Removed: 1, BaseRecords: 1, ResultRecords: 0},
			wantOpCount: 1,
		},
		{
			name:        "both feeds empty",
			oldContent:  nil,
			newContent:  nil,
			wantStats:   DeltaStats{},
			wantOpCount: 0,
		},
		{
			name:        "empty object feeds",
			oldContent:  []byte("{}"),
			newContent:  []byte("{}"),
			wantStats:   DeltaStats{},
			wantOpCount: 0,
		},
	}

	dir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPath := filepath.Join(dir, "old.json")
			newPath := filepath.Join(dir, "new.json")
			deltaPath := filepath.Join(dir, "delta.json.gz")
			writeFile(t, oldPath, tt.oldContent)
			writeFile(t, newPath, tt.newContent)

			stats, err := GenerateDelta(oldPath, newPath, deltaPath)
			if err != nil {
				t.Fatalf("GenerateDelta: %v", err)
			}
			if !reflect.DeepEqual(stats, tt.wantStats) {
				t.Errorf("stats = %+v, want %+v", stats, tt.wantStats)
			}

			header, ops, err := readDeltaFile(deltaPath)
			if err != nil {
				t.Fatalf("reading generated delta: %v", err)
			}
			if header.Format != DeltaFormat {
				t.Errorf("header format = %q, want %q", header.Format, DeltaFormat)
			}
			if len(ops) != tt.wantOpCount || header.Records != tt.wantOpCount {
				t.Errorf("op count = %d/%d, want %d", len(ops), header.Records, tt.wantOpCount)
			}
			if header.ResultRecords != tt.wantStats.ResultRecords {
				t.Errorf("header result_records = %d, want %d", header.ResultRecords, tt.wantStats.ResultRecords)
			}
			wantBaseSHA, err := fileSHA256(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			if header.BaseSHA256 != wantBaseSHA {
				t.Errorf("base_sha256 = %q, want %q", header.BaseSHA256, wantBaseSHA)
			}
		})
	}
}

// recD/recE/recF are tiny distinct records for mixed-diff fixtures.
func recD(id string) string {
	return rec(id, "Plugin D < 4.0.0", "CVE-2026-0004", 5.3, "2026-04-04T00:00:00+00:00", false)
}
func recE(id string) string {
	return rec(id, "Plugin E < 5.0.0", "CVE-2026-0005", 6.7, "2026-05-05T00:00:00+00:00", false)
}
func recF(id string) string {
	return rec(id, "Plugin F < 6.0.0", "CVE-2026-0006", 9.8, "2026-06-06T00:00:00+00:00", false)
}

// readDeltaFile decompresses a delta and returns its header plus ops.
func readDeltaFile(path string) (deltaHeader, []deltaOp, error) {
	var header deltaHeader
	var ops []deltaOp
	f, err := os.Open(path)
	if err != nil {
		return header, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return header, nil, err
	}
	defer gz.Close()
	dec := json.NewDecoder(gz)
	if err := dec.Decode(&header); err != nil {
		return header, nil, err
	}
	for {
		var op deltaOp
		if err := dec.Decode(&op); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return header, ops, err
		}
		ops = append(ops, op)
	}
	return header, ops, nil
}

func TestApplyDeltaRoundTripWithDBLoader(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-1111-1111-111111111111"
		idB = "bbbbbbbb-2222-2222-2222-222222222222"
		idC = "cccccccc-3333-3333-3333-333333333333"
		idD = "dddddddd-4444-4444-4444-444444444444"
		idE = "eeeeeeee-5555-5555-5555-555555555555"
		idF = "ffffffff-6666-6666-6666-666666666666"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)
	recC := rec(idC, "Plugin C < 3.0.0", "CVE-2026-0003", 6.1, "2026-03-03T00:00:00+00:00", false)
	recC2 := rec(idC, "Plugin C < 3.0.1", "CVE-2026-0003", 6.1, "2026-03-03T00:00:00+00:00", false)
	recD := recD(idD)
	recE := recE(idE)
	recF := recF(idF)

	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	workPath := filepath.Join(dir, "work.json")
	deltaPath := filepath.Join(dir, "daily.json.gz")
	resultPath := filepath.Join(dir, "result.json")

	oldFeed := feedJSON(
		[2]string{idA, recA}, [2]string{idB, recB}, [2]string{idC, recC},
		[2]string{idD, recD}, [2]string{idE, recE},
	)
	newFeed := feedJSON(
		[2]string{idA, recA}, [2]string{idB, recB}, [2]string{idC, recC2},
		[2]string{idF, recF},
	)
	writeFile(t, oldPath, oldFeed)
	writeFile(t, newPath, newFeed)
	writeFile(t, workPath, oldFeed) // the copy that gets patched

	stats, err := GenerateDelta(oldPath, newPath, deltaPath)
	if err != nil {
		t.Fatalf("GenerateDelta: %v", err)
	}
	wantStats := DeltaStats{Added: 1, Removed: 2, Updated: 1, BaseRecords: 5, ResultRecords: 4}
	if !reflect.DeepEqual(stats, wantStats) {
		t.Fatalf("generate stats = %+v, want %+v", stats, wantStats)
	}

	applyStats, err := ApplyDelta(workPath, deltaPath, resultPath)
	if err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	wantApply := DeltaStats{Added: 1, Removed: 2, Updated: 1, BaseRecords: 5, ResultRecords: 4}
	if !reflect.DeepEqual(applyStats, wantApply) {
		t.Fatalf("apply stats = %+v, want %+v", applyStats, wantApply)
	}

	// Semantic equality via the real loader.
	gotResult, err := db.Load(resultPath)
	if err != nil {
		t.Fatalf("db.Load(result): %v", err)
	}
	gotNew, err := db.Load(newPath)
	if err != nil {
		t.Fatalf("db.Load(new): %v", err)
	}
	if gotResult.Count() != gotNew.Count() {
		t.Fatalf("record counts differ: result=%d new=%d", gotResult.Count(), gotNew.Count())
	}
	byID := func(d *db.DB) map[string]db.Vuln {
		m := make(map[string]db.Vuln, d.Count())
		for _, v := range d.Records {
			m[v.ID] = v
		}
		return m
	}
	resByID, newByID := byID(gotResult), byID(gotNew)
	if len(resByID) != len(newByID) {
		t.Fatalf("unique id sets differ: %d vs %d", len(resByID), len(newByID))
	}
	for id, want := range newByID {
		got, ok := resByID[id]
		if !ok {
			t.Errorf("result missing id %q", id)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("record %q differs:\n got %+v\nwant %+v", id, got, want)
		}
	}

	// Byte-for-byte preservation: unchanged records must be identical raw
	// slices in the base and the reconstructed output.
	baseRaw := rawRecords(t, workPath)
	resultRaw := rawRecords(t, resultPath)
	for _, id := range []string{idA, idB} {
		if !bytes.Equal(baseRaw[id], resultRaw[id]) {
			t.Errorf("unchanged record %q was re-encoded:\n base: %s\n out:  %s", id, baseRaw[id], resultRaw[id])
		}
	}
	if bytes.Equal(baseRaw[idC], resultRaw[idC]) {
		t.Errorf("updated record %q should have new bytes", idC)
	}
	if _, ok := resultRaw[idD]; ok {
		t.Errorf("removed record %q still present", idD)
	}
	if _, ok := resultRaw[idE]; ok {
		t.Errorf("removed record %q still present", idE)
	}
	if !bytes.Equal(resultRaw[idF], []byte(recF)) {
		t.Errorf("added record %q not verbatim: %s", idF, resultRaw[idF])
	}
}

func TestApplyDeltaErrors(t *testing.T) {
	const (
		idA = "11111111-1111-1111-1111-111111111111"
		idB = "22222222-2222-2222-2222-222222222222"
	)
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)
	recB := rec(idB, "Plugin B < 2.0.0", "CVE-2026-0002", 7.5, "2026-02-02T00:00:00+00:00", false)

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	otherPath := filepath.Join(dir, "other.json")
	writeFile(t, basePath, feedJSON([2]string{idA, recA}))
	writeFile(t, otherPath, feedJSON([2]string{idA, recA}, [2]string{idB, recB}))
	baseSHA, err := fileSHA256(basePath)
	if err != nil {
		t.Fatal(err)
	}

	validHeader := func() deltaHeader {
		return deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 1}
	}

	tests := []struct {
		name      string
		makeDelta func(t *testing.T) string
		wantErr   string
	}{
		{
			name: "base hash mismatch",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: "deadbeef", ResultRecords: 1}, nil)
				return p
			},
			wantErr: "base file hash mismatch",
		},
		{
			name: "duplicate op id",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 2}, []deltaOp{
					{Op: opRemove, ID: idB},
					{Op: opRemove, ID: idB},
				})
				return p
			},
			wantErr: `duplicate id "` + idB + `"`,
		},
		{
			name: "truncated operations",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 3}, []deltaOp{
					{Op: opUpdate, ID: idA, Record: json.RawMessage(recA)},
				})
				return p
			},
			wantErr: "truncated: header lists 3 operations, found 1",
		},
		{
			name: "remove unknown id",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 1}, []deltaOp{
					{Op: opRemove, ID: idB},
				})
				return p
			},
			wantErr: `remove op references unknown id`,
		},
		{
			name: "update unknown id",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 1}, []deltaOp{
					{Op: opUpdate, ID: idB, Record: json.RawMessage(recB)},
				})
				return p
			},
			wantErr: `update op references unknown id`,
		},
		{
			name: "add existing id",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 2, Records: 1}, []deltaOp{
					{Op: opAdd, ID: idA, Record: json.RawMessage(recA)},
				})
				return p
			},
			wantErr: `add op for existing id`,
		},
		{
			name: "unknown op type",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeTestDelta(t, p, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 1, Records: 1}, []deltaOp{
					{Op: "replace", ID: idA, Record: json.RawMessage(recA)},
				})
				return p
			},
			wantErr: `unknown op "replace"`,
		},
		{
			name: "wrong format magic",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				h := validHeader()
				h.Format = "onyx-delta-v2"
				writeTestDelta(t, p, h, nil)
				return p
			},
			wantErr: `unsupported format "onyx-delta-v2"`,
		},
		{
			name: "corrupt gzip",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeFile(t, p, []byte("this is not gzip at all"))
				return p
			},
			wantErr: "corrupt gzip stream",
		},
		{
			name: "empty delta file",
			makeDelta: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "d.gz")
				writeFile(t, p, nil)
				return p
			},
			wantErr: "empty file",
		},
		{
			name: "truncated gzip body cuts operations mid-line",
			makeDelta: func(t *testing.T) string {
				full := filepath.Join(t.TempDir(), "full.gz")
				writeTestDelta(t, full, deltaHeader{Format: DeltaFormat, BaseSHA256: baseSHA, ResultRecords: 2, Records: 2}, []deltaOp{
					{Op: opAdd, ID: idB, Record: json.RawMessage(recB)},
					{Op: opUpdate, ID: idA, Record: json.RawMessage(recA)},
				})
				blob, err := os.ReadFile(full)
				if err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(t.TempDir(), "cut.gz")
				writeFile(t, p, blob[:len(blob)-12]) // chop trailing bytes
				return p
			},
			wantErr: "truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "out.json")
			_, err := ApplyDelta(basePath, tt.makeDelta(t), outPath)
			if err == nil {
				t.Fatalf("ApplyDelta succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			if _, statErr := os.Stat(outPath); statErr == nil {
				t.Errorf("failed apply left an output file behind")
			}
		})
	}
}

func TestApplyDeltaOntoEmptyBase(t *testing.T) {
	const idA = "11111111-1111-1111-1111-111111111111"
	recA := rec(idA, "Plugin A < 1.0.0", "CVE-2026-0001", 8.1, "2026-01-01T00:00:00+00:00", false)

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.json")
	newPath := filepath.Join(dir, "new.json")
	deltaPath := filepath.Join(dir, "d.json.gz")
	resultPath := filepath.Join(dir, "result.json")
	writeFile(t, emptyPath, nil) // zero-byte base
	writeFile(t, newPath, feedJSON([2]string{idA, recA}))

	if _, err := GenerateDelta(emptyPath, newPath, deltaPath); err != nil {
		t.Fatalf("GenerateDelta: %v", err)
	}
	stats, err := ApplyDelta(emptyPath, deltaPath, resultPath)
	if err != nil {
		t.Fatalf("ApplyDelta onto empty base: %v", err)
	}
	if stats.BaseRecords != 0 || stats.Added != 1 || stats.ResultRecords != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	d, err := db.Load(resultPath)
	if err != nil {
		t.Fatalf("db.Load: %v", err)
	}
	if d.Count() != 1 {
		t.Fatalf("count = %d, want 1", d.Count())
	}
}

func TestGenerateDeltaIdenticalFilesZeroOps(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	content := feedJSON(
		[2]string{"x", rec("x-id", "Plugin X < 9.9.9", "CVE-2026-9999", 1.2, "2026-07-07T00:00:00+00:00", false)},
	)
	writeFile(t, a, content)
	writeFile(t, b, content)

	stats, err := GenerateDelta(a, b, filepath.Join(dir, "d.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Added != 0 || stats.Removed != 0 || stats.Updated != 0 {
		t.Fatalf("identical inputs produced ops: %+v", stats)
	}
}
