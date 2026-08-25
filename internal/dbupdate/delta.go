// Package dbupdate implements incremental updates of the local Wordfence
// vulnerability feed.
//
// It provides three independent capabilities:
//
//   - Record-level deltas between two feed snapshots in the
//     "onyx-delta-v1" format (GenerateDelta, ApplyDelta). A daily delta
//     against the ~151MB feed is typically a few hundred kilobytes
//     instead of a full re-download.
//   - A small client for the mirror's manifest document, which advertises
//     the current full snapshot and the deltas available from earlier
//     snapshots (FetchManifest).
//   - Verify-only minisign/signify Ed25519 signature checking so that
//     downloaded artifacts can be authenticated against a pinned public
//     key (VerifyMinisign).
//
// The package is stdlib-only and deliberately decoupled from internal/db:
// it operates on raw feed bytes so the loader never has to re-parse
// records it already has on disk.
package dbupdate

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// DeltaFormat is the magic "format" value of every onyx-delta-v1 header.
const DeltaFormat = "onyx-delta-v1"

// Op type names used inside a delta file.
const (
	opAdd    = "add"
	opUpdate = "update"
	opRemove = "remove"
)

// DeltaStats summarises one GenerateDelta or ApplyDelta run. BaseRecords
// is the number of records in the input (old feed for generate, base feed
// for apply); ResultRecords is the number of records in the output (new
// feed for generate, reconstructed feed for apply).
type DeltaStats struct {
	Added         int
	Removed       int
	Updated       int
	BaseRecords   int
	ResultRecords int
}

// deltaHeader is the first JSON line of every delta file.
//
// Fields:
//
//	format                 always "onyx-delta-v1"; rejects files that are
//	                       not deltas. The format string is intentionally
//	                       NOT bumped for the optional digest field below —
//	                       v1 files with the field absent (or present) must
//	                       keep applying, and ApplyDelta treats the field as
//	                       optional either way.
//	base_sha256            hex sha256 of the complete base (old) feed file;
//	                       ApplyDelta refuses to patch anything else, which
//	                       pins the delta to an exact base snapshot.
//	result_records         expected record count of the reconstructed feed;
//	                       verified after applying so truncation or
//	                       corruption of either side is detected even when
//	                       every individual op parses.
//	records                number of operation lines that follow the header;
//	                       also verified during application.
//	result_semantic_sha256 OPTIONAL (delta-v2) hex sha256 of the canonical
//	                       semantic digest of the feed the delta was
//	                       generated from (see semanticFeedDigest). Absent
//	                       in v1 files; ApplyDelta verifies the
//	                       reconstructed output against it when present and
//	                       skips the check when absent.
//
// Note on integrity: structural verification (record counts + every op
// applied cleanly) plus the pinned base hash catch truncation and most
// corruption, but they cannot catch an op whose record bytes were rewritten
// while the counts stay valid. result_semantic_sha256 closes that gap
// whenever the generating tool emits it: the digest covers every record's
// compacted content keyed by id, sorted by id, so any content change —
// including a rewritten op record — changes it. It is a SEMANTIC digest,
// not a byte hash: there is deliberately no result byte hash, because an
// application cannot reproduce the upstream byte layout — untouched records
// keep their base ordering while adds and updates are appended — so the
// result is only semantically equal to the new feed, never byte-identical.
// The digest is defined over sorted records precisely so it is insensitive
// to record order and whitespace.
type deltaHeader struct {
	Format               string `json:"format"`
	BaseSHA256           string `json:"base_sha256"`
	ResultRecords        int    `json:"result_records"`
	Records              int    `json:"records"`
	ResultSemanticSHA256 string `json:"result_semantic_sha256,omitempty"`
}

// deltaOp is one JSON-lines operation record.
//
//	{"op":"add","id":"<uuid>","record":{...}}
//	{"op":"update","id":"<uuid>","record":{...}}
//	{"op":"remove","id":"<uuid>"}
//
// Record carries the full raw JSON object for add/update ops; remove ops
// omit it. The id is the feed's outer object key (the vulnerability UUID).
type deltaOp struct {
	Op     string          `json:"op"`
	ID     string          `json:"id"`
	Record json.RawMessage `json:"record,omitempty"`
}

// GenerateDelta compares the feed at oldPath with the feed at newPath and
// writes a gzipped "onyx-delta-v1" file to outPath describing how to turn
// old into new.
//
// Both feeds are streamed with encoding/json streaming decoders (mirroring
// db.Load: dec.Token() for the outer object, dec.More() per record), keyed
// by the outer object key (UUID). Records are compared by canonical
// re-encoding: each raw json.RawMessage is normalised with json.Compact so
// whitespace-only differences do not produce spurious updates. Key order
// inside a record still matters for comparison (it is part of the raw
// bytes); real feeds are machine-generated with stable key order, so this
// is not a problem in practice.
//
// The old feed's compacted records are held in memory (~size of the old
// file) because diffing needs random access by UUID; the new feed is only
// ever touched one record at a time. This matches the memory profile of
// db.Load, which also materialises every record.
//
// The delta header carries result_semantic_sha256: the canonical semantic
// digest of the NEW feed (see semanticFeedDigest), computed from newPath
// after the streaming diff, so ApplyDelta can verify the reconstructed
// feed's content — not just its shape. Computing it re-opens newPath; a
// feed mutated between the diff pass and the digest pass would produce a
// header whose digest matches neither version, which ApplyDelta then
// rejects.
//
// Edge cases: an empty (or whitespace-only) feed file is treated as zero
// records, so generating against an empty old file yields all-adds and
// identical inputs yield a header-only delta with zero operations.
func GenerateDelta(oldPath, newPath string, outPath string) (DeltaStats, error) {
	var stats DeltaStats

	oldRecs, err := loadFeed(oldPath)
	if err != nil {
		return stats, fmt.Errorf("loading old feed: %w", err)
	}
	stats.BaseRecords = len(oldRecs)

	baseSHA, err := fileSHA256(oldPath)
	if err != nil {
		return stats, fmt.Errorf("hashing old feed: %w", err)
	}

	var ops []deltaOp
	err = streamFeed(newPath, func(id string, raw json.RawMessage) error {
		oldRaw, ok := oldRecs[id]
		if !ok {
			stats.Added++
			ops = append(ops, deltaOp{Op: opAdd, ID: id, Record: raw})
			return nil
		}
		delete(oldRecs, id)
		if !bytes.Equal(oldRaw, compactJSON(raw)) {
			stats.Updated++
			ops = append(ops, deltaOp{Op: opUpdate, ID: id, Record: raw})
		}
		return nil
	})
	if err != nil {
		return stats, fmt.Errorf("scanning new feed: %w", err)
	}
	// Whatever remains in oldRecs was absent from the new feed: removed.
	removedIDs := make([]string, 0, len(oldRecs))
	for id := range oldRecs {
		removedIDs = append(removedIDs, id)
	}
	sort.Strings(removedIDs)
	for _, id := range removedIDs {
		stats.Removed++
		ops = append(ops, deltaOp{Op: opRemove, ID: id})
	}
	stats.ResultRecords = stats.BaseRecords + stats.Added - stats.Removed

	digest, err := semanticFeedDigest(newPath)
	if err != nil {
		return stats, fmt.Errorf("digesting new feed: %w", err)
	}

	header := deltaHeader{
		Format:               DeltaFormat,
		BaseSHA256:           baseSHA,
		ResultRecords:        stats.ResultRecords,
		Records:              len(ops),
		ResultSemanticSHA256: digest,
	}
	if err := writeFileAtomic(outPath, func(w io.Writer) error {
		gz := gzip.NewWriter(w)
		if err := writeJSONL(gz, header, ops); err != nil {
			return err
		}
		return gz.Close()
	}); err != nil {
		return stats, fmt.Errorf("writing delta: %w", err)
	}
	return stats, nil
}

// ApplyDelta applies the gzipped "onyx-delta-v1" file at deltaPath onto
// the feed at basePath, writing the reconstructed feed to outPath.
//
// Verification performed:
//
//   - header.base_sha256 must equal the sha256 of the complete base file.
//     The base is opened exactly once: a single streaming pass copies
//     untouched records while feeding every raw byte through the hasher,
//     and the digest is compared to header.base_sha256 at the end of that
//     pass — before any op-derived record reaches the writer. This closes
//     a TOCTOU gap where a second open could observe different content
//     than the hash check did. Because writeFileAtomic writes to a temp
//     file and renames only on success, a mismatch aborts cleanly and no
//     output appears;
//   - the number of parsed operation lines must equal header.records
//     (catches truncated deltas);
//   - every operation must apply cleanly: update/remove ids must exist in
//     the base, add ids must not, and no id may appear twice among the
//     operations;
//   - the reconstructed record count must equal header.result_records;
//   - when the header carries result_semantic_sha256, the canonical
//     semantic digest of the reconstructed feed (see semanticFeedDigest)
//     must equal it. This catches content corruption that survives the
//     structural checks — e.g. a record's bytes rewritten inside an op
//     while counts stay valid. The check runs after the atomic write
//     completes; on mismatch the output file is removed, so a rejected
//     delta leaves nothing behind. v1 deltas without the field skip the
//     check entirely (backward compatible).
//
// Untouched records are copied verbatim — their exact raw JSON bytes from
// the base file, not a re-encoding — so unchanged records survive a
// round-trip byte-for-byte. Updated and added records are appended after
// the preserved base records (in operation order). See the deltaHeader doc
// comment for why the result is semantically but not byte-wise equal to
// the feed the delta was generated from.
func ApplyDelta(basePath, deltaPath, outPath string) (DeltaStats, error) {
	var stats DeltaStats

	df, err := os.Open(deltaPath)
	if err != nil {
		return stats, err
	}
	defer df.Close()

	gz, err := gzip.NewReader(bufio.NewReaderSize(df, 1<<20))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return stats, fmt.Errorf("delta %s: empty file", deltaPath)
		}
		return stats, fmt.Errorf("delta %s: corrupt gzip stream: %w", deltaPath, err)
	}
	defer gz.Close()

	dec := json.NewDecoder(gz)

	var header deltaHeader
	if err := dec.Decode(&header); err != nil {
		return stats, fmt.Errorf("delta %s: reading header: %w", deltaPath, wrapTruncated(err))
	}
	if header.Format != DeltaFormat {
		return stats, fmt.Errorf("delta %s: unsupported format %q (want %q)", deltaPath, header.Format, DeltaFormat)
	}

	// Parse all operations up front. Deltas are tiny relative to feeds, and
	// duplicate-id / unknown-op validation is much easier before streaming.
	ops := make(map[string]deltaOp)
	var order []string
	for {
		var op deltaOp
		if err := dec.Decode(&op); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return stats, fmt.Errorf("delta %s: reading operation %d: %w",
				deltaPath, len(order)+1, wrapTruncated(err))
		}
		switch op.Op {
		case opAdd, opUpdate, opRemove:
		default:
			return stats, fmt.Errorf("delta %s: operation %d has unknown op %q",
				deltaPath, len(order)+1, op.Op)
		}
		if op.ID == "" {
			return stats, fmt.Errorf("delta %s: operation %d has empty id", deltaPath, len(order)+1)
		}
		if op.Op != opRemove && len(op.Record) == 0 {
			return stats, fmt.Errorf("delta %s: %s op for %q has no record", deltaPath, op.Op, op.ID)
		}
		if _, dup := ops[op.ID]; dup {
			return stats, fmt.Errorf("delta %s: duplicate id %q in operations", deltaPath, op.ID)
		}
		ops[op.ID] = op
		order = append(order, op.ID)
	}
	if len(order) != header.Records {
		return stats, fmt.Errorf("delta %s: truncated: header lists %d operations, found %d",
			deltaPath, header.Records, len(order))
	}

	applied := make(map[string]bool, len(ops))

	// Single open of the base feed: every raw byte flows through the
	// tee'd hasher exactly once while records stream to the writer. The
	// digest is validated after the pass completes but before pass 2
	// emits any op-derived entries, so a mutated/mismatched base can
	// never produce accepted output (the atomic temp+rename discards it).
	bf, err := os.Open(basePath)
	if err != nil {
		return stats, fmt.Errorf("opening base feed: %w", err)
	}
	defer bf.Close()
	baseHash := sha256.New()
	baseBr := bufio.NewReaderSize(bf, 1<<20)

	err = writeFileAtomic(outPath, func(w io.Writer) error {
		if _, err := io.WriteString(w, "{\n"); err != nil {
			return err
		}
		first := true
		writeEntry := func(id string, raw json.RawMessage) error {
			if !first {
				if _, err := io.WriteString(w, ",\n"); err != nil {
					return err
				}
			}
			first = false
			kb, err := json.Marshal(id)
			if err != nil {
				return err
			}
			if _, err := w.Write(kb); err != nil {
				return err
			}
			if _, err := io.WriteString(w, ":"); err != nil {
				return err
			}
			_, err = w.Write(raw)
			return err
		}

		// Pass 1: stream the base, hashing its raw bytes and copying
		// untouched records verbatim.
		if err := streamFeedReader(io.TeeReader(baseBr, baseHash), basePath, func(id string, raw json.RawMessage) error {
			stats.BaseRecords++
			op, tracked := ops[id]
			if !tracked {
				stats.ResultRecords++
				return writeEntry(id, raw)
			}
			applied[id] = true
			switch op.Op {
			case opRemove:
				stats.Removed++
				return nil
			case opUpdate:
				stats.Updated++
				stats.ResultRecords++
				return writeEntry(id, op.Record)
			default: // add colliding with an existing base id
				return fmt.Errorf("add op for existing id %q", id)
			}
		}); err != nil {
			return err
		}
		// Drain bytes the JSON decoder never consumed (trailing
		// whitespace/newlines) so the digest covers the whole file.
		if _, err := io.Copy(baseHash, baseBr); err != nil {
			return err
		}
		if got := hex.EncodeToString(baseHash.Sum(nil)); got != header.BaseSHA256 {
			return errors.New("base file hash mismatch")
		}

		// Pass 2: append adds in operation order; report update/remove ops
		// whose ids were missing from the base.
		for _, id := range order {
			op := ops[id]
			if applied[id] {
				continue
			}
			if op.Op != opAdd {
				return fmt.Errorf("%s op references unknown id %q", op.Op, id)
			}
			stats.Added++
			stats.ResultRecords++
			applied[id] = true
			if err := writeEntry(id, op.Record); err != nil {
				return err
			}
		}

		if _, err := io.WriteString(w, "\n}\n"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return stats, fmt.Errorf("applying delta: %w", err)
	}

	if stats.ResultRecords != header.ResultRecords {
		return stats, fmt.Errorf("result record count mismatch: got %d, want %d",
			stats.ResultRecords, header.ResultRecords)
	}

	// Delta-v2 integrity check: when the header advertises a semantic
	// digest, verify the reconstructed feed's content — not just its
	// shape — against it. A mismatch means some op's record bytes were
	// corrupted or forged in a way the structural checks cannot see; the
	// output is removed so a rejected delta leaves nothing behind. v1
	// deltas carry no digest and skip this entirely.
	if header.ResultSemanticSHA256 != "" {
		got, err := semanticFeedDigest(outPath)
		if err != nil {
			return stats, fmt.Errorf("digesting result feed: %w", err)
		}
		if got != header.ResultSemanticSHA256 {
			os.Remove(outPath)
			return stats, fmt.Errorf("result feed semantic digest mismatch: got %s, want %s",
				got, header.ResultSemanticSHA256)
		}
	}
	return stats, nil
}

// loadFeed reads a whole feed into memory as id -> compacted raw JSON.
// An empty or whitespace-only file yields an empty map.
func loadFeed(path string) (map[string][]byte, error) {
	m := make(map[string][]byte)
	if err := streamFeed(path, func(id string, raw json.RawMessage) error {
		m[id] = compactJSON(raw)
		return nil
	}); err != nil {
		return nil, err
	}
	return m, nil
}

// streamFeed walks the feed file at path, invoking fn for every record
// with its outer key and raw JSON value. See streamFeedReader for the
// parsing rules.
func streamFeed(path string, fn func(id string, raw json.RawMessage) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return streamFeedReader(bufio.NewReaderSize(f, 1<<20), path, fn)
}

// streamFeedReader is streamFeed's core over an arbitrary reader. It
// mirrors db.Load's streaming approach: dec.Token() opens the object,
// dec.More() iterates entries, values are captured as json.RawMessage so
// callers see the original bytes.
//
// An empty or whitespace-only input is tolerated as a zero-record feed
// (useful when bootstrapping deltas from a missing snapshot); any other
// malformed input is an error. Note that bytes after the closing brace —
// and any read-ahead left in r — are NOT consumed; callers that need to
// account for every byte (e.g. hashers behind a TeeReader) must drain r
// themselves.
func streamFeedReader(r io.Reader, path string, fn func(id string, raw json.RawMessage) error) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil // empty input = empty feed
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("%s: unexpected feed root %v (want object)", path, tok)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("reading %s: record key: %w", path, err)
		}
		id, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("%s: non-string record key", path)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("reading %s: decoding record %q: %w", path, id, err)
		}
		if err := fn(id, raw); err != nil {
			return err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return fmt.Errorf("%s: feed object not terminated", path)
	}
	return nil
}

// compactJSON returns the whitespace-normalised form of raw for
// difference comparison. Compact preserves key order and number literals,
// so two records compare equal iff they differ by whitespace alone.
func compactJSON(raw json.RawMessage) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		// Decoder-produced RawMessage is always valid JSON; fall back to
		// the raw bytes rather than inventing a sentinel.
		return raw
	}
	return buf.Bytes()
}

// semanticFeedDigest returns the hex sha256 of the canonical semantic
// digest of the feed at path: for every record sorted by id, the bytes
//
//	id + "\x00" + json.Compact(record) + "\n"
//
// hashed in that order. The digest is order-insensitive by construction
// (records are sorted by id) and whitespace-insensitive (records are
// compacted), so it changes if and only if some record's content changes.
// ApplyDelta verifies a reconstructed feed against the digest its delta's
// header advertises; the sorted-and-compacted definition exists precisely
// because the reconstructed feed's byte layout differs from the source's
// (see deltaHeader).
//
// Memory: the compacted records of the whole feed are held in memory to
// enable the id sort — the same profile as loadFeed, which GenerateDelta
// already uses, so this does not change the package's memory envelope.
func semanticFeedDigest(path string) (string, error) {
	recs := make(map[string][]byte)
	if err := streamFeed(path, func(id string, raw json.RawMessage) error {
		recs[id] = compactJSON(raw)
		return nil
	}); err != nil {
		return "", err
	}
	ids := make([]string, 0, len(recs))
	for id := range recs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		if _, err := io.WriteString(h, id); err != nil {
			return "", err
		}
		h.Write([]byte{0})
		h.Write(recs[id])
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileSHA256 streams path through crypto/sha256 and returns the hex
// digest of the raw file bytes.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeJSONL writes the header followed by one operation per line. Each
// Encode call appends exactly one newline, producing valid JSON lines.
func writeJSONL(w io.Writer, header deltaHeader, ops []deltaOp) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(header); err != nil {
		return err
	}
	for _, op := range ops {
		if err := enc.Encode(op); err != nil {
			return err
		}
	}
	return nil
}

// writeFileAtomic writes path via a temporary file in the same directory
// and renames it into place, so a failed run never leaves a partial
// artifact behind.
func writeFileAtomic(path string, write func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onyx-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	bw := bufio.NewWriterSize(tmp, 1<<20)
	if err := write(bw); err != nil {
		return fail(err)
	}
	if err := bw.Flush(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// wrapTruncated labels unexpected end-of-input errors so truncated delta
// files produce a clear message instead of a bare syntax error.
func wrapTruncated(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("truncated delta: %w", err)
	}
	return err
}
