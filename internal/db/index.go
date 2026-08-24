package db

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Boreas37/onyx/internal/version"
)

// SaveIndex writes a pre-built index of the loaded DB d as <path>.idx,
// next to the source feed at path (e.g. data/wordfence.json.idx for
// data/wordfence.json). The index is a gob stream — see indexFile for the
// exact layout. It is safe to write over an existing sidecar; the write is
// atomic (temp file + rename), so readers only ever observe a complete
// file.
//
// The sidecar records the sha256 of the source feed's raw bytes at save
// time; LoadCached re-hashes the feed and refuses the sidecar when the
// digests differ, so a stale index can never be served for content it was
// not built from. The index is a pure cache: losing or corrupting it costs
// a full Load, never correctness.
func SaveIndex(path string, d *DB) error {
	sha, err := fileSHA256(path)
	if err != nil {
		return fmt.Errorf("hashing source feed: %w", err)
	}
	f := indexFile{Version: indexFormatVersion, SourceSHA: sha, Skipped: d.skipped}
	f.Records = make([]indexVuln, 0, len(d.Records))
	for i := range d.Records {
		rec := &d.Records[i]
		iv := indexVuln{
			ID:            rec.ID,
			Title:         rec.Title,
			Informational: rec.Informational,
			Description:   rec.Description,
			CVE:           rec.CVE,
			CVSS:          rec.CVSS,
			PublishedAt:   rec.PublishedAt,
			Software:      make([]indexSoftware, 0, len(rec.Software)),
		}
		for j := range rec.Software {
			sw := &rec.Software[j]
			is := indexSoftware{
				Type:             sw.Type,
				Name:             sw.Name,
				Slug:             sw.Slug,
				Patched:          sw.Patched,
				PatchedVersions:  sw.PatchedVersions,
				Remediation:      sw.Remediation,
				AffectedVersions: make(map[string]indexAffectedVersion, len(sw.AffectedVersions)),
			}
			for label, av := range sw.AffectedVersions {
				iav := indexAffectedVersion{Label: av.Label, Ranges: make([]indexRange, 0, len(av.Ranges))}
				for _, r := range av.Ranges {
					ir := indexRange{FromIncl: r.FromIncl, ToIncl: r.ToIncl, Label: r.Label}
					if r.From != nil {
						ir.From = r.From.Raw()
					}
					if r.To != nil {
						ir.To = r.To.Raw()
					}
					iav.Ranges = append(iav.Ranges, ir)
				}
				is.AffectedVersions[label] = iav
			}
			iv.Software = append(iv.Software, is)
		}
		f.Records = append(f.Records, iv)
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(f); err != nil {
		return fmt.Errorf("encoding index: %w", err)
	}
	if err := writeFileAtomic(path+".idx", buf.Bytes()); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	return nil
}

// LoadCached loads the feed at path, preferring the pre-built index
// sidecar at <path>.idx written by SaveIndex. It is the fast entry point
// for callers that already have the feed on disk (the canonical loader
// Load remains unchanged and is what every cache miss falls back to).
//
// Semantics:
//
//   - when <path>.idx exists, is a valid index, and its recorded source
//     sha256 matches the current bytes of <path> while the sidecar's
//     mtime is not older than the feed's, it is deserialized and returned,
//     skipping the full JSON re-parse;
//   - in every other case — no sidecar, stale or corrupt sidecar, unknown
//     format version, or source-hash mismatch — LoadCached calls
//     Load(path) and, best-effort, refreshes the sidecar via SaveIndex;
//   - the cache path NEVER produces an error: only Load's own errors
//     (missing or malformed feed) surface. A cache miss silently degrades
//     to a full load.
func LoadCached(path string) (*DB, error) {
	if idx, err := readIndexFile(path); err == nil {
		return rebuildFromIndex(idx, path)
	}
	d, err := Load(path)
	if err != nil {
		return nil, err
	}
	// Best-effort refresh: an unwritable directory or a racing writer must
	// never turn a successful load into a failure.
	if err := SaveIndex(path, d); err != nil {
		// Not a failure: the sidecar is optional.
		_ = err
	}
	return d, nil
}

// indexFile is the gob-serialized payload of a pre-built database index
// sidecar. Only exported fields are stored because encoding/gob cannot
// encode unexported fields — and the in-memory DB is NOT gob-safe as a
// whole, since AffectedVersion holds []version.Range whose version.Version
// internals (parts, raw) are unexported. This gob-friendly mirror is what
// makes the sidecar serializable.
//
// Layout (version 1):
//
//	version    format version, currently indexFormatVersion. Unknown
//	           versions are rejected at load so future layout changes can
//	           never silently mis-decode.
//	source_sha hex sha256 of the source feed's bytes at SaveIndex time;
//	           LoadCached re-hashes <path> and refuses the sidecar on
//	           mismatch, so the index cannot be replayed against feed
//	           content it was not built from.
//	skipped    the loader's skipped-record count, preserved so Skipped()
//	           round-trips through the cache.
//	records    the loaded records, in feed order.
type indexFile struct {
	Version   int
	SourceSHA string
	Skipped   int
	Records   []indexVuln
}

// indexVuln is the gob-safe mirror of Vuln. CVSS is entirely exported, so
// it is reused directly instead of being mirrored.
type indexVuln struct {
	ID            string
	Title         string
	Software      []indexSoftware
	Informational bool
	Description   string
	CVE           string
	CVSS          CVSS
	PublishedAt   string
}

// indexSoftware is the gob-safe mirror of Software.
type indexSoftware struct {
	Type             string
	Name             string
	Slug             string
	AffectedVersions map[string]indexAffectedVersion
	Patched          bool
	PatchedVersions  []string
	Remediation      string
}

// indexAffectedVersion is the gob-safe mirror of AffectedVersion.
type indexAffectedVersion struct {
	Label  string
	Ranges []indexRange
}

// indexRange is the gob-safe mirror of one version.Range. From/To are the
// raw endpoint version strings ("" when unbounded); rebuildFromIndex feeds
// them back through structRange — the exact inverse of how Load built the
// range — so the reconstructed range is identical, including the unexported
// internals of version.Version.
//
// Range labels alone would be lossy here: a range derived from the feed's
// structured from_version/to_version fields carries an EMPTY
// version.Range.Label (structRange never sets it), so re-parsing the
// affected-version label cannot reconstruct those ranges. Storing the
// endpoints themselves handles both shapes uniformly.
type indexRange struct {
	From     string
	To       string
	FromIncl bool
	ToIncl   bool
	Label    string
}

// indexFormatVersion is the indexFile layout version written by SaveIndex.
const indexFormatVersion = 1

// readIndexFile validates and decodes the sidecar for path. It returns an
// error — a cache miss — on ANY problem: missing file, corrupt payload,
// unknown format version, a sidecar older than the feed, or a recorded
// source hash that disagrees with the feed's current bytes. Callers treat
// every error identically and fall back to Load.
//
// The mtime comparison is only a cheap pre-filter: it is evaluated before
// the (expensive) full-file re-hash so a sidecar that is obviously stale
// costs nothing. The stored source hash is the authoritative freshness
// check; mtime alone is trusted for nothing (it is trivially touchable and
// coarse on some filesystems).
func readIndexFile(path string) (*indexFile, error) {
	idxPath := path + ".idx"
	dataInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	idxInfo, err := os.Stat(idxPath)
	if err != nil {
		return nil, err
	}
	if idxInfo.ModTime().Before(dataInfo.ModTime()) {
		return nil, fmt.Errorf("index %s is older than its source %s", idxPath, path)
	}
	f, err := os.Open(idxPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var idx indexFile
	if err := gob.NewDecoder(f).Decode(&idx); err != nil {
		return nil, fmt.Errorf("decoding index %s: %w", idxPath, err)
	}
	if idx.Version != indexFormatVersion {
		return nil, fmt.Errorf("index %s: unsupported format version %d", idxPath, idx.Version)
	}
	sha, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	if idx.SourceSHA != sha {
		return nil, fmt.Errorf("index %s: source hash mismatch", idxPath)
	}
	return &idx, nil
}

// rebuildFromIndex reconstructs a DB from a validated index payload and
// runs the same finalize pass Load uses, so the slug index, top-slug
// ordering and lookup semantics are identical to a fresh load. Records
// that were skipped at load time are not in the index and stay absent.
//
// A range that cannot be rebuilt from its stored endpoints means the
// sidecar is corrupt — every range was valid when SaveIndex wrote it — so
// the whole cache is rejected and the caller falls back to Load.
func rebuildFromIndex(idx *indexFile, path string) (*DB, error) {
	d := &DB{Path: path, skipped: idx.Skipped}
	d.Records = make([]Vuln, 0, len(idx.Records))
	for i := range idx.Records {
		iv := &idx.Records[i]
		rec := Vuln{
			ID:            iv.ID,
			Title:         iv.Title,
			Informational: iv.Informational,
			Description:   iv.Description,
			CVE:           iv.CVE,
			CVSS:          iv.CVSS,
			PublishedAt:   iv.PublishedAt,
			Software:      make([]Software, 0, len(iv.Software)),
		}
		for j := range iv.Software {
			is := &iv.Software[j]
			sw := Software{
				Type:             is.Type,
				Name:             is.Name,
				Slug:             is.Slug,
				Patched:          is.Patched,
				PatchedVersions:  is.PatchedVersions,
				Remediation:      is.Remediation,
				AffectedVersions: make(map[string]AffectedVersion, len(is.AffectedVersions)),
			}
			for label, iav := range is.AffectedVersions {
				av := AffectedVersion{Label: iav.Label, Ranges: make([]version.Range, 0, len(iav.Ranges))}
				for _, ir := range iav.Ranges {
					rng, ok := structRange(ir.From, ir.To, ir.FromIncl, ir.ToIncl)
					if !ok {
						return nil, fmt.Errorf("index %s.idx: corrupt range for %q", path, label)
					}
					rng.Label = ir.Label
					av.Ranges = append(av.Ranges, rng)
				}
				sw.AffectedVersions[label] = av
			}
			rec.Software = append(rec.Software, sw)
		}
		d.Records = append(d.Records, rec)
	}
	finalize(d)
	return d, nil
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

// writeFileAtomic writes data to path via a temp file in the same
// directory and a rename into place, so a failed save never leaves a
// partial or corrupt sidecar behind and readers only ever observe
// complete files.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onyx-idx-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
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
