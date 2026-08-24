package dbupdate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultManifestTimeout bounds FetchManifest when no client is supplied.
const DefaultManifestTimeout = 30 * time.Second

// maxManifestSize caps how much of a manifest response is read; manifests
// are small JSON documents, so anything near this bound is hostile or
// broken and fails parsing anyway.
const maxManifestSize = 4 << 20 // 4MiB

// Manifest is the mirror's advertisement of currently available database
// artifacts.
//
//	expected shape:
//	{
//	  "generated_at": "2026-08-21T04:00:00Z",
//	  "full": {"sha256": "<hex>", "size": 158334981, "path": "wordfence-latest.json.gz"},
//	  "deltas": [
//	    {"from_sha256": "<hex>", "path": "delta-<hex>.json.gz",
//	     "records": {"added": 3, "removed": 1, "updated": 12, "result": 39871}}
//	  ]
//	}
//
// full.sha256 is the digest of the GZIPPED artifact bytes at full.path —
// the same value a client stores in its dst+".sha256" sidecar after a
// download, making that sidecar an upstream artifact pointer rather than
// a digest of the local decompressed database. Each delta's from_sha256
// pins it to the exact base snapshot it patches, keyed by the same
// compressed-artifact digest; the delta file itself separately carries
// base_sha256 = sha256 of the DECOMPRESSED base feed, which ApplyDelta
// enforces.
type Manifest struct {
	GeneratedAt string       `json:"generated_at"`
	Full        FullEntry    `json:"full"`
	Deltas      []DeltaEntry `json:"deltas"`
}

// FullEntry describes the current complete feed snapshot.
type FullEntry struct {
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
}

// DeltaEntry describes one delta file that patches a specific prior
// snapshot into the current one.
type DeltaEntry struct {
	FromSha256 string      `json:"from_sha256"`
	Path       string      `json:"path"`
	Records    DeltaCounts `json:"records"`
}

// DeltaCounts holds the per-delta operation counts advertised by the
// mirror. Result is the record count of the reconstructed feed (the delta
// header's result_records).
type DeltaCounts struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Updated int `json:"updated"`
	Result  int `json:"result"`
}

// ParseManifest decodes a Manifest document from raw JSON bytes. It is
// the shared parser behind FetchManifest and is exported so callers with
// the body already in hand (tests, cached copies) reuse identical
// validation.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}

// FetchManifestRaw GETs url and returns the raw manifest bytes, subject to
// the same size cap and error handling as FetchManifest. It is the
// transport layer that FetchManifest builds on, exported so callers that
// want to verify the manifest's signature (VerifyManifest) or cache its
// raw body can fetch exactly the bytes that were advertised without a
// parse-then-re-encode round trip. A nil client gets a default one with a
// 30s timeout; any non-200 status is an error and the response body is
// size-capped defensively.
func FetchManifestRaw(client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: DefaultManifestTimeout}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching manifest: unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return body, nil
}

// FetchManifest GETs url and decodes the Manifest document. It is the raw
// fetch of FetchManifestRaw followed by ParseManifest; a nil client gets a
// default one with a 30s timeout. Any non-200 status or malformed body is
// an error; the response body is size-capped defensively.
func FetchManifest(client *http.Client, url string) (*Manifest, error) {
	body, err := FetchManifestRaw(client, url)
	if err != nil {
		return nil, err
	}
	return ParseManifest(body)
}
