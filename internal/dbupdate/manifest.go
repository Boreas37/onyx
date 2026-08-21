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
// full.sha256 is the digest of the artifact at full.path (after
// decompression for .gz feeds). Each delta's from_sha256 pins it to the
// exact base snapshot it patches — the same value a delta file carries in
// its own header as base_sha256.
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

// FetchManifest GETs url and decodes the Manifest document. A nil client
// gets a default one with a 30s timeout. Any non-200 status or malformed
// body is an error; the response body is size-capped defensively.
func FetchManifest(client *http.Client, url string) (*Manifest, error) {
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
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}
