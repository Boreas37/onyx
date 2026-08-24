// Command onyx-deltagen generates an onyx-delta-v1 changeset between two
// Wordfence feed snapshots. The mirror (onyx-db) uses it in its daily
// update job so onyx clients can patch their local database instead of
// re-downloading the full feed.
//
// Usage:
//
//	onyx-deltagen -old <base.json> -new <current.json> -out <delta.json.gz>
//
// Both inputs are uncompressed feed JSON files; the delta is written as a
// gzipped JSON-lines document whose header carries the SHA-256 of the base
// file exactly as passed here, plus the optional v2 semantic digest of the
// new feed (result_semantic_sha256), which ApplyDelta verifies against the
// reconstructed feed. Statistics are printed to stdout as JSON:
//
//	{"added":3,"removed":1,"updated":12,"base_records":38884,"result_records":38898}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Boreas37/onyx/internal/dbupdate"
)

func main() {
	oldPath := flag.String("old", "", "path to the base feed (uncompressed JSON)")
	newPath := flag.String("new", "", "path to the current feed (uncompressed JSON)")
	outPath := flag.String("out", "", "path of the delta file to write (.json.gz)")
	flag.Parse()
	if *oldPath == "" || *newPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: onyx-deltagen -old base.json -new current.json -out delta.json.gz")
		os.Exit(2)
	}
	st, err := dbupdate.GenerateDelta(*oldPath, *newPath, *outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deltagen:", err)
		os.Exit(1)
	}
	out := struct {
		Added         int `json:"added"`
		Removed       int `json:"removed"`
		Updated       int `json:"updated"`
		BaseRecords   int `json:"base_records"`
		ResultRecords int `json:"result_records"`
	}{
		Added:         st.Added,
		Removed:       st.Removed,
		Updated:       st.Updated,
		BaseRecords:   st.BaseRecords,
		ResultRecords: st.ResultRecords,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "deltagen:", err)
		os.Exit(1)
	}
}
