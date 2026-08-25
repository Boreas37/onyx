// Package pocs — reader.go
//
// Raw PoC fetching for pocgen: reads the first usable file from a PoC
// repository via raw.githubusercontent.com. The tracker itself only stores
// links, not code — so this fetches the linked repo's README + common
// exploit filenames. All failures are soft (empty string, no error) so
// pocgen can fall back to link-only mode.
package pocs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxRawBytes caps a single raw file download so a hostile repo cannot
// exhaust memory. PoCs are small Python/PHP/JS scripts.
const maxRawBytes = 1 << 16 // 64 KiB

// commonPoCFiles are tried in order after README.md. The first that
// returns 200 is used. Names are case-sensitive as on GitHub.
var commonPoCFiles = []string{
	"exploit.py",
	"poc.py",
	"exploit.sh",
	"poc.php",
	"exploit.php",
	"PoC.py",
	"README.md",
}

// rawClient is a 15s-timeout client for raw GitHub fetches. Reused across
// calls so keep-alives are shared.
var rawClient = &http.Client{Timeout: 15 * time.Second}

// FetchRawPoC fetches the first usable PoC file from pocURL (a
// https://github.com/owner/repo link). It tries main then master branch
// for each candidate file. On any network error or 404 it continues to
// the next candidate; when nothing is found it returns ("", nil) so
// callers can degrade gracefully.
func FetchRawPoC(ctx context.Context, pocURL string) (string, error) {
	ownerRepo := repoPath(pocURL)
	if ownerRepo == "" {
		return "", fmt.Errorf("not a github repo URL: %s", pocURL)
	}
	// Prefer README.md first, then common exploit filenames.
	candidates := append([]string{"README.md"}, commonPoCFiles...)
	seen := make(map[string]bool)
	for _, file := range candidates {
		if seen[file] {
			continue
		}
		seen[file] = true
		for _, branch := range []string{"main", "master"} {
			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", ownerRepo, branch, file)
			body, err := fetchRaw(ctx, rawURL)
			if err != nil {
				continue
			}
			if strings.TrimSpace(body) != "" {
				return body, nil
			}
		}
	}
	return "", nil
}

// fetchRaw GETs url with ctx and returns the body as string, capped at
// maxRawBytes. Non-200 is treated as not found.
func fetchRaw(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "onyx")
	resp, err := rawClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRawBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
