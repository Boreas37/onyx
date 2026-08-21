package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Boreas37/onyx/internal/scanner"
)

// Options configures Run.
type Options struct {
	StateDir string       // directory holding per-target state files
	Webhook  string       // optional webhook URL notified on non-empty diffs
	Client   *http.Client // optional HTTP client for the webhook
}

// stateFileName maps a target URL to its state file name: the first 16 hex
// characters of the SHA-256 of the URL, plus ".json".
func stateFileName(target string) string {
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:])[:16] + ".json"
}

// Run performs one watch-mode iteration for target against the scan result
// res: it loads the previous state (a missing file means an empty baseline,
// so every finding is reported as new), builds the diff, saves the updated
// state and, when opts.Webhook is set and the diff is non-empty, posts the
// diff to the webhook. It returns the diff.
func Run(target string, res *scanner.Result, opts Options, now time.Time) (*Diff, error) {
	if err := os.MkdirAll(opts.StateDir, 0o755); err != nil {
		return nil, fmt.Errorf("watch: create state dir: %w", err)
	}
	path := filepath.Join(opts.StateDir, stateFileName(target))

	prev, err := LoadState(path)
	switch {
	case err == nil:
	case errors.Is(err, ErrNoState):
		prev = &State{Target: target, Baseline: make(map[string]map[string]bool)}
	default:
		return nil, err
	}

	d := DiffStates(prev, res, now)
	if d.Target == "" {
		d.Target = target
	}

	if err := SaveState(path, BuildState(target, res, now)); err != nil {
		return d, err
	}
	if opts.Webhook != "" && !d.Empty() {
		if err := Notify(opts.Webhook, d, opts.Client); err != nil {
			return d, err
		}
	}
	return d, nil
}
