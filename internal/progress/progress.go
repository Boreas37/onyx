// Package progress renders live scan status to stderr. When the output is a
// terminal a single updating line is drawn with \r (no trailing newlines).
// When the output is a pipe or log file no control characters are emitted;
// explicit [INF] log lines provide feedback instead. A silent bar renders
// nothing at all, leaving the scan result as the only output.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bar tracks scan state and renders it on demand. All update methods are
// safe for concurrent use from the scan worker pool.
type Bar struct {
	silent bool
	out    io.Writer
	tty    bool
	start  time.Time

	total    atomic.Int64
	done     atomic.Int64
	findings atomic.Int64
	current  atomic.Value // string

	pad    int // width of the last drawn progress line
	mu     sync.Mutex
	lastSh time.Time // last throttle window start
}

// renderThrottle is the minimum interval between live progress redraws.
// It is a variable so tests can disable throttling (set to 0).
var renderThrottle = 80 * time.Millisecond

// New returns a Bar writing to out. silent suppresses all output.
func New(out io.Writer, silent bool) *Bar {
	return &Bar{silent: silent, out: out, tty: isTTY(out), start: time.Now()}
}

// isTTY reports whether w is a terminal (character device). Pipes, buffers
// and files are not.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// SetTotal fixes the total number of tracked requests.
func (b *Bar) SetTotal(n int64) {
	b.total.Store(n)
	b.render()
}

// AddTotal grows the total when enumeration scope is discovered later.
func (b *Bar) AddTotal(n int64) {
	if n <= 0 {
		return
	}
	b.total.Add(n)
	b.render()
}

// AddDone counts n completed requests.
func (b *Bar) AddDone(n int64) {
	b.done.Add(n)
	b.render()
}

// SetFindings reports the current number of matched findings.
func (b *Bar) SetFindings(n int64) {
	b.findings.Store(n)
	b.render()
}

// SetCurrent labels the item currently being enumerated.
func (b *Bar) SetCurrent(label string) {
	b.current.Store(label)
	b.render()
}

// line renders the one-line progress status without any newlines.
func (b *Bar) line() string {
	elapsed := time.Since(b.start).Round(time.Second).String()
	total := b.total.Load()
	done := b.done.Load()

	// Simple percentage bar — no per-request labels, just progress.
	const barWidth = 30
	frac := 0.0
	if total > 0 {
		frac = float64(done) / float64(total)
		if frac > 1 {
			frac = 1
		}
	}
	filled := int(frac * barWidth)
	bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)

	label := fmt.Sprintf("[%s] %3d%%", bar, int(frac*100))
	if total > 0 {
		label += fmt.Sprintf(" %d/%d", done, total)
	}
	line := label + " " + elapsed
	if total > 0 && done > 0 {
		elapsedDur := time.Since(b.start)
		remaining := elapsedDur * time.Duration(total-done) / time.Duration(done)
		line += " ETA " + remaining.Round(time.Second).String()
	}
	return line
}

func (b *Bar) render() {
	if b.silent || !b.tty {
		return
	}
	// Throttle redraws: with a fast worker pool (5-20 threads) the bar would
	// otherwise redraw for every request, which some terminals render as a
	// flood of lines. Redraw at most ~12 times per second and always make
	// the final state visible when Finish is called.
	b.mu.Lock()
	if time.Since(b.lastSh) < renderThrottle {
		b.mu.Unlock()
		return
	}
	b.lastSh = time.Now()
	b.mu.Unlock()

	line := b.line()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pad >= len(line) {
		fmt.Fprintf(b.out, "\r%s%s", line, strings.Repeat(" ", b.pad-len(line)))
	} else {
		fmt.Fprint(b.out, "\r"+line)
	}
	b.pad = len(line)
}

// LogInf prints a nuclei-style [INF] log line, clearing any in-flight
// progress line first on a TTY.
func (b *Bar) LogInf(format string, args ...any) {
	if b.silent {
		return
	}
	b.mu.Lock()
	if b.tty && b.pad > 0 {
		fmt.Fprintf(b.out, "\r%s\r", strings.Repeat(" ", b.pad))
		b.pad = 0
	}
	fmt.Fprintf(b.out, "[INF] "+format+"\n", args...)
	b.mu.Unlock()
	b.render()
}

// Finish marks all work complete and erases the progress line on a TTY.
func (b *Bar) Finish() {
	b.done.Store(b.total.Load())
	if b.silent || !b.tty {
		return
	}
	// Force a final redraw so the completed state is visible even if the
	// last render was throttled, then erase the line.
	b.mu.Lock()
	line := b.line()
	if b.pad >= len(line) {
		fmt.Fprintf(b.out, "\r%s%s", line, strings.Repeat(" ", b.pad-len(line)))
	} else {
		fmt.Fprint(b.out, "\r"+line)
	}
	b.pad = len(line)
	fmt.Fprintf(b.out, "\r%s\r", strings.Repeat(" ", b.pad))
	b.pad = 0
	b.mu.Unlock()
}
