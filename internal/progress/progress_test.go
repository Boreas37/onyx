package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestNonTTYNoProgressCarriage verifies that a non-terminal output never
// receives \r progress escapes — only plain [INF] log lines.
func TestNonTTYNoProgressCarriage(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf, false)
	if b.tty {
		t.Fatal("bytes.Buffer must not be detected as a TTY")
	}
	b.SetTotal(200)
	b.AddDone(12)
	b.SetFindings(2)
	b.SetCurrent("plugin:elementor readme.txt")
	b.LogInf("detected WordPress 6.4.2 at https://example.com")
	b.Finish()

	got := buf.String()
	if strings.Contains(got, "\r") {
		t.Errorf("non-TTY output must not contain \\r: %q", got)
	}
	if !strings.Contains(got, "[INF] detected WordPress 6.4.2 at https://example.com") {
		t.Errorf("expected [INF] log line, got %q", got)
	}
}

// TestSilentSuppressesEverything verifies that a silent bar emits nothing,
// neither progress escapes nor [INF] log lines.
func TestSilentSuppressesEverything(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf, true)
	b.SetTotal(1)
	b.AddDone(1)
	b.SetFindings(1)
	b.SetCurrent("plugin:elementor readme.txt")
	b.LogInf("hello")
	b.Finish()
	if buf.Len() != 0 {
		t.Errorf("silent bar must emit no output, got %q", buf.String())
	}
}

// TestTTYRenderSingleLine forces terminal rendering and checks the live
// single-line format: counter, current item, findings and elapsed time.
func TestTTYRenderSingleLine(t *testing.T) {
	renderThrottle = 0 // disable throttling for deterministic output
	defer func() { renderThrottle = 80 * time.Millisecond }()

	var buf bytes.Buffer
	b := New(&buf, false)
	b.tty = true // white-box: force the terminal code path

	b.SetTotal(200)
	b.AddDone(12)
	b.SetFindings(2)
	b.SetCurrent("plugin:elementor readme.txt (3.24.0)")

	got := buf.String()
	for _, want := range []string{"%", "12/200", "0s"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress line missing %q: %q", want, got)
		}
	}
	// The live line must be a percentage bar, not a per-request label flood.
	if strings.Contains(got, "plugin:elementor") {
		t.Errorf("bar must not embed per-request labels: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("progress render must stay on a single line: %q", got)
	}
	if !strings.HasPrefix(got, "\r") {
		t.Errorf("progress line must start with \\r: %q", got)
	}

	b.Finish()
	if !strings.HasSuffix(buf.String(), "\r") {
		t.Errorf("Finish must erase the progress line: %q", buf.String())
	}
}

// TestTTYInfClearsLine verifies an [INF] log on a TTY erases the in-flight
// progress line before printing, then redraws it.
func TestTTYInfClearsLine(t *testing.T) {
	renderThrottle = 0 // disable throttling for deterministic output
	defer func() { renderThrottle = 80 * time.Millisecond }()

	var buf bytes.Buffer
	b := New(&buf, false)
	b.tty = true

	b.AddTotal(10)
	b.LogInf("scan started")

	got := buf.String()
	if !strings.Contains(got, "[INF] scan started") {
		t.Errorf("expected INF log, got %q", got)
	}
	if !strings.Contains(got, "0/10") {
		t.Errorf("expected progress redraw after INF log, got %q", got)
	}
}

// TestLineETAAppendsAfterElapsed verifies line() appends a rounded
// remaining-time estimate once work is in progress, and omits it when there
// is no total or nothing done yet.
func TestLineETAAppendsAfterElapsed(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		total   int64
		done    int64
		elapsed time.Duration
		wantETA bool
	}{
		{"no total", 0, 5, 2 * time.Minute, false},
		{"nothing done", 100, 0, 2 * time.Minute, false},
		{"in progress", 500, 100, 2 * time.Minute, true},
		{"complete", 500, 500, 2 * time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New(&bytes.Buffer{}, true)
			b.start = now.Add(-tt.elapsed)
			b.total.Store(tt.total)
			b.done.Store(tt.done)
			got := b.line()
			if has := strings.Contains(got, " ETA "); has != tt.wantETA {
				t.Fatalf("line() = %q, ETA present = %v, want %v", got, has, tt.wantETA)
			}
		})
	}
}

// TestLineETAPrefixUntouched pins the exact ETA value and proves the
// existing prefix (bar, percent, count, elapsed) is left unchanged.
func TestLineETAPrefixUntouched(t *testing.T) {
	b := New(&bytes.Buffer{}, true)
	b.start = time.Now().Add(-12 * time.Second)
	b.total.Store(500)
	b.done.Store(252)

	wantPrefix := "[###############---------------]  50% 252/500 12s"
	got := b.line()
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("line() = %q, want prefix %q", got, wantPrefix)
	}
	// 12s elapsed at 252/500 done -> 12*248/252 ≈ 12s remaining.
	if !strings.Contains(got, " ETA 12s") {
		t.Fatalf("line() = %q, want ETA 12s suffix", got)
	}
}
