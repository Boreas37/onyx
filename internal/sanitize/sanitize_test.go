package sanitize

import (
	"strings"
	"testing"
)

func TestTextStripsControlChars(t *testing.T) {
	in := "ok\x1b[31mANSI\x1b[0m\nnewline\ttab\x00null\x7fdel\xc2\x9bc1"
	got := Text(in, 200)
	for _, r := range got {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			t.Fatalf("control char %q survived: %q", r, got)
		}
	}
	if strings.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("line breaks survived: %q", got)
	}
}

func TestTextCapsRunes(t *testing.T) {
	in := strings.Repeat("é", 500)
	got := Text(in, 64)
	if len([]rune(got)) != 64 {
		t.Fatalf("cap = %d runes, want 64", len([]rune(got)))
	}
}

func TestTextKeepsPrintable(t *testing.T) {
	const in = "Contact Form 7 <= 6.0.5 — Order Replay (CVE-2025-3247)"
	if got := Text(in, 200); got != in {
		t.Fatalf("printable text mangled: %q", got)
	}
}

func FuzzText(f *testing.F) {
	f.Add("normal 1.2.3", 64)
	f.Add("\x1b[31mred\x1b[0m", 10)
	f.Add(strings.Repeat("A", 1000), 8)
	f.Add("", 5)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1<<20 {
			max = 64
		}
		got := Text(s, max)
		if len([]rune(got)) > max {
			t.Fatalf("output %d runes exceeds cap %d", len([]rune(got)), max)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
				t.Fatalf("control char %q survived: %q", r, got)
			}
		}
	})
}
