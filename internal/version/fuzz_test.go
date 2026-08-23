package version

import (
	"strings"
	"testing"
)

// maxSegmentFuzz mirrors the documented Parse component cap (maxSegment,
// 18 digits): any successfully parsed part must be non-negative and below
// 10^18. Note this is the tightest bound consistent with Parse's contract
// of accepting exactly-18-digit components; nothing larger can ever parse.
const maxSegmentFuzz = 999_999_999_999_999_999

// FuzzParse checks Parse's core invariants for arbitrary input:
//
//   - ok implies every parsed part is within [0, maxSegment] (no overflow
//     wrap-around can survive into a Version);
//   - Compare is antisymmetric;
//   - appending a ".0" segment to a purely numeric version never changes
//     how it compares (zero-padding equivalence).
func FuzzParse(f *testing.F) {
	seeds := []string{
		"18446744073709551616",
		"99999999999999999999.1",
		"999999999999999999",
		"1.18446744073709551616",
		"[*, 3.7)",
		"*-1.37",
		"0.1-0.9",
		"1.2.3-beta",
		"<= 2.0",
		"> 1.5",
		"[1.0,2.0]",
		"1.0 - *",
		"1.0-*",
		"1.",
		"v3.24.9",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	partner := testVersionMust("1.2.0")
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := Parse(s)
		if !ok {
			return
		}
		for _, p := range v.parts {
			if p < 0 || p > maxSegmentFuzz {
				t.Fatalf("Parse(%q): part %d outside [0, maxSegment]", s, p)
			}
		}
		if c := v.Compare(partner); c != -partner.Compare(v) {
			t.Fatalf("Compare not antisymmetric for %q: %d vs %d", s, c, -partner.Compare(v))
		}
		if isPlainNumeric(s) {
			padded, ok2 := Parse(s + ".0")
			if !ok2 {
				t.Fatalf("Parse(%q) ok but Parse(%q) failed", s, s+".0")
			}
			if v.Compare(padded) != 0 {
				t.Fatalf("%q should compare equal to its zero-padded form", s)
			}
		}
	})
}

// FuzzInAffected checks that InAffected never panics and honors its
// fail-closed contract: an invalid label or an unparseable installed
// version never matches, while an empty label matches every parseable
// version.
func FuzzInAffected(f *testing.F) {
	seeds := [][2]string{
		{"", "1.0"},
		{"<= 100", "18446744073709551616"},
		{"*-50", "18446744073709551616"},
		{"[1.0, 2.0, junk]", "1.5"},
		{"garbage", "1.0.0"},
		{"1.0.0 - 3.24.9", "unknown"},
		{"*-1.37", "1.36.2"},
		{"[*, 3.7)", "3.6.1"},
		{"0.1-0.9", "0.5"},
		{"1.0-*", "5.0"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, label, installed string) {
		got := InAffected(label, installed)
		ranges, err := ParseRanges(label)
		if err != nil {
			if got {
				t.Fatalf("InAffected(%q, %q)=true but label failed to parse", label, installed)
			}
			return
		}
		v, ok := Parse(installed)
		if !ok {
			if got {
				t.Fatalf("InAffected(%q, %q)=true but installed failed to parse", label, installed)
			}
			return
		}
		if strings.TrimSpace(label) == "" && !got {
			t.Fatalf("empty label must match parseable version %q", installed)
		}
		if want := InRanges(ranges, v); got != want {
			t.Fatalf("InAffected(%q, %q)=%v inconsistent with InRanges=%v", label, installed, got, want)
		}
	})
}

// testVersionMust is testVersion without *testing.T plumbing so fuzz
// targets can build fixed reference versions.
func testVersionMust(s string) Version {
	v, ok := Parse(s)
	if !ok {
		panic("testVersionMust: fixed seed " + s + " does not parse")
	}
	return v
}

// isPlainNumeric reports whether s consists solely of non-empty digit
// groups separated by single dots (no leading/trailing dot), i.e. the
// shape for which appending ".0" is exact zero-padding under Parse's rules.
func isPlainNumeric(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	prev := byte('.')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c == '.':
			if prev == '.' {
				return false
			}
		default:
			return false
		}
		prev = c
	}
	return true
}
