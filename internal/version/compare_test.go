package version

import "testing"

func testVersion(t *testing.T, s string) Version {
	t.Helper()
	v, ok := Parse(s)
	if !ok {
		t.Fatalf("Parse(%q) unexpectedly failed", s)
	}
	return v
}

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		parts []int
	}{
		{"1.2.3", true, []int{1, 2, 3}},
		{"3.24.9", true, []int{3, 24, 9}},
		{"1.0", true, []int{1, 0}},
		{"0.1", true, []int{0, 1}},
		{"0.10.210305", true, []int{0, 10, 210305}},
		{"1.0.0.85", true, []int{1, 0, 0, 85}},
		{"v1.2.3", true, []int{1, 2, 3}},
		{"V1.2.3", true, []int{1, 2, 3}},
		{"1.2.3-beta", true, []int{1, 2, 3}},
		{"1.2.3-beta.1", true, []int{1, 2, 3}},
		{" 2.0 ", true, []int{2, 0}},
		{"1.2.3b", true, []int{1, 2, 3}},
		{"2", true, []int{2}},
		{"", false, nil},
		{"abc", false, nil},
		{"-1.2", false, nil},
		{".", false, nil},
		{"..", false, nil},

		// Trailing-dot versions keep their historical behavior: the empty
		// final segment is skipped (locked by TestTrailingDotVersions).
		{"1.", true, []int{1}},
		{"1.0.", true, []int{1, 0}},

		// Overflow cap: 18 digits per component is accepted, anything
		// longer fails the whole version (locked by TestParseOverflowCap).
		{"999999999999999999", true, []int{999999999999999999}},
		{"1.999999999999999999", true, []int{1, 999999999999999999}},
		{"1000000000000000000", false, nil},    // 19 digits
		{"18446744073709551616", false, nil},   // would wrap to 0
		{"99999999999999999999.1", false, nil}, // 20-digit first component
		{"1.18446744073709551616", false, nil}, // overflow in SECOND component fails whole version
	}
	for _, c := range cases {
		v, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q): ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(v.parts) != len(c.parts) {
			t.Errorf("Parse(%q): parts=%v want %v", c.in, v.parts, c.parts)
			continue
		}
		for i := range c.parts {
			if v.parts[i] != c.parts[i] {
				t.Errorf("Parse(%q): parts=%v want %v", c.in, v.parts, c.parts)
				break
			}
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.3", "1.2.3", 0},
		{"1.2.3-beta", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"2.0", "2.0.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.3", "1.3.0", -1},
		{"1.9", "1.10", -1},
		{"0.10.210305", "0.9.99999", 1},
		{"3.24.9", "3.24.10", -1},
		{"1.0.0.85", "1.0.0.86", -1},
		{"4.0", "3.24.9", 1},
	}
	for _, c := range cases {
		a, b := testVersion(t, c.a), testVersion(t, c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("Compare(%q, %q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInAffected(t *testing.T) {
	cases := []struct {
		label, installed string
		want             bool
	}{
		// Plain inclusive range "from - to".
		{"1.0.0 - 3.24.9", "1.0.0", true},
		{"1.0.0 - 3.24.9", "3.24.9", true},
		{"1.0.0 - 3.24.9", "2.5.0", true},
		{"1.0.0 - 3.24.9", "0.9.9", false},
		{"1.0.0 - 3.24.9", "3.25.0", false},
		{"1.0.0 - 3.24.9", "3.24.10", false},

		// Compact range.
		{"0.1-0.9", "0.5", true},
		{"0.1-0.9", "0.9", true},
		{"0.1-0.9", "1.0", false},
		{"0.1.0-3.4.7", "3.4.7", true},
		{"0.1.0-3.4.7", "3.4.8", false},

		// <= upper bound.
		{"<= 2.0", "2.0", true},
		{"<= 2.0", "1.9", true},
		{"<= 2.0", "2.0.1", false},

		// < exclusive upper bound.
		{"< 2.0", "1.9.9", true},
		{"< 2.0", "2.0", false},

		// >= / > lower bounds.
		{">= 1.5", "1.5", true},
		{">= 1.5", "3.0", true},
		{">= 1.5", "1.4.9", false},
		{"> 1.5", "1.5", false},
		{"> 1.5", "1.5.1", true},

		// Exact match.
		{"= 1.5", "1.5", true},
		{"= 1.5", "1.5.0", true},
		{"= 1.5", "1.6", false},
		{"1.5", "1.5", true},
		{"1.5", "1.5.0", true},
		{"1.5", "1.6", false},

		// Wildcard / unbounded formats.
		{"*", "0.0.1", true},
		{"*", "99.99.99", true},
		{"*-1.37", "1.37", true},
		{"*-1.37", "0.1", true},
		{"*-1.37", "1.37.1", false},
		{"*-1.0", "0.9", true},
		{"*-1.0", "1.0", true},
		{"*-1.0", "1.1", false},

		// Bracket ranges.
		{"[*, 3.7)", "3.6", true},
		{"[*, 3.7)", "3.7", false},
		{"[1.0, 2.0]", "1.0", true},
		{"[1.0, 2.0]", "2.0", true},
		{"[1.0, 2.0]", "2.1", false},
		{"(1.0, 2.0]", "1.0", false},
		{"(1.0, 2.0]", "2.0", true},

		// Comma-separated union.
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "3.24.9", true},
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "4.0", true},
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "4.2", true},
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "3.25.0", false},
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "4.3", false},
		{"1.0.0 - 3.24.9, 4.0 - 4.2", "3.25.0", false},
		{"22.0, <= 24.0", "23.0", true},
		{"22.0, <= 24.0", "22.0", true},
		{"22.0, <= 24.0", "25.0", false},

		// Prerelease versions are handled: "1.2.3-beta" == "1.2.3".
		{"1.0.0 - 2.0.0", "1.5.0-beta", true},
		{"= 1.5", "1.5.0-rc1", true},

		// Unparseable / non-numeric inputs never match.
		{"1.0.0 - 3.24.9", "unknown", false},
		{"garbage", "1.0.0", false},
		{"1.0.0 - banana", "1.0.0", false},
		{"", "1.0.0", true},
	}
	for _, c := range cases {
		if got := InAffected(c.label, c.installed); got != c.want {
			t.Errorf("InAffected(%q, %q)=%v want %v", c.label, c.installed, got, c.want)
		}
	}
}

func TestInAffectedWith4PartVersions(t *testing.T) {
	cases := []struct {
		label, installed string
		want             bool
	}{
		{"*-0.1.0.85", "0.1.0.85", true},
		{"*-0.1.0.85", "0.1.0.86", false},
		{"0.1.0-3.4.7", "1.2.3.4", true},
		{"0.1.0-3.4.7", "3.4.7.1", false},
		{"0.0.1-0.0.6", "0.0.6", true},
	}
	for _, c := range cases {
		if got := InAffected(c.label, c.installed); got != c.want {
			t.Errorf("InAffected(%q, %q)=%v want %v", c.label, c.installed, got, c.want)
		}
	}
}

func TestParseRangesErrors(t *testing.T) {
	bad := []string{
		"1.0.0 -", "- 3.0", "abc", "[1.0 2.0]", "[*,3.7", ")1.0,2.0(", "<= xyz", "= ",
		// Strict bracket bounds: trailing junk after a bound must not be
		// silently truncated away by Parse.
		"[1.0, 2.0, junk]", "[1.0, 2.0 , junk]", "[1.0, 2.0, extra]",
		"[0.1-0.9]",      // dash-digit tail inside a bound reads as a range
		"[1.0, 2.0-3.0]", // same
	}
	for _, s := range bad {
		if _, err := ParseRanges(s); err == nil {
			t.Errorf("ParseRanges(%q): expected error, got nil", s)
		}
	}
}

func TestParseOverflowCap(t *testing.T) {
	// The audit finding: Parse("18446744073709551616") used to wrap to
	// parts=[0], compare EQUAL to "0", and match ranges "<= 100" and
	// "*-50". It must now fail to parse entirely (fail closed).
	if v, ok := Parse("18446744073709551616"); ok {
		t.Fatalf("Parse(overflowing) = %v, want ok=false", v)
	}
	for _, label := range []string{"<= 100", "*-50"} {
		if InAffected(label, "18446744073709551616") {
			t.Errorf("InAffected(%q, overflowing version) = true, want false", label)
		}
	}
	zero := testVersion(t, "0")
	for _, s := range []string{
		"1000000000000000000",      // smallest 19-digit number
		"99999999999999999999.1",   // 20 digits in first component
		"1.1000000000000000000",    // overflow in second component fails whole version
		"1.2.99999999999999999999", // overflow in third component
	} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q): expected ok=false", s)
		}
		if InAffected("*-50", s) || InAffected("<= 100", s) {
			t.Errorf("InAffected matches unparseable overflowing version %q", s)
		}
	}
	for _, s := range []string{
		"999999999999999999",   // exactly 18 digits
		"1.999999999999999999", // exactly 18 digits in second component
	} {
		v, ok := Parse(s)
		if !ok {
			t.Errorf("Parse(%q): unexpected failure at the 18-digit cap", s)
			continue
		}
		if c := v.Compare(zero); c <= 0 && s != "" {
			t.Errorf("Compare(%q, 0) = %d, want > 0", s, c)
		}
	}
}

func TestBracketBoundsStrict(t *testing.T) {
	// Prerelease-style continuations of a bound remain consistent with
	// Parse's rules and are accepted.
	good := []struct {
		label, installed string
		want             bool
	}{
		{"[1.2.3-beta, 2.0]", "1.5", true},
		{"[1.0, 2.0-rc1]", "2.0", true},
		{"[1.0, 2.0b]", "1.5", true},
		{"[v1.0, 2.0]", "1.5", true},
	}
	for _, c := range good {
		if got := InAffected(c.label, c.installed); got != c.want {
			t.Errorf("InAffected(%q, %q)=%v want %v", c.label, c.installed, got, c.want)
		}
	}
}

func TestDashStarRange(t *testing.T) {
	// "1.0-*" / "1.0 - *" mean From=1.0 inclusive with no upper bound,
	// i.e. the same semantics as "[1.0, *]".
	cases := []struct {
		label, installed string
		want             bool
	}{
		{"1.0-*", "0.9", false},
		{"1.0-*", "1.0", true},
		{"1.0-*", "99.0", true},
		{"1.0 - *", "0.9", false},
		{"1.0 - *", "1.0", true},
		{"1.0 - *", "99.0", true},
		// Prerelease dash is untouched: still an exact match.
		{"1.2.3-beta", "1.2.3", true},
		{"1.2.3-beta", "1.2.4", false},
	}
	for _, c := range cases {
		if got := InAffected(c.label, c.installed); got != c.want {
			t.Errorf("InAffected(%q, %q)=%v want %v", c.label, c.installed, got, c.want)
		}
	}
	for _, label := range []string{"1.0-*", "1.0 - *"} {
		rs, err := ParseRanges(label)
		if err != nil {
			t.Fatalf("ParseRanges(%q): %v", label, err)
		}
		if len(rs) != 1 || rs[0].From == nil || rs[0].To != nil || !rs[0].FromIncl {
			t.Errorf("ParseRanges(%q) = %+v, want single range From=1.0 inclusive, To=nil", label, rs)
		}
	}
	// "*-1.37" must keep working after the dash-star change.
	if !InAffected("*-1.37", "1.37") || InAffected("*-1.37", "1.37.1") {
		t.Errorf("*-1.37 semantics regressed")
	}
}

func TestTrailingDotVersions(t *testing.T) {
	// Locked decision: a trailing dot yields an empty final segment which
	// is skipped, so "1." parses as [1] — historical behavior preserved.
	v, ok := Parse("1.")
	if !ok || len(v.parts) != 1 || v.parts[0] != 1 {
		t.Fatalf("Parse(\"1.\") = (%#v, %v), want parts [1]", v, ok)
	}
	if w := testVersion(t, "1."); w.Compare(testVersion(t, "1")) != 0 {
		t.Errorf("\"1.\" should equal \"1\"")
	}
	if !InAffected("= 1.", "1.0") {
		t.Errorf("= 1. should match 1.0")
	}
}

func TestParseRangesEmptyIsUniversal(t *testing.T) {
	rs, err := ParseRanges("")
	if err != nil {
		t.Fatalf("ParseRanges(\"\"): %v", err)
	}
	if len(rs) != 1 || !rs[0].Contains(testVersion(t, "3.1.0")) {
		t.Errorf("empty label should match all versions")
	}
}
