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
		in   string
		ok   bool
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
	bad := []string{"1.0.0 -", "- 3.0", "abc", "[1.0 2.0]", "[*,3.7", ")1.0,2.0(", "<= xyz", "= "}
	for _, s := range bad {
		if _, err := ParseRanges(s); err == nil {
			t.Errorf("ParseRanges(%q): expected error, got nil", s)
		}
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