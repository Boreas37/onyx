// Package version implements WordPress version comparison against the
// affected-version range formats used by the Wordfence Intelligence feed
// and described in PROMPT.md.
//
// Supported range formats:
//
//	"1.0.0 - 3.24.9"      inclusive range
//	"0.1-0.9"             inclusive range (compact)
//	"<= 2.0"              upper bound (inclusive)
//	"< 2.0"               upper bound (exclusive)
//	">= 1.5"              lower bound (inclusive)
//	"> 1.5"               lower bound (exclusive)
//	"= 1.5"               exact version
//	"*"                   any version
//	"*-1.37"              any version up to (and including) 1.37
//	"1.0-*"               any version from (and including) 1.0 onward
//	"[*, 3.7)"            bracket range: [ inclusive, ( exclusive, * unbounded
//	"1.0.0 - 3.24.9, 4.0 - 4.2"  comma-separated union of ranges
//
// Versions are compared numerically by their dotted numeric parts
// (major.minor.patch, with any extra parts allowed). Prerelease suffixes
// such as "-beta" are ignored, so "1.2.3-beta" compares equal to "1.2.3".
//
// Security note: each dotted component is capped at 18 digits. A version
// containing a longer (or otherwise overflowing) component fails to parse
// entirely rather than wrapping around, so hostile input cannot fabricate
// versions that force-match or dodge range checks. See Parse.
package version

import (
	"errors"
	"strings"
)

// Version is a parsed, purely-numeric dotted version.
type Version struct {
	parts []int
	raw   string
}

// ErrInvalidVersion is returned when a version or range string cannot be parsed.
var ErrInvalidVersion = errors.New("invalid version")

// maxSegment is the largest value accepted for a single dotted component:
// 999,999,999,999,999,999 (18 digits). Real component versions never come
// close to this bound, and capping well below math.MaxInt lets the overflow
// check run before every multiply/add. Requires a 64-bit int platform.
const maxSegment = 999_999_999_999_999_999

// consumeVersion scans the leading dotted-numeric version from s using the
// same segment rules as Parse: segments are dot-separated and individually
// trimmed; empty segments are skipped; scanning stops at a segment that does
// not start with a digit or mid-segment at the first non-digit (a
// prerelease-style qualifier such as "-beta" or "b").
//
// It returns the parsed parts (empty if nothing numeric was consumed) plus
// the unconsumed remainder of s ("", when fully consumed). ok is false when
// no numeric content was found OR when any component would overflow
// maxSegment; in the overflow case the whole version fails closed so a
// wrapped value can never be compared as if it were real.
func consumeVersion(s string) (parts []int, rest string, ok bool) {
	for {
		j := strings.IndexByte(s, '.')
		seg := s
		if j >= 0 {
			seg = s[:j]
		}
		t := strings.TrimSpace(seg)
		if t != "" {
			if t[0] < '0' || t[0] > '9' {
				break
			}
			n := 0
			trunc := false
			k := 0
			for k < len(t) {
				c := t[k]
				if c < '0' || c > '9' {
					trunc = true
					break
				}
				d := int(c - '0')
				if n > (maxSegment-d)/10 {
					return nil, "", false // would overflow: fail whole version
				}
				n = n*10 + d
				k++
			}
			parts = append(parts, n)
			if trunc {
				return parts, t[k:], len(parts) > 0
			}
		}
		if j < 0 {
			return parts, "", len(parts) > 0
		}
		s = s[j+1:]
	}
	return parts, s, len(parts) > 0
}

// Parse parses a version string into its numeric parts, ignoring a leading
// "v" and any prerelease/qualifier suffix (e.g. "1.2.3-beta" -> [1,2,3]).
// It reports ok=false for strings with no numeric content.
//
// Each dotted component is capped at 18 digits (maxSegment). If any
// component is longer — or would otherwise exceed that cap — the WHOLE
// version fails (ok=false) instead of silently wrapping around. Failing
// closed prevents both false positives (an overflowing version force-
// matching ranges like "<= 100") and false negatives.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = strings.TrimSpace(s[1:])
	}
	parts, _, ok := consumeVersion(s)
	if !ok {
		return Version{}, false
	}
	return Version{parts: parts, raw: s}, true
}

// Valid reports whether the version was parsed successfully.
func (v Version) Valid() bool { return len(v.parts) > 0 }

// Raw returns the original (trimmed) version string.
func (v Version) Raw() string { return v.raw }

// Compare compares two versions numerically, padding the shorter one with
// zeros. It returns -1, 0 or +1.
func (v Version) Compare(o Version) int {
	n := len(v.parts)
	if len(o.parts) > n {
		n = len(o.parts)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

// Range is an interval of versions. A nil From or To means an unbounded
// side. Inclusivity applies to the bound that is present.
type Range struct {
	From     *Version
	To       *Version
	FromIncl bool
	ToIncl   bool
	Label    string
}

// Contains reports whether v falls inside the range.
func (r Range) Contains(v Version) bool {
	if !v.Valid() {
		return false
	}
	if r.From != nil {
		c := v.Compare(*r.From)
		if c < 0 || (c == 0 && !r.FromIncl) {
			return false
		}
	}
	if r.To != nil {
		c := v.Compare(*r.To)
		if c > 0 || (c == 0 && !r.ToIncl) {
			return false
		}
	}
	return true
}

// exactRange builds a range matching exactly one version.
func exactRange(v Version) Range { return Range{From: &v, To: &v, FromIncl: true, ToIncl: true} }

// qualifierTail reports whether rest — whatever consumeVersion did not
// consume — is a prerelease-style continuation consistent with Parse's
// rules: empty, a hyphen followed by a non-digit ("1.2.3-beta", where a
// trailing digit would instead read as a compact range separator), or a
// letter glued to the last digit ("1.2.3b"). Anything else (commas,
// spaces, digits after a hyphen, ...) is junk and rejected by parseBound.
func qualifierTail(rest string) bool {
	if rest == "" {
		return true
	}
	if rest[0] == '-' {
		return len(rest) == 1 || rest[1] < '0' || rest[1] > '9'
	}
	return (rest[0] >= 'a' && rest[0] <= 'z') || (rest[0] >= 'A' && rest[0] <= 'Z')
}

// parseBound parses one endpoint of a bracket range; "*" becomes nil.
// Parsing is STRICT: after the bound's numeric version, any remaining
// input must be an empty string or a prerelease-style continuation
// (see qualifierTail). "[1.0, 2.0, junk]" therefore fails with
// ErrInvalidVersion rather than silently truncating to [1.0, 2.0].
func parseBound(s string) (*Version, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return nil, nil
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = strings.TrimSpace(s[1:])
	}
	parts, rest, ok := consumeVersion(s)
	if !ok || !qualifierTail(rest) {
		return nil, ErrInvalidVersion
	}
	return &Version{parts: parts, raw: s}, nil
}

// splitParts splits a comma-separated union of ranges, ignoring commas
// that appear inside bracket ranges such as "[*, 3.7)".
func splitParts(s string) []string {
	var parts []string
	start := 0
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// ParseRanges parses a range expression into a union of ranges.
// An empty label ("") is treated as "any version", matching Wordfence
// entries that list no affected versions.
func ParseRanges(label string) ([]Range, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return []Range{{From: nil, To: nil, FromIncl: true, ToIncl: true, Label: label}}, nil
	}

	parts := splitParts(label)
	out := make([]Range, 0, len(parts))
	for _, part := range parts {
		r, err := parseOne(part)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func parseOne(expr string) (Range, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return Range{}, ErrInvalidVersion
	}
	if expr == "*" {
		return Range{From: nil, To: nil, FromIncl: true, ToIncl: true, Label: expr}, nil
	}

	// Bracket form: [*, 3.7) / (1.0, 2.0] / [1.0, 2.0]
	if expr[0] == '[' || expr[0] == '(' {
		if len(expr) < 2 || (expr[len(expr)-1] != ']' && expr[len(expr)-1] != ')') {
			return Range{}, ErrInvalidVersion
		}
		fromIncl := expr[0] == '['
		toIncl := expr[len(expr)-1] == ']'
		inner := expr[1 : len(expr)-1]
		comma := strings.IndexByte(inner, ',')
		if comma < 0 {
			return Range{}, ErrInvalidVersion
		}
		from, err := parseBound(inner[:comma])
		if err != nil {
			return Range{}, err
		}
		to, err := parseBound(inner[comma+1:])
		if err != nil {
			return Range{}, err
		}
		return Range{From: from, To: to, FromIncl: fromIncl, ToIncl: toIncl, Label: expr}, nil
	}

	// Operator forms: <= 2.0 / < 2.0 / >= 1.5 / > 1.5 / = 1.5
	for _, op := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(expr, op) {
			rest := strings.TrimSpace(expr[len(op):])
			v, ok := Parse(rest)
			if !ok {
				return Range{}, ErrInvalidVersion
			}
			switch op {
			case "<=":
				return Range{From: nil, To: &v, FromIncl: true, ToIncl: true, Label: expr}, nil
			case "<":
				return Range{From: nil, To: &v, FromIncl: true, ToIncl: false, Label: expr}, nil
			case ">=":
				return Range{From: &v, To: nil, FromIncl: true, ToIncl: true, Label: expr}, nil
			case ">":
				return Range{From: &v, To: nil, FromIncl: false, ToIncl: true, Label: expr}, nil
			case "=":
				return exactRange(v), nil
			}
		}
	}

	// "*-1.37": unbounded from, inclusive upper bound.
	if strings.HasPrefix(expr, "*") {
		rest := strings.TrimSpace(strings.TrimLeft(expr[1:], "- "))
		if rest == "" {
			return Range{From: nil, To: nil, FromIncl: true, ToIncl: true, Label: expr}, nil
		}
		v, ok := Parse(rest)
		if !ok {
			return Range{}, ErrInvalidVersion
		}
		return Range{From: nil, To: &v, FromIncl: true, ToIncl: true, Label: expr}, nil
	}

	// Range: "A - B" or "A-B". A dash is a range separator when it is
	// surrounded by spaces or when the following (non-space) run starts
	// with a digit (e.g. "0.1.0-3.4.7"), or when that run is "*" (e.g.
	// "1.0-*", meaning "A and everything after"). A dash followed by a
	// letter is a prerelease qualifier inside a single version (e.g.
	// "1.2.3-beta") and resolves to an exact match.
	idx := strings.IndexByte(expr, '-')
	if idx >= 0 {
		rest := strings.TrimSpace(expr[idx+1:])
		prevSpace := idx > 0 && (expr[idx-1] == ' ' || expr[idx-1] == '\t')
		nextSpace := idx+1 < len(expr) && (expr[idx+1] == ' ' || expr[idx+1] == '\t')
		nextDigit := rest != "" && rest[0] >= '0' && rest[0] <= '9'
		toStar := rest == "*"
		if (prevSpace || nextSpace) && rest == "" {
			return Range{}, ErrInvalidVersion
		}
		if toStar || (prevSpace && nextSpace) || nextDigit {
			a := strings.TrimSpace(expr[:idx])
			from, ok := Parse(a)
			if !ok {
				return Range{}, ErrInvalidVersion
			}
			if toStar {
				// "1.0-*": From inclusive, To unbounded (same as "[1.0, *]").
				return Range{From: &from, To: nil, FromIncl: true, ToIncl: true, Label: expr}, nil
			}
			to, ok := Parse(rest)
			if !ok {
				return Range{}, ErrInvalidVersion
			}
			return Range{From: &from, To: &to, FromIncl: true, ToIncl: true, Label: expr}, nil
		}
	}

	// Bare version: exact match.
	v, ok := Parse(expr)
	if !ok {
		return Range{}, ErrInvalidVersion
	}
	return exactRange(v), nil
}

// InAffected is a convenience wrapper: reports whether installed falls
// inside any range described by the label. An unparseable label never
// matches (false-positive prevention).
func InAffected(label, installed string) bool {
	ranges, err := ParseRanges(label)
	if err != nil {
		return false
	}
	v, ok := Parse(installed)
	if !ok {
		return false
	}
	for _, r := range ranges {
		if r.Contains(v) {
			return true
		}
	}
	return false
}

// InRanges reports whether v falls inside any of the ranges.
func InRanges(ranges []Range, v Version) bool {
	for _, r := range ranges {
		if r.Contains(v) {
			return true
		}
	}
	return false
}
