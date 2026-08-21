// Package sanitize makes target-controlled or feed-controlled strings safe
// to embed in reports: control characters (ANSI escapes, newlines, nulls)
// are stripped so a hostile server or a corrupted feed cannot forge report
// lines, and results are capped to a rune limit.
package sanitize

import (
	"strings"
	"unicode"
)

// Text strips control characters from s and truncates the result to maxLen
// runes. Control characters are anything below 0x20, DEL (0x7f) and the
// C1 range (0x80-0x9f); invalid UTF-8 (U+FFFD after decoding) is dropped.
func Text(s string, maxLen int) string {
	if s == "" {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	r := []rune(cleaned)
	if len(r) > maxLen {
		r = r[:maxLen]
	}
	return string(r)
}
