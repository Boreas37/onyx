package scanner

import (
	"strings"
	"testing"
)

func TestExtractVersionFromReadmeCapsLength(t *testing.T) {
	long := "Stable tag: 9." + strings.Repeat("9", 10000)
	v, ok := ExtractVersionFromReadme(long)
	if !ok {
		t.Fatal("expected version to be found")
	}
	if len(v) > maxVersionLen {
		t.Fatalf("version not capped: %d chars", len(v))
	}
}

func TestExtractVersionFromStyleCSSCapsLength(t *testing.T) {
	long := "Version: 1." + strings.Repeat("5", 10000)
	v, ok := ExtractVersionFromStyleCSS(long)
	if !ok {
		t.Fatal("expected version to be found")
	}
	if len(v) > maxVersionLen {
		t.Fatalf("version not capped: %d chars", len(v))
	}
}

func TestSanitizeTextStripsControlChars(t *testing.T) {
	in := "ok\x1b[31mANSI\x1b[0m\nnewline\ttab\x00null\x7fdel"
	got := sanitizeText(in, maxNameLen)
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control char %q survived sanitize: %q", r, got)
		}
	}
	if strings.Contains(got, "\n") || strings.Contains(got, "\x00") {
		t.Fatalf("newline/null survived: %q", got)
	}
}

func TestSanitizeTextCapsRunes(t *testing.T) {
	in := strings.Repeat("é", 500)
	got := sanitizeText(in, maxNameLen)
	if len([]rune(got)) != maxNameLen {
		t.Fatalf("rune cap failed: %d", len([]rune(got)))
	}
}

func TestParseDetectedListSanitizesFields(t *testing.T) {
	body := []byte(`[{"plugin":"evil/plugin.php","version":"1.0\u000b\u001b[31mred","name":"<script>\u001b]0;x"}]`)
	got := parseDetectedList(body, "plugin", "rest")
	if len(got) != 1 {
		t.Fatalf("expected 1 detected, got %d", len(got))
	}
	d := got[0]
	if d.Slug != "evil" {
		t.Fatalf("slug = %q, want evil", d.Slug)
	}
	if strings.ContainsAny(d.Version, "\x0b\x1b") {
		t.Fatalf("version kept control chars: %q", d.Version)
	}
	if strings.Contains(d.Name, "\x1b") {
		t.Fatalf("name kept escape: %q", d.Name)
	}
}

func TestUsersFromAPIPayloadSanitized(t *testing.T) {
	body := []byte(`[{"id":1,"slug":"a\u001b]0;evil","name":"Admin\u0007bell"}]`)
	users := usersFromJSON(body)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if strings.ContainsRune(users[0].Slug, 0x1b) {
		t.Fatalf("user slug kept escape: %q", users[0].Slug)
	}
	if strings.ContainsRune(users[0].Name, 0x07) {
		t.Fatalf("user name kept bell: %q", users[0].Name)
	}
}

func TestAuthorSlugFromBodyCapped(t *testing.T) {
	long := strings.Repeat("a", 5000)
	body := []byte("<link rel='canonical' href='http://x.test/author/" + long + "/'>")
	slug := authorSlugFromBody(body)
	if len(slug) > maxSlugLen {
		t.Fatalf("author slug not capped: %d chars", len(slug))
	}
}
