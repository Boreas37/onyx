package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestExtractTimthumbVersionMarkers drives the version extractor with the
// three common marker shapes: the "TimThumb version X.Y.Z" banner line,
// a JSON-style "version" field and the $version = 'X.Y.Z' PHP assignment
// (single- and double-quoted, any casing, first marker wins).
func TestExtractTimthumbVersionMarkers(t *testing.T) {
	cases := []struct{ body, want string }{
		{"// TimThumb version 2.8.10", "2.8.10"},
		{"TimThumb version 2.8.10\r\nCopyright", "2.8.10"},
		{`{"version": "2.8.11"}`, "2.8.11"},
		{"$version = '2.8.12';", "2.8.12"},
		{`$version = "2.8.13";`, "2.8.13"},
		{"TIMTHUMB VERSION 2.8.14", "2.8.14"},
		{`{"VERSION": "2.8.15"}`, "2.8.15"},
		{"$VERSION = '2.8.16';", "2.8.16"},
		// First marker in document order wins.
		{"TimThumb version 2.8.17\n$version = '9.9';", "2.8.17"},
	}
	for _, c := range cases {
		v, ok := ExtractTimthumbVersion(c.body)
		if !ok || v != c.want {
			t.Errorf("ExtractTimthumbVersion(%q) = %q, %v; want %q, true", c.body, v, ok, c.want)
		}
	}
}

// TestExtractTimthumbVersionAbsent verifies version-less bodies — prose
// mentioning timthumb, a define()-based version constant, unrelated JSON
// and empty input — all report found=false.
func TestExtractTimthumbVersionAbsent(t *testing.T) {
	for _, body := range []string{
		"",
		"This file is a timthumb image resizer, no banner here.",
		"define('TIMTHUMB_VERSION', '2.8.10');",
		`{"file":"timthumb.php","size":1234}`,
		"version = 2.8.10",  // no marker prefix
		`"version": 2.8.10`, // unquoted JSON number
	} {
		if v, ok := ExtractTimthumbVersion(body); ok {
			t.Errorf("ExtractTimthumbVersion(%q) = %q, true; want false", body, v)
		}
	}
}

// TestExtractTimthumbVersionHostile verifies the sanitizeVersion contract:
// a hostile marker padded with megabytes of digits is truncated to
// maxVersionLen and carries no control characters.
func TestExtractTimthumbVersionHostile(t *testing.T) {
	body := "TimThumb version 2.8.10." + strings.Repeat("9", 10000)
	v, ok := ExtractTimthumbVersion(body)
	if !ok {
		t.Fatal("ExtractTimthumbVersion should still find the hostile version")
	}
	if len(v) > maxVersionLen {
		t.Errorf("version %d chars exceeds cap %d", len(v), maxVersionLen)
	}

	body = "$version = '" + strings.Repeat("9", 10000) + "';"
	v, ok = ExtractTimthumbVersion(body)
	if !ok {
		t.Fatal("ExtractTimthumbVersion should still find the hostile $version")
	}
	if len(v) > maxVersionLen {
		t.Errorf("version %d chars exceeds cap %d", len(v), maxVersionLen)
	}
}

// TestTimthumbFinderVersions verifies timthumbFinder suffixes every found
// path with the pinned release: banner-based and $version-based bodies get
// their version, and a version-less body keeps the bare path.
func TestTimthumbFinderVersions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/timthumb.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("/* TimThumb version 2.8.10 - image resizer */\n$version = '9.9';"))
	})
	mux.HandleFunc("/wp-content/plugins/timthumb.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("// timthumb.php image resizer\n$version = '2.8.11';"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(nil, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := sc.timthumbFinder()
	// Probe order follows timthumbPaths: the plugins copy first, then the
	// site-root copy.
	want := []string{
		"/wp-content/plugins/timthumb.php (TimThumb 2.8.11)",
		"/timthumb.php (TimThumb 2.8.10)",
	}
	if len(got) != len(want) {
		t.Fatalf("timthumbFinder() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("timthumbFinder()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTimthumbFinderVersionLess verifies version-less bodies keep the
// bare path and bodies without any timthumb mention are skipped.
func TestTimthumbFinderVersionLess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/timthumb.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("// a bare timthumb.php resizer with no version banner"))
	})
	mux.HandleFunc("/wp-content/plugins/timthumb.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not a resizer</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc, err := NewScanner(nil, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := sc.timthumbFinder()
	want := []string{"/timthumb.php"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("timthumbFinder() = %v, want %v", got, want)
	}
}
