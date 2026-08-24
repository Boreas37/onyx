package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestExtractTestedUpTo exercises the "Tested up to:" extractor across the
// accepted spellings: case-insensitive headers, "=" separators, trailing
// spaces — and absence.
func TestExtractTestedUpTo(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"classic colon", "== P ==\nTested up to: 6.4.2\nStable tag: 1.0.0\n", "6.4.2"},
		{"uppercase header", "== P ==\nTESTED UP TO: 6.5.1\n", "6.5.1"},
		{"equals separator", "== P ==\nTested up to = 6.3\n", "6.3"},
		{"trailing spaces", "== P ==\nTested up to: 6.4.2   \n", "6.4.2"},
		{"v prefix kept", "== P ==\nTested up to: v6.4.2\n", "v6.4.2"},
		{"absent", "== P ==\nStable tag: 1.0.0\n", ""},
		{"not line start", "xTested up to: 6.4.2\n", ""},
		{"embedded must not span lines", "== P ==\nTested up to: 6.4.2\nsecond line\n", "6.4.2"},
	}
	for _, c := range cases {
		if got := ExtractTestedUpTo(c.body); got != c.want {
			t.Errorf("%s: ExtractTestedUpTo = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestExtractRequiresAtLeast exercises the "Requires at least:" extractor
// across the accepted spellings, mirroring TestExtractTestedUpTo.
func TestExtractRequiresAtLeast(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"classic colon", "== P ==\nRequires at least: 5.9\nStable tag: 1.0.0\n", "5.9"},
		{"mixed case", "== P ==\nRequires At Least: 6.0\n", "6.0"},
		{"equals separator", "== P ==\nRequires at least = 5.8\n", "5.8"},
		{"trailing spaces", "== P ==\nRequires at least: 5.9   \n", "5.9"},
		{"absent", "== P ==\nStable tag: 1.0.0\n", ""},
		{"not line start", "xRequires at least: 5.9\n", ""},
	}
	for _, c := range cases {
		if got := ExtractRequiresAtLeast(c.body); got != c.want {
			t.Errorf("%s: ExtractRequiresAtLeast = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestScanJobReadmeHeaderMetadata verifies a plugin readme carrying both
// headers populates Detected.TestedUpTo and Detected.RequiresAtLeast.
func TestScanJobReadmeHeaderMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/meta-plugin/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Meta Plugin ===
Contributors: team
Tags: things
Requires at least: 5.9
Tested up to: 6.4.2
Stable tag: 1.5.0
`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "meta-plugin", path: "/wp-content/plugins/meta-plugin/readme.txt"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].TestedUpTo != "6.4.2" {
		t.Errorf("TestedUpTo = %q, want 6.4.2", detected[0].TestedUpTo)
	}
	if detected[0].RequiresAtLeast != "5.9" {
		t.Errorf("RequiresAtLeast = %q, want 5.9", detected[0].RequiresAtLeast)
	}
	if detected[0].Version != "1.5.0" {
		t.Errorf("Version = %q, want 1.5.0", detected[0].Version)
	}
}

// TestScanJobReadmeWithoutHeadersStaysEmpty verifies a readme that parses
// but carries no header lines leaves both metadata fields empty (they are
// omitempty in JSON).
func TestScanJobReadmeWithoutHeadersStaysEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/plugins/plain/readme.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`=== Plain ===
Contributors: team
Stable tag: 1.0.0
`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "plugin", slug: "plain", path: "/wp-content/plugins/plain/readme.txt"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].TestedUpTo != "" || detected[0].RequiresAtLeast != "" {
		t.Errorf("metadata must stay empty without headers, got %+v", detected[0])
	}
}

// TestScanJobStyleCSSRequiresAtLeast verifies the theme branch parses
// "Requires at least:" from style.css headers (TestedUpTo is a
// readme-only header and stays empty).
func TestScanJobStyleCSSRequiresAtLeast(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-content/themes/req-theme/style.css", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`/*
Theme Name: Req Theme
Requires at least: 6.0
Version: 1.1
*/
body { margin: 0; }
`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	detected, _ := sc.scanJob(job{kind: "theme", slug: "req-theme", path: "/wp-content/themes/req-theme/style.css"})
	if len(detected) != 1 {
		t.Fatalf("expected 1 detection, got %+v", detected)
	}
	if detected[0].RequiresAtLeast != "6.0" {
		t.Errorf("RequiresAtLeast = %q, want 6.0", detected[0].RequiresAtLeast)
	}
	if detected[0].TestedUpTo != "" {
		t.Errorf("TestedUpTo = %q, want empty for style.css", detected[0].TestedUpTo)
	}
	if detected[0].Version != "1.1" {
		t.Errorf("Version = %q, want 1.1", detected[0].Version)
	}
}
