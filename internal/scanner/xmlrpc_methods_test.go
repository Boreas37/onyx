package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// TestExtractXMLRPCMethods drives the method-list parser directly: a
// realistic system.listMethods response yields the sorted, deduplicated
// method names; prose and non-method tokens are dropped; and the result is
// capped at maxXMLRPCMethods.
func TestExtractXMLRPCMethods(t *testing.T) {
	t.Run("realistic method list", func(t *testing.T) {
		body := `<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
			`<value><string>system.multicall</string></value>` +
			`<value><string>pingback.ping</string></value>` +
			`<value><string>wp.getUsersBlogs</string></value>` +
			`<value><string>test.string</string></value>` +
			`<value><string>pingback.ping</string></value>` +
			`</data></array></value></param></params></methodResponse>`
		got := extractXMLRPCMethods(body)
		want := []string{"pingback.ping", "system.multicall", "test.string", "wp.getUsersBlogs"}
		if len(got) != len(want) {
			t.Fatalf("methods = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("methods[%d] = %q, want %q (sorted, deduplicated)", i, got[i], want[i])
			}
		}
	})

	t.Run("cap respected with 25 methods", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>`)
		for i := 1; i <= 25; i++ {
			fmt.Fprintf(&b, `<value><string>wp.method%d</string></value>`, i)
		}
		b.WriteString(`</data></array></value></param></params></methodResponse>`)
		got := extractXMLRPCMethods(b.String())
		if len(got) != maxXMLRPCMethods {
			t.Fatalf("methods = %d entries, want capped at %d", len(got), maxXMLRPCMethods)
		}
		for _, m := range got {
			if !strings.HasPrefix(m, "wp.method") {
				t.Errorf("unexpected method %q", m)
			}
		}
	})

	t.Run("non-method tokens dropped", func(t *testing.T) {
		body := `<?xml version="1.0"?><methodResponse><params><param><value><array><data>` +
			`<value><string>foo</string></value>` + // no dot: not a method
			`<value><string>blog name here</string></value>` + // spaces: not a method
			`<value><string>wp.getUsersBlogs</string></value>` +
			`</data></array></value></param></params></methodResponse>`
		got := extractXMLRPCMethods(body)
		if len(got) != 1 || got[0] != "wp.getUsersBlogs" {
			t.Errorf("methods = %v, want [wp.getUsersBlogs]", got)
		}
	})

	t.Run("garbage yields empty list", func(t *testing.T) {
		for _, body := range []string{
			"",
			"not xml at all",
			`<?xml version="1.0"?><methodResponse><params><param><value><string>garbage with spaces</string></value></param></params></methodResponse>`,
			`<?xml version="1.0"?><methodResponse><params><param><value><string>&lt;script&gt;alert(1)&lt;/script&gt;</string></value></param></params></methodResponse>`,
		} {
			if got := extractXMLRPCMethods(body); len(got) != 0 {
				t.Errorf("extractXMLRPCMethods(%q) = %v, want empty", body, got)
			}
		}
	})
}

// methodsList builds a full system.listMethods response body with the given
// method names.
func methodsList(names ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><methodResponse><params><param><value><array><data>`)
	for _, n := range names {
		b.WriteString(`<value><string>` + n + `</string></value>`)
	}
	b.WriteString(`</data></array></value></param></params></methodResponse>`)
	return b.String()
}

// TestCheckXMLRPCReturnsMethods verifies the new checkXMLRPC signature
// surfaces the parsed method inventory alongside enabled/pingback.
func TestCheckXMLRPCReturnsMethods(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	t.Run("methods parsed", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK,
			methodsList("system.listMethods", "system.multicall", "pingback.ping", "wp.getUsersBlogs"))
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		enabled, pingback, methods := sc.checkXMLRPC()
		if !enabled {
			t.Fatal("enabled = false, want true")
		}
		if !pingback {
			t.Error("pingback = false, want true")
		}
		want := []string{"pingback.ping", "system.listMethods", "system.multicall", "wp.getUsersBlogs"}
		if len(methods) != len(want) {
			t.Fatalf("methods = %v, want %v", methods, want)
		}
		for i := range want {
			if methods[i] != want[i] {
				t.Errorf("methods[%d] = %q, want %q", i, methods[i], want[i])
			}
		}
	})

	t.Run("garbage body still enabled, empty methods", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK,
			`<?xml version="1.0"?><methodResponse><params><param><value><string>garbage with spaces</string></value></param></params></methodResponse>`)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		enabled, pingback, methods := sc.checkXMLRPC()
		if !enabled {
			t.Error("enabled = false, want true (methodResponse present)")
		}
		if pingback {
			t.Error("pingback = true, want false")
		}
		if len(methods) != 0 {
			t.Errorf("methods = %v, want empty", methods)
		}
	})
}

// TestScanXMLRPCMethodsResult verifies the scan-level flow: the method
// inventory lands in res.XMLRPCMethods and an Interesting entry reports the
// derived count; the pingback entry behavior is unchanged.
func TestScanXMLRPCMethodsResult(t *testing.T) {
	d, _ := db.Load(minimalFeed(t))

	t.Run("methods surface in result", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK,
			methodsList("system.multicall", "pingback.ping", "wp.getUsersBlogs", "test.string"))
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		res, err := sc.Scan()
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !res.XMLRPC {
			t.Fatal("XMLRPC = false, want true")
		}
		if len(res.XMLRPCMethods) != 4 {
			t.Fatalf("XMLRPCMethods = %v, want 4 parsed methods", res.XMLRPCMethods)
		}
		countEntry := fmt.Sprintf("XML-RPC exposes %d methods", len(res.XMLRPCMethods))
		found := false
		for _, i := range res.Interesting {
			if i == countEntry {
				found = true
			}
		}
		if !found {
			t.Errorf("Interesting missing %q: %+v", countEntry, res.Interesting)
		}
		if !res.XMLRPCPingback {
			t.Error("XMLRPCPingback = false, want true (pingback.ping listed)")
		}
	})

	t.Run("garbage body no crash, no methods", func(t *testing.T) {
		srv := pingbackServer(t, http.StatusOK,
			`<?xml version="1.0"?><methodResponse><params><param><value><string>garbage with spaces</string></value></param></params></methodResponse>`)
		defer srv.Close()
		sc, _ := NewScanner(d, srv.URL, Options{})
		res, err := sc.Scan()
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !res.XMLRPC {
			t.Fatal("XMLRPC = false, want true")
		}
		if len(res.XMLRPCMethods) != 0 {
			t.Errorf("XMLRPCMethods = %v, want empty", res.XMLRPCMethods)
		}
		for _, i := range res.Interesting {
			if strings.Contains(i, "XML-RPC exposes") {
				t.Errorf("Interesting must not report a method count for garbage: %q", i)
			}
		}
	})
}
