package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestParseScanArgsBasicAuth(t *testing.T) {
	_, o := parseScanArgs([]string{"http://example.test", "--basic-auth", "admin:hunter2"})
	if o.basicAuthUser != "admin" || o.basicAuthPass != "hunter2" {
		t.Errorf("basic auth = %q:%q, want admin:hunter2", o.basicAuthUser, o.basicAuthPass)
	}
	_, o = parseScanArgs([]string{"--basic-auth", "user:p:a:ss", "http://example.test"})
	if o.basicAuthUser != "user" || o.basicAuthPass != "p:a:ss" {
		t.Errorf("basic auth with colons in pass = %q:%q, want user:p:a:ss", o.basicAuthUser, o.basicAuthPass)
	}
}

func TestSplitBasicAuthMalformed(t *testing.T) {
	for _, v := range []string{"", "nocolon"} {
		if _, _, err := splitBasicAuth(v); err == nil {
			t.Errorf("splitBasicAuth(%q) = nil error, want malformed error", v)
		}
	}
}

func TestParseScanArgsHeaders(t *testing.T) {
	_, o := parseScanArgs([]string{
		"http://example.test",
		"--headers", "X-Api-Key: abc, User-Agent: custom",
	})
	want := map[string]string{"X-Api-Key": "abc", "User-Agent": "custom"}
	if !reflect.DeepEqual(o.headers, want) {
		t.Errorf("headers = %v, want %v", o.headers, want)
	}
	_, o = parseScanArgs([]string{"--headers", " A : b , C: d ", "http://example.test"})
	want = map[string]string{"A": "b", "C": "d"}
	if !reflect.DeepEqual(o.headers, want) {
		t.Errorf("headers with spaces = %v, want %v", o.headers, want)
	}
}

func TestParseScanArgsHeadersLastWins(t *testing.T) {
	_, o := parseScanArgs([]string{
		"http://example.test",
		"--headers", "A: 1",
		"--headers", "B: 2",
	})
	want := map[string]string{"B": "2"}
	if !reflect.DeepEqual(o.headers, want) {
		t.Errorf("headers after repeat = %v, want %v (last wins, no merge)", o.headers, want)
	}
}

func TestParseHeadersMalformed(t *testing.T) {
	for _, v := range []string{"NoColon", " :value", "A: 1,NoColon"} {
		if _, err := parseHeaders(v); err == nil {
			t.Errorf("parseHeaders(%q) = nil error, want malformed error", v)
		}
	}
	if h, err := parseHeaders(""); err != nil || len(h) != 0 {
		t.Errorf("parseHeaders(\"\") = %v, %v; want empty map, nil error", h, err)
	}
}

func TestParseScanArgsExcludeVulns(t *testing.T) {
	_, o := parseScanArgs([]string{
		"http://example.test",
		"--exclude-vulns", "CVE-2026-1111, CVE-2026-2222, ",
	})
	want := []string{"CVE-2026-1111", "CVE-2026-2222"}
	if !reflect.DeepEqual(o.excludeVulns, want) {
		t.Errorf("excludeVulns = %v, want %v", o.excludeVulns, want)
	}
}

func TestParseScanArgsForceCookieVhost(t *testing.T) {
	_, o := parseScanArgs([]string{
		"http://example.test",
		"--force",
		"--cookie", "wordpress_sec=abc; wp_lang=en",
		"--vhost", "vhost.example",
	})
	if !o.force {
		t.Error("force = false, want true")
	}
	if o.cookie != "wordpress_sec=abc; wp_lang=en" {
		t.Errorf("cookie = %q", o.cookie)
	}
	if o.vhost != "vhost.example" {
		t.Errorf("vhost = %q, want vhost.example", o.vhost)
	}
}

func TestScannerOptionsFromWiresAuthHeadersVHostForceExcludeVulns(t *testing.T) {
	o := scanOptions{
		basicAuthUser: "admin",
		basicAuthPass: "hunter2",
		cookie:        "a=1; b=2",
		headers:       map[string]string{"X-Api-Key": "abc"},
		vhost:         "vhost.example",
		force:         true,
		excludeVulns:  []string{"CVE-2026-1111", "CVE-2026-2222"},
	}
	opts := scannerOptionsFrom(o, nil)
	if opts.BasicAuthUser != "admin" {
		t.Errorf("BasicAuthUser = %q, want admin", opts.BasicAuthUser)
	}
	if opts.BasicAuthPass != "hunter2" {
		t.Errorf("BasicAuthPass = %q, want hunter2", opts.BasicAuthPass)
	}
	if opts.Cookie != "a=1; b=2" {
		t.Errorf("Cookie = %q, want a=1; b=2", opts.Cookie)
	}
	if !reflect.DeepEqual(opts.Headers, o.headers) {
		t.Errorf("Headers = %v, want %v", opts.Headers, o.headers)
	}
	if opts.VHost != "vhost.example" {
		t.Errorf("VHost = %q, want vhost.example", opts.VHost)
	}
	if !opts.Force {
		t.Error("Force = false, want true")
	}
	if !reflect.DeepEqual(opts.ExcludeVulns, o.excludeVulns) {
		t.Errorf("ExcludeVulns = %v, want %v", opts.ExcludeVulns, o.excludeVulns)
	}
}

func TestScannerOptionsForRunContextWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := scannerOptionsForRun(scanOptions{}, nil, ctx)
	if opts.Context != ctx {
		t.Errorf("Context without MaxScanDuration = %v, want signal ctx", opts.Context)
	}

	o := scanOptions{maxScanDuration: 30 * time.Second}
	if got := scannerOptionsForRun(o, nil, ctx).Context; got != ctx {
		t.Errorf("Context with MaxScanDuration = %v, want signal ctx as timeout parent", got)
	}
}

func TestScanSignalContext(t *testing.T) {
	ctx, cancel := scanSignalContext()
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("signal context already canceled")
	default:
	}
	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("signal context not canceled after cancel()")
	}
}
