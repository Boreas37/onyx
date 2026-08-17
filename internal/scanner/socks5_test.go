package scanner

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Boreas37/onyx/internal/db"
)

// socks5ConnLog records one CONNECT request as seen by the fake proxy.
type socks5ConnLog struct {
	target string // requested DST.ADDR:DST.PORT
	atyp   byte   // 1 = IPv4, 3 = domain, 4 = IPv6
	user   string // RFC 1929 username ("" when unauthenticated)
	pass   string
}

type socks5Log struct {
	mu       sync.Mutex
	conns    []socks5ConnLog
	needAuth bool
	user     string
	pass     string
}

func (l *socks5Log) snapshot() []socks5ConnLog {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]socks5ConnLog(nil), l.conns...)
}

// fakeSocks5Proxy starts a minimal SOCKS5 server (RFC 1928 + RFC 1929 auth)
// that answers CONNECT requests by dialing the requested target and
// relaying bytes both ways, so end-to-end HTTP through the proxy works.
func fakeSocks5Proxy(t *testing.T, needAuth bool, user, pass string) (string, *socks5Log) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &socks5Log{needAuth: needAuth, user: user, pass: pass}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go log.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), log
}

// serve handles one client connection: handshake, CONNECT, then relay.
func (l *socks5Log) serve(conn net.Conn) {
	defer conn.Close()
	var entry socks5ConnLog
	if err := l.handshake(conn, &entry); err != nil {
		return
	}
	up, err := net.Dial("tcp", entry.target)
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	// Success reply with 0.0.0.0:0 bound address (RFC 1928 6).
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	l.mu.Lock()
	l.conns = append(l.conns, entry)
	l.mu.Unlock()
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// handshake implements the server side of RFC 1928 (greeting, method
// selection, optional RFC 1929 auth, CONNECT parse). The request details
// land in e; entry is only logged after the relay starts.
func (l *socks5Log) handshake(conn net.Conn, e *socks5ConnLog) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] == 0 {
		return fmt.Errorf("bad greeting")
	}
	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if l.needAuth {
		offered := false
		for _, m := range methods {
			if m == 2 {
				offered = true
			}
		}
		if !offered {
			_, _ = conn.Write([]byte{5, 0xff})
			return fmt.Errorf("no usr/pass method offered")
		}
		if _, err := conn.Write([]byte{5, 2}); err != nil {
			return err
		}
		if err := l.authenticate(conn, e); err != nil {
			return err
		}
	} else if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[1] != 1 { // CONNECT
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("command %d, want CONNECT", hdr[1])
	}
	var host string
	switch hdr[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return err
		}
		name := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return err
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	default:
		return fmt.Errorf("atyp %d", hdr[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return err
	}
	e.atyp = hdr[3]
	e.target = net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
	return nil
}

// authenticate runs the server side of the RFC 1929 username/password
// sub-negotiation.
func (l *socks5Log) authenticate(conn net.Conn, e *socks5ConnLog) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 1 {
		return fmt.Errorf("auth version %d, want 1", hdr[0])
	}
	uname := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(conn, pl); err != nil {
		return err
	}
	pass := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	e.user, e.pass = string(uname), string(pass)
	if e.user != l.user || e.pass != l.pass {
		_, _ = conn.Write([]byte{1, 1})
		return fmt.Errorf("credentials rejected")
	}
	_, err := conn.Write([]byte{1, 0})
	return err
}

// TestSocks5ProxyScan verifies a full scan through a hand-rolled SOCKS5
// proxy (no auth): every request is relayed by the proxy, the CONNECT
// target is the scanned host and the WordPress evidence still comes back.
func TestSocks5ProxyScan(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()
	proxyAddr, plog := fakeSocks5Proxy(t, false, "", "")

	d, err := db.Load(minimalFeed(t))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner(d, srv.URL, Options{Proxy: "socks5://" + proxyAddr, Enumerate: "p"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection through the SOCKS5 proxy")
	}
	conns := plog.snapshot()
	if len(conns) == 0 {
		t.Fatal("no CONNECT requests reached the SOCKS5 proxy")
	}
	wantHost := srv.Listener.Addr().String()
	for i, c := range conns {
		if c.target != wantHost {
			t.Errorf("CONNECT[%d] target = %q, want %q", i, c.target, wantHost)
		}
		if c.user != "" || c.pass != "" {
			t.Errorf("CONNECT[%d] carried auth %q:%q without --proxy-auth", i, c.user, c.pass)
		}
	}
}

// TestSocks5hProxyScan verifies the socks5h semantic: the hostname is sent
// to the proxy (ATYP 3) instead of being resolved locally.
func TestSocks5hProxyScan(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	proxyAddr, plog := fakeSocks5Proxy(t, false, "", "")

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, base, Options{Proxy: "socks5h://" + proxyAddr, Enumerate: "p"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.IsWordPress {
		t.Fatal("expected WordPress detection through the socks5h proxy")
	}
	conns := plog.snapshot()
	if len(conns) == 0 {
		t.Fatal("no CONNECT requests reached the socks5h proxy")
	}
	wantPort := srv.Listener.Addr().(*net.TCPAddr).Port
	for i, c := range conns {
		if c.atyp != 3 {
			t.Errorf("CONNECT[%d] ATYP = %d, want 3 (domain via proxy)", i, c.atyp)
		}
		if c.target != net.JoinHostPort("localhost", strconv.Itoa(wantPort)) {
			t.Errorf("CONNECT[%d] target = %q, want localhost port %d", i, c.target, wantPort)
		}
	}
}

// TestSocks5ProxyAuth verifies RFC 1929 username/password auth: valid
// --proxy-auth credentials get through, while wrong or missing credentials
// fail the scan with a hard error.
func TestSocks5ProxyAuth(t *testing.T) {
	srv := fakeWordPress()
	defer srv.Close()
	proxyAddr, _ := fakeSocks5Proxy(t, true, "user", "pass")

	d, _ := db.Load(minimalFeed(t))
	sc, err := NewScanner(d, srv.URL, Options{Proxy: "socks5://" + proxyAddr, ProxyAuth: "user:pass", Enumerate: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Scan(); err != nil {
		t.Fatalf("Scan with valid credentials: %v", err)
	}

	for _, auth := range []string{"user:nope", ""} {
		sc, err := NewScanner(d, srv.URL, Options{Proxy: "socks5://" + proxyAddr, ProxyAuth: auth, Enumerate: "p"})
		if err != nil {
			t.Fatal(err)
		}
		res, err := sc.Scan()
		if err == nil || res != nil {
			t.Fatalf("auth %q: expected fatal scan error, got res=%v err=%v", auth, res, err)
		}
		if !strings.Contains(err.Error(), "cannot reach target") {
			t.Errorf("auth %q: error = %q, want cannot-reach-target", auth, err)
		}
	}
}

func TestSocks5ProxyAuthRequiresUserPassFormat(t *testing.T) {
	proxyAddr, _ := fakeSocks5Proxy(t, false, "", "")
	_, err := NewScanner(nil, "http://example.test", Options{
		Proxy:     "socks5://" + proxyAddr,
		ProxyAuth: "no-colon-here",
	})
	if err == nil {
		t.Fatal("expected error for --proxy-auth without a colon")
	}
	if !strings.Contains(err.Error(), "USER:PASS") {
		t.Errorf("error = %q, want USER:PASS hint", err)
	}
}
