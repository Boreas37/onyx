package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socks5Dialer is a hand-rolled RFC 1928 SOCKS5 CONNECT client (no external
// dependencies). It dials a target address through a SOCKS5 proxy,
// optionally authenticating with username/password (RFC 1929).
//
// localResolve selects the proxy semantics for the two supported URL
// flavours: socks5:// resolves the target hostname locally and sends the
// proxy a raw IP address, while socks5h:// (host-resolve) sends the
// hostname so the proxy performs DNS itself.
type socks5Dialer struct {
	proxyAddr    string // host:port of the SOCKS5 proxy
	user, pass   string // RFC 1929 credentials (empty = no auth)
	localResolve bool   // socks5:// resolves DNS locally, socks5h:// via proxy
	base         func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext connects to addr through the SOCKS5 proxy. The returned
// connection is ready for use: greeting, optional auth and the CONNECT
// handshake have all completed.
func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5: unsupported network %q", network)
	}
	if d.localResolve {
		resolved, err := resolveHost(ctx, addr)
		if err != nil {
			return nil, err
		}
		addr = resolved
	}

	conn, err := d.base(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dialing proxy %s: %w", d.proxyAddr, err)
	}
	// Bound the handshake by the caller's deadline (the request context),
	// so a hung proxy cannot outlive the request timeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	defer conn.SetDeadline(time.Time{})

	if err := d.handshake(ctx, conn, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// handshake performs the RFC 1928 greeting, optional RFC 1929 auth and the
// CONNECT request, verifying every reply.
func (d *socks5Dialer) handshake(ctx context.Context, conn net.Conn, addr string) error {
	// Greeting: version 5, offer no-auth and (with credentials) user/pass.
	methods := []byte{socks5MethodNoAuth}
	if d.user != "" || d.pass != "" {
		methods = append(methods, socks5MethodUserPass)
	}
	greet := make([]byte, 0, 2+len(methods))
	greet = append(greet, socks5Version, byte(len(methods)))
	greet = append(greet, methods...)
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("socks5: server version %d, want 5", reply[0])
	}
	switch reply[1] {
	case socks5MethodNoAuth:
	case socks5MethodUserPass:
		if err := d.authenticate(conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5: no acceptable auth method (server offered %d)", reply[1])
	}

	// CONNECT request (RFC 1928 section 4).
	req, err := socks5ConnectRequest(addr)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}
	status, err := socks5ReadReply(conn)
	if err != nil {
		return err
	}
	if status != socks5ReplySuccess {
		return fmt.Errorf("socks5 connect to %s: %s", addr, socks5ReplyName(status))
	}
	return nil
}

// authenticate runs the RFC 1929 username/password sub-negotiation.
func (d *socks5Dialer) authenticate(conn net.Conn) error {
	if d.user == "" {
		return errors.New("socks5: server requires authentication but no --proxy-auth was given")
	}
	msg := make([]byte, 0, 3+len(d.user)+len(d.pass))
	msg = append(msg, 0x01, byte(len(d.user)))
	msg = append(msg, d.user...)
	msg = append(msg, byte(len(d.pass)))
	msg = append(msg, d.pass...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5 auth: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 auth reply: %w", err)
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		return fmt.Errorf("socks5: username/password authentication failed (%d)", reply[1])
	}
	return nil
}

// resolveHost resolves addr's hostname locally when the target is not
// already an IP address, returning "ip:port" for the proxy CONNECT request.
// socks5:// semantics.
func resolveHost(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}
	if net.ParseIP(host) != nil {
		return addr, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("socks5: resolving %s: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			host = v4.String()
			break
		}
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("socks5: no address for %s", host)
	}
	if port == "" {
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

// socks5ConnectRequest builds an RFC 1928 CONNECT payload for addr
// ("host:port"), encoding the address as IPv4 (ATYP 1), IPv6 (ATYP 4) or a
// domain name (ATYP 3).
func socks5ConnectRequest(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target address %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("socks5: invalid target port %q", portStr)
	}
	req := []byte{socks5Version, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5: target hostname too long (%d bytes)", len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	return append(req, byte(port>>8), byte(port)), nil
}

// socks5ReadReply reads and validates a SOCKS5 reply, consuming the bound
// address field. The connection status byte is returned.
func socks5ReadReply(conn net.Conn) (byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if header[0] != socks5Version {
		return 0, fmt.Errorf("socks5: reply version %d, want 5", header[0])
	}
	var addrLen int
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return 0, fmt.Errorf("socks5 connect reply: %w", err)
		}
		addrLen = int(lb[0])
	case 0x04:
		addrLen = 16
	default:
		return 0, fmt.Errorf("socks5: reply ATYP %d", header[3])
	}
	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return 0, fmt.Errorf("socks5 connect reply: %w", err)
	}
	return header[1], nil
}

// socks5ReplyName maps the RFC 1928 reply status codes to their error text.
func socks5ReplyName(code byte) string {
	switch code {
	case socks5ReplySuccess:
		return "succeeded"
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return fmt.Sprintf("unknown error %d", code)
}

const (
	socks5Version        = 0x05
	socks5MethodNoAuth   = 0x00
	socks5MethodUserPass = 0x02

	socks5ReplySuccess = 0x00
)
