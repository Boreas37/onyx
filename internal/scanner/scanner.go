package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Boreas37/onyx/internal/db"
	"github.com/Boreas37/onyx/internal/nuclei"
	"github.com/Boreas37/onyx/internal/pocs"
	"github.com/Boreas37/onyx/internal/progress"
	"github.com/Boreas37/onyx/internal/version"
)

// ErrNotWordPress is returned when a scan target shows no WordPress signs.
var ErrNotWordPress = errors.New("target does not appear to be a WordPress site")

// ErrOutOfScope is returned when --scope does not match the target URL.
var ErrOutOfScope = errors.New("target out of scope")

// ErrBlocked is returned when the homepage HTML matches
// --exclude-content-based (WAF or error page).
var ErrBlocked = errors.New("blocked by WAF or error page")

// ErrRedirectBlocked is wrapped by the redirect guard when a Location would
// cross the scanned target's host:port authority or exceed the hop limit.
// It is not a transport failure, so it is never retried by sendRequest.
var ErrRedirectBlocked = errors.New("redirect blocked")

// maxBodySize caps response bodies (readme.txt / style.css are small).
const maxBodySize = 1 << 20

// defaultTopSlugs is how many vuln-heavy slugs to brute-force enumerate
// aggressively after passive detection from the homepage HTML.
const defaultTopSlugs = 200

// defaultMaxRequests caps the brute-force enumeration request budget.
const defaultMaxRequests = 500

// maxAuthorChecks is how many /?author=N redirects to follow at most.
const maxAuthorChecks = 10

// authorSlugRe matches the author archive path the /?author=N redirect
// chain lands on. The optional leading slash prefix also covers
// subdirectory multisite installs (/blog/author/<slug>/).
var authorSlugRe = regexp.MustCompile(`(?:^|/)author/([^/?#]+)`)

// Options tunes the scan behaviour. Zero values fall back to defaults.
type Options struct {
	Threads             int           // concurrent HTTP requests (default 5)
	Timeout             time.Duration // per-request timeout (default 10s, alias for RequestTimeout)
	Stealth             bool          // throttle to 1 request/second
	RateLimit           float64       // max requests per second (0 = unlimited)
	APIOnly             bool          // skip brute-force enumeration, only wp-json/plugins
	MaxRequests         int           // cap on brute-force enumeration requests (default 500)
	Enumerate           string        // what to enumerate: u/p/t, combinable (default "pt")
	UserAgent           string        // custom User-Agent for all requests
	RandomUA            bool          // pick a random browser User-Agent per request
	DetectionMode       string        // passive (homepage only), aggressive (DB only), mixed (default)
	Proxy               string        // http://, https://, socks5:// or socks5h:// proxy URL
	ProxyAuth           string        // --proxy-auth USER:PASS for SOCKS5 proxies (RFC 1929)
	ProxyTargetOnly     bool          // --proxy-target-only: use the proxy only for target-host traffic
	TLSFingerprint      string        // --tls-fingerprint: chrome | firefox | random (TLSClientConfig variations)
	PerHostRateLimit    float64       // --per-host-rate-limit N: per-host requests per second (0 = off)
	NoXMLRPC            bool          // skip the XML-RPC (xmlrpc.php) ping check
	Checks              string        // extra checks: cb (config backups), dbe (db exports), comma-separated
	ConnectTimeout      time.Duration // TCP dial timeout (default 10s)
	RequestTimeout      time.Duration // per-request timeout (default 10s)
	ContentDir          string        // wp-content directory (default "wp-content")
	PluginsDir          string        // plugins directory (default "wp-content/plugins")
	ExcludeContentBased string        // regex; matching homepage HTML aborts the scan
	Scope               string        // regex; a non-matching target URL is out of scope
	PluginsList         string        // file with plugin slugs (one per line, # comments)
	ThemesList          string        // file with theme slugs (one per line, # comments)
	MaxScanDuration     time.Duration // hard stop for the whole scan; 0 = unlimited
	CacheTTL            time.Duration // HTTP response cache TTL; 0 = off
	CrawlPages          int           // --crawl-pages N: passively crawl up to N sitemap pages (0 = disabled)
	Findings            chan Finding  // when set, every finding is emitted live

	PasswordsFile string // --passwords FILE: wordlist for the wp-login brute force (one per line)
	UsernamesFile string // --usernames FILE: wordlist for brute-force attacks (one per line)
	User          string // --user USER: single username for the XML-RPC multicall attack
	XMLRPCBrute   string // --xmlrpc-brute FILE: wordlist for the XML-RPC multicall attack
	MCPerRequest  int    // --multicall-max-passwords N: passwords per multicall request (default 3)
	WPAuth        string // --wp-auth USER:PASS: Basic auth for the REST inventory
	NoBrute       bool   // --no-brute: disable credential brute force (login + XML-RPC)
	NoSummary     bool   // --no-summary: skip gathering scan summary statistics

	// FingerprintDB is an optional path to a JSON core-fingerprint table
	// ("{"files": {path: {md5hex: [versions]}}}") used as a final core
	// version fallback when meta/RSS/OPML sources all fail. A missing or
	// unparseable table is silently skipped. Disabled when empty.
	FingerprintDB string
	// PopularSlugs appends the static popular plugin/theme slug seed lists
	// (popular.go) to aggressive enumeration after the DB top-slug list.
	// The CLI flag defaults it to true; building Options directly leaves
	// the zero value (false), which keeps the seed lists off.
	PopularSlugs bool
	// AllowForeignRedirect allows following HTTP redirects whose target
	// host:port differs from the scanned target's authority. The default
	// (false) blocks foreign redirects as SSRF hardening, surfacing them as
	// fetch errors.
	AllowForeignRedirect bool
	// MaxRetries is how many times a transient transport error (a non-HTTP
	// failure from the transport layer) is retried with exponential backoff
	// plus jitter before giving up. The CLI flag defaults it to 2; 0
	// disables retries entirely.
	MaxRetries int
}

// Scanner drives one scan against a single target.
type Scanner struct {
	db          *db.DB
	base        string
	client      *http.Client
	opts        Options
	lim         *rateLimiter
	enum        string
	maxRequests int
	mode        string // detection mode: passive | aggressive | mixed
	progress    *progress.Bar
	homepage    string // raw homepage HTML for passive slug detection

	coreEvidence []CoreEvidence // core version observations (meta/rss/opml)

	sitemapPlugins  []string          // slugs discovered by --crawl-pages sitemap crawling
	sitemapThemes   []string          //
	sitemapVersions map[string]string // slug -> ?ver= version from sitemap pages
	sitemapRequests int               // HTTP requests spent on sitemap discovery

	rlMu          sync.Mutex // guards the rate-limit state below
	rateHits      int        // count of 429 responses seen
	rlBackoff     time.Duration
	maxBackoff    time.Duration
	cooldownUntil time.Time     // global pause: every fetch gates on this
	consecOK      int           // consecutive non-429 responses
	sendSlot      time.Time     // next permitted send instant (adaptive pacing)
	spacing       time.Duration // adaptive minimum gap between requests

	abortRateLimited atomic.Bool // set when throttling makes enumeration futile

	perHostMu       sync.Mutex              // guards perHostLim
	perHostLim      map[string]*rateLimiter // --per-host-rate-limit: one limiter per scheme://host:port
	perHostInterval time.Duration

	checks     map[string]bool // extra checks requested via --checks (cb, dbe)
	contentDir string
	pluginsDir string

	scopeRe   *regexp.Regexp // --scope target URL filter
	excludeRe *regexp.Regexp // --exclude-content-based homepage filter

	pluginsList []string        // explicit plugin slugs (--plugins-list)
	themesList  []string        // explicit theme slugs (--themes-list)
	ctx         context.Context // scan-wide context (--max-scan-duration)
	cacheDir    string          // HTTP cache directory (--cache-ttl)

	passwords       []string // --passwords wordlist (wp-login brute)
	xmlrpcPasswords []string // --xmlrpc-brute wordlist
	usernames       []string // --usernames wordlist
	singleUser      string   // --user USER
	wpUser          string   // --wp-auth USER:PASS credentials
	wpPass          string
	mcPerReq        int          // passwords per XML-RPC multicall request
	bruteLim        *rateLimiter // brute-force throttle (1 req/s unless --rate-limit)
	loginBrute      bool         // wp-login brute force requested
	xmlrpcBrute     bool         // XML-RPC multicall attack requested
	requests        atomic.Int64 // total HTTP requests issued through fetch()

	fingerprintOnce sync.Once
	fingerprintTab  *fingerprintTable
	fingerprintErr  error
}

// configBackupFiles are the wp-config.php backup names probed by the cb
// check at the site root.
var configBackupFiles = []string{
	"wp-config.php~", "wp-config.php.bak", "wp-config.bak", "wp-config.php.old",
	"wp-config.php.save", "wp-config.php.swp", "wp-config.txt", "wp-config.php.txt",
	".wp-config.php.swp", "wp-config.php.orig", "wp-config.php.dist", "wp-config.php.copy",
}

// dbExportFiles are the SQL dump names probed by the dbe check, at the root
// and inside dbExportDirs.
var dbExportFiles = []string{
	"dump.sql", "backup.sql", "db.sql", "database.sql", "wp.sql",
	"db_backup.sql", "site.sql", "wordpress.sql", "mysql.sql",
}

// dbExportDirs are the subdirectories where dbe also probes for SQL dumps.
var dbExportDirs = []string{
	"/db/", "/backup/", "/sql/", "/dump/", "/database/",
}

// timthumbPaths are the locations probed by the timthumb check.
var timthumbPaths = []string{
	"/wp-content/plugins/timthumb.php",
	"/timthumb.php",
}

// timthumbFinder probes for an exposed TimThumb image-resizer copy: any of
// timthumbPaths answering 200 with a body mentioning timthumb.
func (s *Scanner) timthumbFinder() []string {
	var found []string
	for _, p := range timthumbPaths {
		code, body, err := s.fetch(p)
		if err != nil || code != http.StatusOK {
			continue
		}
		if strings.Contains(strings.ToLower(string(body)), "timthumb") {
			found = append(found, p)
		}
	}
	return found
}

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

// readSlugList loads a slug list file (one slug per line, # comments
// allowed) for --plugins-list / --themes-list.
func readSlugList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// readList loads a plain wordlist file (one entry per line; blank lines are
// skipped). Used for --passwords / --usernames / --xmlrpc-brute files, where
// comment stripping would corrupt entries.
func readList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// browserUAs is a small fixed set of realistic desktop browser User-Agent
// strings used by --random-user-agent.
var browserUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
}

// uaTransport stamps the configured or a random browser User-Agent onto
// every outbound request.
type uaTransport struct {
	base      http.RoundTripper
	userAgent string
	randomUA  bool
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ua := t.userAgent
	if ua == "" && t.randomUA {
		ua = browserUAs[rand.IntN(len(browserUAs))]
	}
	if ua != "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", ua)
	}
	return t.base.RoundTrip(req)
}

func (r *rateLimiter) wait() {
	if r == nil || r.interval <= 0 {
		return
	}
	for {
		r.mu.Lock()
		now := time.Now()
		if wait := r.last.Add(r.interval).Sub(now); wait > 0 {
			r.mu.Unlock()
			time.Sleep(wait)
			continue
		}
		r.last = now
		r.mu.Unlock()
		return
	}
}

// perHostWait throttles on the --per-host-rate-limit limiter for the host
// of u, keyed by scheme://host:port. Every unique host gets its own lazily
// created limiter, so one busy host never throttles another.
func (s *Scanner) perHostWait(u string) {
	if s.perHostLim == nil {
		return
	}
	key := perHostKey(u)
	s.perHostMu.Lock()
	lim := s.perHostLim[key]
	if lim == nil {
		lim = &rateLimiter{interval: s.perHostInterval}
		s.perHostLim[key] = lim
	}
	s.perHostMu.Unlock()
	lim.wait()
}

// perHostKey maps a full URL onto its scheme://host[:port] limiter key.
func perHostKey(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	return pu.Scheme + "://" + pu.Host
}

// targetAuthority returns the normalized "host:port" authority of the
// scanned base URL (filling in the scheme-default port), used by
// --proxy-target-only to pick proxy-worthy traffic.
func targetAuthority(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

// normalizeAuthority fills in the scheme-default port when host has none
// (http URLs carry no explicit port on the default port).
func normalizeAuthority(host, scheme string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	switch scheme {
	case "http":
		return net.JoinHostPort(host, "80")
	case "https":
		return net.JoinHostPort(host, "443")
	}
	return host
}

// sameAuthority reports whether addr ("host" or "host:port") refers to the
// same host:port endpoint as want ("host:port"), ignoring case. Two
// different services on the same hostname (different ports) are distinct.
func sameAuthority(addr, want string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}
	whost, wport, err := net.SplitHostPort(want)
	if err != nil {
		return false
	}
	return strings.EqualFold(host, whost) && port == wport
}

// NewScanner builds a Scanner for base, using the given database and
// options.
func NewScanner(database *db.DB, base string, opts Options) (*Scanner, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL %q", base)
	}
	if opts.Threads <= 0 {
		opts.Threads = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = opts.Timeout
	}
	contentDir := strings.Trim(opts.ContentDir, "/")
	if contentDir == "" {
		contentDir = "wp-content"
	}
	pluginsDir := strings.Trim(opts.PluginsDir, "/")
	if pluginsDir == "" {
		pluginsDir = "wp-content/plugins"
	}
	checks := make(map[string]bool)
	if opts.Checks != "" {
		for _, c := range strings.Split(opts.Checks, ",") {
			c = strings.ToLower(strings.TrimSpace(c))
			if c == "" {
				continue
			}
			if c != "cb" && c != "dbe" && c != "timthumb" {
				return nil, fmt.Errorf("invalid --checks value %q (use cb, dbe and/or timthumb)", c)
			}
			checks[c] = true
		}
	}
	enum := strings.ToLower(strings.TrimSpace(opts.Enumerate))
	if enum == "" {
		enum = "pt"
	}
	for _, c := range enum {
		if c != 'p' && c != 't' && c != 'u' && c != 'm' {
			return nil, fmt.Errorf("invalid --enumerate value %q (use p, t, u and/or m)", opts.Enumerate)
		}
	}
	var scopeRe, excludeRe *regexp.Regexp
	if opts.Scope != "" {
		re, err := regexp.Compile(opts.Scope)
		if err != nil {
			return nil, fmt.Errorf("invalid --scope regex %q: %v", opts.Scope, err)
		}
		scopeRe = re
	}
	if opts.ExcludeContentBased != "" {
		re, err := regexp.Compile(opts.ExcludeContentBased)
		if err != nil {
			return nil, fmt.Errorf("invalid --exclude-content-based regex %q: %v", opts.ExcludeContentBased, err)
		}
		excludeRe = re
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = defaultMaxRequests
	}
	mode := strings.ToLower(strings.TrimSpace(opts.DetectionMode))
	if mode == "" {
		mode = "mixed"
	}
	switch mode {
	case "passive", "aggressive", "mixed":
	default:
		return nil, fmt.Errorf("invalid --detection-mode %q (use passive, aggressive or mixed)", opts.DetectionMode)
	}
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	dialCtx := dialer.DialContext
	tr := &http.Transport{
		MaxIdleConns:        opts.Threads * 2,
		MaxIdleConnsPerHost: opts.Threads,
		IdleConnTimeout:     30 * time.Second,
		DialContext:         dialCtx,
	}

	// --tls-fingerprint: hand-rolled TLSClientConfig variations (chrome,
	// firefox) or per-request rotation (random). Real JA3 fingerprints
	// would need uTLS — these stdlib-only variations are intended against
	// naive WAF TLS checks.
	fingerprint := strings.ToLower(strings.TrimSpace(opts.TLSFingerprint))
	switch fingerprint {
	case "", "off":
	case "chrome", "firefox", "random":
	default:
		return nil, fmt.Errorf("invalid --tls-fingerprint %q (use chrome, firefox or random)", opts.TLSFingerprint)
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil || proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", opts.Proxy)
		}
		switch proxyURL.Scheme {
		case "http", "https":
			if opts.ProxyTargetOnly {
				targetHost := targetAuthority(u)
				tr.Proxy = func(req *http.Request) (*url.URL, error) {
					if sameAuthority(normalizeAuthority(req.URL.Host, req.URL.Scheme), targetHost) {
						return proxyURL, nil
					}
					return nil, nil
				}
			} else {
				tr.Proxy = http.ProxyURL(proxyURL)
			}
		case "socks5", "socks5h":
			sd := &socks5Dialer{
				proxyAddr:    proxyURL.Host,
				localResolve: proxyURL.Scheme == "socks5",
				base:         dialer.DialContext,
			}
			if opts.ProxyAuth != "" {
				i := strings.IndexByte(opts.ProxyAuth, ':')
				if i <= 0 || i == len(opts.ProxyAuth)-1 {
					return nil, fmt.Errorf("invalid --proxy-auth %q (must be USER:PASS)", opts.ProxyAuth)
				}
				sd.user, sd.pass = opts.ProxyAuth[:i], opts.ProxyAuth[i+1:]
			}
			targetHost := targetAuthority(u)
			dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if opts.ProxyTargetOnly && !sameAuthority(addr, targetHost) {
					return dialer.DialContext(ctx, network, addr)
				}
				return sd.DialContext(ctx, network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (only http, https, socks5 and socks5h are supported)", proxyURL.Scheme)
		}
	}
	tr.DialContext = dialCtx

	switch fingerprint {
	case "chrome", "firefox":
		tr.TLSClientConfig = tlsFingerprintConfig(fingerprint)
	case "random":
		if tr.Proxy != nil {
			// Go's http.Transport refuses a custom TLS dialer when
			// dialing through an HTTP proxy, so fall back to one random
			// combination for the whole scan.
			tr.TLSClientConfig = randomTLSFingerprint()
		} else {
			// One fresh connection per request (keep-alives off), each
			// handshaking with a randomly picked fingerprint.
			tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialCtx(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(conn, randomTLSFingerprint())
				if err := tc.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tc, nil
			}
			tr.DisableKeepAlives = true
		}
	}
	client := &http.Client{
		Timeout:   opts.RequestTimeout,
		Transport: tr,
	}
	// Cross-host redirect restriction (SSRF hardening): allow a redirect
	// only when it stays on the scanned target's host:port authority (or
	// --allow-foreign-redirect opts in), and never more than 9 hops.
	// Rejected redirects surface as errors from fetch-like helpers instead
	// of silently following an attacker-chosen Location. fetchNoRedirect
	// copies the client and swaps this hook for ErrUseLastResponse, so the
	// author-enumeration redirect chain is unaffected.
	targetAuth := targetAuthority(u)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("%w: stopped after 10 redirects", ErrRedirectBlocked)
		}
		if !opts.AllowForeignRedirect &&
			!sameAuthority(normalizeAuthority(req.URL.Host, req.URL.Scheme), targetAuth) {
			return fmt.Errorf("%w: redirect to %q (scanned authority %s; use --allow-foreign-redirect to follow)",
				ErrRedirectBlocked, req.URL.Host, targetAuth)
		}
		return nil
	}
	if opts.UserAgent != "" || opts.RandomUA {
		client.Transport = &uaTransport{
			base:      client.Transport,
			userAgent: opts.UserAgent,
			randomUA:  opts.RandomUA,
		}
	}
	s := &Scanner{
		db:          database,
		base:        strings.TrimRight(base, "/"),
		client:      client,
		opts:        opts,
		enum:        enum,
		maxRequests: opts.MaxRequests,
		mode:        mode,
		checks:      checks,
		contentDir:  contentDir,
		pluginsDir:  pluginsDir,
		scopeRe:     scopeRe,
		excludeRe:   excludeRe,
	}
	if opts.PluginsList != "" {
		s.pluginsList, err = readSlugList(opts.PluginsList)
		if err != nil {
			return nil, fmt.Errorf("reading plugins list: %w", err)
		}
	}
	if opts.ThemesList != "" {
		s.themesList, err = readSlugList(opts.ThemesList)
		if err != nil {
			return nil, fmt.Errorf("reading themes list: %w", err)
		}
	}

	// Wordlists and credentials for the exploit-oriented checks. Both
	// brute-force attacks share the --usernames wordlist (the XML-RPC
	// attack also accepts a single --user USER).
	if opts.UsernamesFile != "" {
		s.usernames, err = readList(opts.UsernamesFile)
		if err != nil {
			return nil, fmt.Errorf("reading usernames list: %w", err)
		}
		if len(s.usernames) == 0 {
			return nil, fmt.Errorf("usernames list %s is empty", opts.UsernamesFile)
		}
	}
	if opts.User != "" {
		s.singleUser = opts.User
	}
	if opts.WPAuth != "" {
		i := strings.IndexByte(opts.WPAuth, ':')
		if i <= 0 || i == len(opts.WPAuth)-1 {
			return nil, fmt.Errorf("invalid --wp-auth %q (must be USER:PASS)", opts.WPAuth)
		}
		s.wpUser, s.wpPass = opts.WPAuth[:i], opts.WPAuth[i+1:]
	}
	s.mcPerReq = opts.MCPerRequest
	if s.mcPerReq == 0 {
		s.mcPerReq = 3
	}
	if s.mcPerReq < 0 {
		return nil, fmt.Errorf("invalid --multicall-max-passwords %d", opts.MCPerRequest)
	}
	if !opts.NoBrute {
		if opts.PasswordsFile != "" {
			list, lerr := readList(opts.PasswordsFile)
			if lerr != nil {
				return nil, fmt.Errorf("reading passwords list: %w", lerr)
			}
			if len(list) == 0 {
				return nil, fmt.Errorf("passwords list %s is empty", opts.PasswordsFile)
			}
			if len(s.usernames) == 0 && !strings.Contains(enum, "u") {
				return nil, fmt.Errorf("--passwords requires --usernames FILE or --enumerate u")
			}
			s.loginBrute = true
			s.passwords = list
		}
		if opts.XMLRPCBrute != "" {
			list, lerr := readList(opts.XMLRPCBrute)
			if lerr != nil {
				return nil, fmt.Errorf("reading XML-RPC passwords list: %w", lerr)
			}
			if len(list) == 0 {
				return nil, fmt.Errorf("passwords list %s is empty", opts.XMLRPCBrute)
			}
			if len(s.usernames) == 0 && s.singleUser == "" {
				return nil, fmt.Errorf("--xmlrpc-brute requires --usernames FILE or --user USER")
			}
			s.xmlrpcBrute = true
			s.xmlrpcPasswords = list
		}
	}
	if s.loginBrute || s.xmlrpcBrute {
		s.bruteLim = &rateLimiter{interval: time.Second}
		if opts.RateLimit > 0 {
			s.bruteLim.interval = time.Duration(float64(time.Second) / opts.RateLimit)
		}
	}
	if opts.CacheTTL > 0 {
		s.cacheDir = os.Getenv("ONYX_CACHE_DIR")
		if s.cacheDir == "" {
			home, herr := os.UserHomeDir()
			if herr != nil {
				home = "."
			}
			s.cacheDir = filepath.Join(home, ".cache", "onyx", "http")
		}
	}
	if opts.Stealth {
		s.lim = &rateLimiter{interval: time.Second}
	}
	if opts.RateLimit > 0 {
		s.lim = &rateLimiter{interval: time.Duration(float64(time.Second) / opts.RateLimit)}
	}
	if opts.PerHostRateLimit > 0 {
		s.perHostLim = make(map[string]*rateLimiter)
		s.perHostInterval = time.Duration(float64(time.Second) / opts.PerHostRateLimit)
	}
	s.maxBackoff = 30 * time.Second
	return s, nil
}

// SetProgress attaches a progress bar to the scanner. A nil bar disables
// progress reporting entirely.
func (s *Scanner) SetProgress(b *progress.Bar) {
	s.progress = b
}

// Progress returns the attached progress bar, or nil.
func (s *Scanner) Progress() *progress.Bar {
	return s.progress
}

// enumeratePlugins reports whether plugins should be enumerated.
func (s *Scanner) enumeratePlugins() bool { return strings.Contains(s.enum, "p") }

// enumerateThemes reports whether themes should be enumerated.
func (s *Scanner) enumerateThemes() bool { return strings.Contains(s.enum, "t") }

// enumerateUsers reports whether users should be enumerated.
func (s *Scanner) enumerateUsers() bool { return strings.Contains(s.enum, "u") }

// enumerateMedia reports whether media upload presence should be checked.
func (s *Scanner) enumerateMedia() bool { return strings.Contains(s.enum, "m") }

// Confidence scores attached to Detected/CoreEvidence entries, mapping each
// detection source onto a rough reliability estimate (100 = highest). These
// are assigned at the call sites that consume the extraction helpers, never
// inside the extractors themselves (which stay pure).
const (
	confReadmeStableTag = 95 // plugin readme.txt "Stable tag:" line
	confReadmeChangelog = 70 // plugin readme.txt Changelog heading
	confStyleCSS        = 90 // theme style.css "Version:" header
	confComposer        = 75 // plugin composer.json "version" field
	confMetaGenerator   = 90 // core generator meta tag
	confRSSGenerator    = 85 // core RSS feed generator element
	confOPMLGenerator   = 80 // core wp-links-opml.php generator attribute
	confPassiveVer      = 60 // passive asset ?ver= query string
	confREST            = 100
	confAuthREST        = 100
	confFingerprint     = 85 // core asset md5 fingerprint table
)

// sourceConfidence maps a Detected/CoreEvidence source onto its canonical
// confidence score. Unknown sources default to 0.
func sourceConfidence(source string) int {
	switch source {
	case "readme":
		return confReadmeStableTag
	case "readme-changelog":
		return confReadmeChangelog
	case "style.css":
		return confStyleCSS
	case "composer":
		return confComposer
	case "meta":
		return confMetaGenerator
	case "rss":
		return confRSSGenerator
	case "opml":
		return confOPMLGenerator
	case "passive-ver":
		return confPassiveVer
	case "rest":
		return confREST
	case "auth-rest":
		return confAuthREST
	case "fingerprint":
		return confFingerprint
	}
	return 0
}

// sourcePriority ranks Detected sources for dedup tie-breaking when two
// entries for the same slug carry the same confidence: the unauthenticated
// REST listing outranks the authenticated inventory, everything else is
// equal.
func sourcePriority(source string) int {
	switch source {
	case "rest":
		return 0
	case "auth-rest":
		return 1
	}
	return 2
}

// preferDetected reports whether a should replace b in a per-slug dedup
// when both entries carry the same slug. A version-known entry beats an
// unknown one; among version-known entries the higher confidence wins
// (so a passive ?ver= hint, confidence 60, never overrides a readme,
// confidence 95, and an unauthenticated REST listing, 100, wins a tie
// against the equally-scored auth-rest listing).
func preferDetected(a, b Detected) bool {
	aKnown := a.Version != "unknown" && a.Version != ""
	bKnown := b.Version != "unknown" && b.Version != ""
	if aKnown != bKnown {
		return aKnown
	}
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return sourcePriority(a.Source) < sourcePriority(b.Source)
}

// Detected is a plugin/theme/core component whose presence and version were
// identified on the target. Source records how it was found: "passive"
// (slug referenced in page HTML), "passive-ver" (asset ?ver= query string),
// "readme" (plugin readme.txt "Stable tag:" probe), "readme-changelog"
// (plugin readme.txt Changelog section heading), "composer" (plugin
// composer.json "version" field), "style.css" (theme stylesheet probe),
// "rest" (unauthenticated wp-json listing), "auth-rest" (authenticated
// wp-json inventory) or "fingerprint" (core asset md5 table). Confidence is
// the 0..100 reliability estimate assigned to the detection source (see
// sourceConfidence); it is omitted from JSON output when zero.
type Detected struct {
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Version    string `json:"installed_version"`
	Source     string `json:"source,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
}

// CoreEvidence records one WordPress core version observation together with
// the source that produced it: "meta" (generator meta tag), "rss" (feed
// generator element), "opml" (wp-links-opml.php generator attribute) or
// "fingerprint" (core asset md5 table). Confidence carries the same 0..100
// reliability score used by Detected.
type CoreEvidence struct {
	Source     string `json:"source"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence,omitempty"`
}

// Vulnerability is one matched database record.
type Vulnerability struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	CVE            string   `json:"cve"`
	CVSSScore      float64  `json:"cvss_score"`
	Rating         string   `json:"cvss_rating"`
	Description    string   `json:"description"`
	AffectedLabels []string `json:"affected_versions"`
	PublishedAt    string   `json:"published_at"`
	// Epss is the EXPloit Prediction Scoring System probability (0..1)
	// attached by the intel enrichment step; omitted when unknown.
	Epss float64 `json:"epss,omitempty"`
	// Kev reports whether the CVE is listed in the CISA Known Exploited
	// Vulnerabilities catalog; omitted when false.
	Kev bool `json:"kev,omitempty"`
}

// Finding links an installed component to its matching vulnerabilities.
type Finding struct {
	Slug             string          `json:"slug"`
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	InstalledVersion string          `json:"installed_version"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
}

// User is a WordPress user account discovered during enumeration. ID is the
// numeric user id (when known), Slug is the author-archive slug, Name is the
// display name (only the REST API provides it).
type User struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// LoginBrute is a credential pair that successfully authenticated against
// the target, either through wp-login.php or the XML-RPC endpoint.
type LoginBrute struct {
	User     string `json:"user"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// Summary holds scan-wide statistics, computed at the end of Scan() (skipped
// with --no-summary). Severity counts come from the findings.
type Summary struct {
	DurationMS  int64 `json:"duration_ms"`
	Requests    int   `json:"requests"`
	RateLimited int   `json:"rate_limited"`
	Detected    int   `json:"detected"`
	Findings    int   `json:"findings"`
	Critical    int   `json:"critical"`
	High        int   `json:"high"`
	Medium      int   `json:"medium"`
	Low         int   `json:"low"`
	Users       int   `json:"users"`
}

// Result is the output of a scan.
type Result struct {
	Target           string                `json:"target"`
	IsWordPress      bool                  `json:"is_wordpress"`
	WordPressVersion string                `json:"wordpress_version,omitempty"`
	CoreEvidence     []CoreEvidence        `json:"core_evidence,omitempty"` // which source produced WordPressVersion
	Evidence         []string              `json:"evidence,omitempty"`
	Detected         []Detected            `json:"detected,omitempty"`
	Findings         []Finding             `json:"findings,omitempty"`
	Nuclei           []nuclei.NucleiResult `json:"nuclei,omitempty"`
	PoCs             []pocs.PoCLink        `json:"pocs,omitempty"`
	Users            []User                `json:"users,omitempty"`
	XMLRPC           bool                  `json:"xmlrpc,omitempty"` // xmlrpc.php ping answered
	Interesting      []string              `json:"interesting,omitempty"`
	ConfigBackups    []string              `json:"config_backups,omitempty"`
	DBExports        []string              `json:"db_exports,omitempty"`
	RateLimitHits    int                   `json:"rate_limit_hits,omitempty"`    // 429s seen
	TimedOut         bool                  `json:"timed_out,omitempty"`          // --max-scan-duration expired
	RateLimitedAbort bool                  `json:"rate_limited_abort,omitempty"` // enumeration stopped: target kept answering 429
	Errors           []string              `json:"errors,omitempty"`
	LoginBrutes      []LoginBrute          `json:"login_brutes,omitempty"` // valid credentials found by brute force
	AuthStatus       string                `json:"auth_status,omitempty"`  // --wp-auth: authenticated | failed | ""
	Summary          *Summary              `json:"summary,omitempty"`      // scan statistics; nil with --no-summary
}

// sendRequest issues one HTTP request through client, re-running the full
// pacing sequence (429 gate, send-slot claim, request build, Do) on each
// retry. Transient transport errors (a non-nil error from Do that is not a
// context cancellation, a deadline expiry or a redirect rejection) are
// retried up to s.opts.MaxRetries times with exponential backoff
// (200ms*2^attempt) plus uniform 0..150ms jitter. HTTP status responses are
// never retried here — a 4xx/5xx is a valid answer, not an error. The
// request counter is bumped once per actual attempt.
func (s *Scanner) sendRequest(client *http.Client, makeReq func() (*http.Request, error)) (*http.Response, error) {
	maxRetries := s.opts.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	for attempt := 0; ; attempt++ {
		s.rateLimitGate()
		s.claimSendSlot()
		req, err := makeReq()
		if err != nil {
			return nil, err // request-build/parse failure: not retryable
		}
		s.requests.Add(1)
		resp, err := client.Do(req)
		if err == nil || attempt >= maxRetries || !retryableNetworkError(err) {
			return resp, err
		}
		backoff := time.Duration(200*(1<<uint(attempt))) * time.Millisecond
		jitter := time.Duration(rand.IntN(151)) * time.Millisecond
		time.Sleep(backoff + jitter)
	}
}

// retryableNetworkError reports whether err is a transient transport error
// worth retrying: a real network failure rather than a context cancellation
// or deadline expiry, and not a redirect rejection from the SSRF guard.
func retryableNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRedirectBlocked) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func (s *Scanner) fetch(path string) (int, []byte, error) {
	s.lim.wait()
	u := s.base + path
	s.perHostWait(u)
	if s.opts.CacheTTL > 0 {
		if code, body, ok := s.cacheGet(u); ok {
			return code, body, nil
		}
	}
	// A 429 no longer gives up immediately: the request is retried after
	// the global cooldown so rate-limited scans stay complete.
	for attempt := 0; attempt <= fetchRetriesOn429; attempt++ {
		resp, err := s.sendRequest(s.client, func() (*http.Request, error) {
			return http.NewRequestWithContext(s.requestCtx(), http.MethodGet, u, nil)
		})
		if err != nil {
			return 0, nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			s.noteSuccess()
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			resp.Body.Close()
			if err == nil && cacheableStatus(resp.StatusCode) && s.opts.CacheTTL > 0 {
				s.cachePut(u, resp.StatusCode, body)
			}
			return resp.StatusCode, body, err
		}

		// Rate limited: register the hit, open a GLOBAL cooldown that every
		// in-flight worker gates on (previously only the unlucky requester
		// slept while its siblings kept hammering), then loop and retry.
		wait := s.noteRateLimited(resp.Header)
		resp.Body.Close()
		if pr := s.progress; pr != nil {
			pr.LogInf("rate limited (429) — global cooldown %s (attempt %d/%d)",
				wait.Truncate(time.Millisecond), attempt+1, fetchRetriesOn429+1)
		}
	}
	return http.StatusTooManyRequests, nil, nil
}

// fetchRetriesOn429 is how many times a single fetch retries itself after
// a 429-triggered global cooldown before giving up on the job.
const fetchRetriesOn429 = 2

// spacingRecoverAfter is the healthy-response streak required before the
// adaptive inter-request spacing starts shrinking back toward zero.
const spacingRecoverAfter = 15

// consecOKReset is how many consecutive non-429 responses clear the shared
// exponential backoff. Resetting on every success let parallel workers see-
// saw between 1s waits and full storms during sustained rate limiting.
const consecOKReset = 25

// rateLimitGate blocks until any open 429 cooldown expires. Called before
// every outbound request so the whole worker pool pauses together.
func (s *Scanner) rateLimitGate() {
	s.rlMu.Lock()
	until := s.cooldownUntil
	s.rlMu.Unlock()
	if until.IsZero() {
		return
	}
	if d := time.Until(until); d > 0 {
		time.Sleep(d)
	}
}

// maxAdaptiveSpacing caps the permanent politeness delay inserted between
// outbound requests while a target keeps answering 429.
const maxAdaptiveSpacing = 2 * time.Second

// rateAbortMinHits and rateAbortPct define the early-abort heuristic: once
// enough requests have been sent and at least half of recent traffic is
// being throttled, enumeration stops early — grinding through hundreds of
// doomed probes only wastes the target's quota and the user's time.
const (
	rateAbortMinHits = 25
	rateAbortPct     = 40
)

// rateLimitAbort reports whether the scan decided further enumeration is
// futile because the target keeps answering 429.
func (s *Scanner) rateLimitAbort() bool {
	return s.abortRateLimited.Load()
}

// claimSendSlot reserves the next outbound-send instant, enforcing the
// adaptive spacing so N workers collectively emit at one polite rate.
func (s *Scanner) claimSendSlot() {
	s.rlMu.Lock()
	now := time.Now()
	t := s.sendSlot
	if t.Before(now) {
		t = now
	}
	s.sendSlot = t.Add(s.spacing)
	s.rlMu.Unlock()
	if d := time.Until(t); d > 0 {
		time.Sleep(d)
	}
}

// noteRateLimited records a 429: bumps counters, advances the shared
// exponential schedule (or adopts a clamped Retry-After hint), opens a
// global cooldown AND permanently widens the inter-request spacing so the
// scanner stops tripping the target's threshold in the first place.
// Returns the wait applied.
func (s *Scanner) noteRateLimited(h http.Header) time.Duration {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	s.rateHits++
	s.consecOK = 0
	if s.spacing == 0 {
		s.spacing = 250 * time.Millisecond
	} else {
		s.spacing *= 2
		if s.spacing > maxAdaptiveSpacing {
			s.spacing = maxAdaptiveSpacing
		}
	}
	if s.rlBackoff == 0 {
		s.rlBackoff = time.Second
	} else {
		s.rlBackoff *= 2
		if s.rlBackoff > s.maxBackoff {
			s.rlBackoff = s.maxBackoff
		}
	}
	wait := s.rlBackoff
	if ra, ok := retryAfter(h, time.Now()); ok {
		// Clamp to [1s, 60s]: never spin faster than a second against an
		// explicit hint, and never let one stall the scan forever.
		if ra > maxRetryAfterWait {
			ra = maxRetryAfterWait
		}
		if ra < time.Second {
			ra = time.Second
		}
		wait = ra
	}
	s.cooldownUntil = time.Now().Add(wait)
	if s.rateHits >= rateAbortMinHits {
		total := s.requests.Load()
		if total > 0 && s.rateHits*100/int(total) >= rateAbortPct {
			s.abortRateLimited.Store(true)
		}
	}
	return wait
}

// noteSuccess tracks consecutive healthy responses; only a long streak
// clears the exponential backoff (see consecOKReset).
func (s *Scanner) noteSuccess() {
	s.rlMu.Lock()
	s.consecOK++
	if s.consecOK >= consecOKReset {
		s.rlBackoff = 0
	}
	// Recover pacing smoothly once the target has clearly relaxed: after a
	// short healthy streak, shed 20% of the spacing per further success.
	// Success-count (not wall-clock) keeps the arithmetic lock-free here;
	// a stray 429 merely restarts the streak, which is the safe direction.
	if s.consecOK >= spacingRecoverAfter && s.spacing > 0 {
		s.spacing -= s.spacing / 5
		if s.spacing < 50*time.Millisecond {
			s.spacing = 0
		}
	}
	s.rlMu.Unlock()
}

// cacheableStatus reports whether a response may be cached: successful and
// deterministic client-error responses (200s and 4xx) are reused within the
// TTL, while 5xx server errors are never cached because they are transient.
// maxRetryAfterWait caps how long a server's Retry-After hint may stall a
// single fetch. Hostile targets could otherwise park the scanner forever
// with an ever-growing delay.
const maxRetryAfterWait = 60 * time.Second

// retryAfter parses the Retry-After response header per RFC 7231: either
// delay-seconds or an HTTP-date. ok is false when the header is absent,
// unparseable, or already in the past.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0, false
		}
		return d, true
	}
	return 0, false
}

func cacheableStatus(code int) bool {
	return code >= http.StatusOK && code < 500 && code != http.StatusTooManyRequests
}

// fetchNoRedirect GETs path without following redirects so the raw 30x
// Location header from the author-enumeration redirect chain can be read.
func (s *Scanner) fetchNoRedirect(path string) (int, http.Header, []byte, error) {
	s.lim.wait()
	u := s.base + path
	s.perHostWait(u)
	client := *s.client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Same 429 discipline as fetch: gate the whole pool and retry once so
	// author-enumeration redirects are not silently lost behind a WAF.
	for attempt := 0; attempt <= 1; attempt++ {
		resp, err := s.sendRequest(&client, func() (*http.Request, error) {
			return http.NewRequestWithContext(s.requestCtx(), http.MethodGet, u, nil)
		})
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			s.noteSuccess()
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			hdr := resp.Header
			resp.Body.Close()
			return resp.StatusCode, hdr, body, err
		}
		wait := s.noteRateLimited(resp.Header)
		resp.Body.Close()
		if pr := s.progress; pr != nil {
			pr.LogInf("rate limited (429) — global cooldown %s", wait.Truncate(time.Millisecond))
		}
	}
	return http.StatusTooManyRequests, nil, nil, nil
}

// requestCtx returns the scan-wide context (--max-scan-duration), or a
// background context when no duration was configured.
func (s *Scanner) requestCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// scanDone reports whether the scan-wide context (--max-scan-duration)
// has expired.
func (s *Scanner) scanDone() bool {
	return s.ctx != nil && s.ctx.Err() != nil
}

// cacheKey hashes a URL into a flat file name for the HTTP cache.
func cacheKey(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:8])
}

// cacheGet serves u from the disk cache when a fresh (within TTL) response
// is stored. The cached status code is returned alongside the body so
// callers can treat negative (404/403) hits the same as fresh ones. ok is
// false on any miss or read error. Entries past the TTL are evicted
// (best-effort unlink) so a long-lived cache directory does not grow
// without bound.
func (s *Scanner) cacheGet(u string) (int, []byte, bool) {
	path := filepath.Join(s.cacheDir, cacheKey(u))
	fi, err := os.Stat(path)
	if err != nil {
		return 0, nil, false
	}
	if time.Since(fi.ModTime()) > s.opts.CacheTTL {
		// Stale: drop the entry so it cannot be served again and does not
		// accumulate. Removal failures are silent — the cache is an
		// optimization, never a scan error.
		_ = os.Remove(path)
		return 0, nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return 0, nil, false
	}
	// First line is the status code ("HTTP 404"), the rest is the body.
	i := strings.IndexByte(string(data), '\n')
	if i < 0 {
		return 0, nil, false
	}
	var code int
	if _, err := fmt.Sscanf(string(data[:i]), "HTTP %d", &code); err != nil {
		return 0, nil, false
	}
	return code, data[i+1:], true
}

// cachePut stores a response (status code + body) in the disk cache. The
// body may be empty for negative responses. Failures are silent: the cache
// is an optimization, never a scan error.
func (s *Scanner) cachePut(u string, code int, body []byte) {
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		return
	}
	data := make([]byte, 0, len(body)+16)
	data = append(data, fmt.Sprintf("HTTP %d\n", code)...)
	data = append(data, body...)
	_ = os.WriteFile(filepath.Join(s.cacheDir, cacheKey(u)), data, 0o644)
}

// checkXMLRPC pings POST /xmlrpc.php with a system.listMethods call and
// reports whether the server answered with a methodResponse payload. The
// request shares the scan-wide pacing: 429 cooldown gate, adaptive send
// slot and the request counter.
func (s *Scanner) checkXMLRPC() bool {
	s.lim.wait()
	const payload = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`
	u := s.base + "/xmlrpc.php"
	s.perHostWait(u)
	req, err := http.NewRequestWithContext(s.requestCtx(), http.MethodPost, u, strings.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "text/xml")
	s.rateLimitGate()
	s.claimSendSlot()
	s.requests.Add(1)
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return false
	}
	return strings.Contains(string(body), "methodResponse")
}

// Response-authenticity helpers.
//
// Live-lab verified on WordPress 7.x/Apache: servers with front-controller
// rewrites answer requests for MISSING files with a redirect that lands on
// 200 + full homepage HTML. A 200 status therefore proves nothing about
// what was actually fetched — every helper below inspects the body for
// markers only the genuine artifact carries, keeping rewritten homepages
// from being misread as exposed config backups or fingerprintable
// components.

// looksLikePHPConfig reports whether body carries the unmistakable shape of
// a WordPress wp-config.php dump: a PHP open tag plus one of the canonical
// WordPress configuration constants (DB_NAME, DB_PASSWORD or table_prefix).
// Homepage HTML served by front-controller rewrites never carries this
// combination — which is exactly what defeated the old len(body)>100 rule:
// a redirected homepage is always long enough but never a config dump.
func looksLikePHPConfig(body []byte) bool {
	b := string(body)
	if !strings.Contains(b, "<?php") {
		return false
	}
	return strings.Contains(b, "DB_NAME") ||
		strings.Contains(b, "DB_PASSWORD") ||
		strings.Contains(b, "table_prefix")
}

// looksLikeReadme reports whether body has the structural markers of a real
// WordPress readme.txt: the "===" heading style plus at least one field
// only readmes carry (matched case-insensitively). A stray line-starting
// "Stable tag:" inside rewritten homepage HTML is not enough.
func looksLikeReadme(body []byte) bool {
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, "===") {
		return false
	}
	for _, marker := range []string{
		"contributors:", "donate link:", "tags:", "requires at least", "stable tag",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// looksLikeThemeCSS reports whether body looks like a WordPress theme
// stylesheet: every theme style.css carries the "Theme Name:" header
// mandated by the WordPress theme handbook; plain CSS files and rewritten
// homepage HTML do not.
func looksLikeThemeCSS(body []byte) bool {
	return strings.Contains(strings.ToLower(string(body)), "theme name:")
}

// configBackupFinder probes every wp-config backup name at the site root.
// A hit requires a 200 response whose body actually looks like PHP config
// (see looksLikePHPConfig): on front-controller rewrite installs missing
// files land on the 200 homepage HTML, which always exceeds 100 bytes, so
// the former size-only rule flagged every stock install behind such
// rewrites.
func (s *Scanner) configBackupFinder() []string {
	var found []string
	for _, f := range configBackupFiles {
		code, body, err := s.fetch("/" + f)
		if err != nil {
			continue
		}
		if code == http.StatusOK && looksLikePHPConfig(body) {
			found = append(found, "/"+f)
		}
	}
	return found
}

// dbExportFinder probes SQL dump names at the root and inside dbExportDirs.
// A 200 response whose body looks like SQL (INSERT INTO / CREATE TABLE)
// counts as a hit.
func (s *Scanner) dbExportFinder() []string {
	var found []string
	try := func(path string) {
		code, body, err := s.fetch(path)
		if err != nil {
			return
		}
		b := string(body)
		if code == http.StatusOK && (strings.Contains(b, "INSERT INTO") || strings.Contains(b, "CREATE TABLE")) {
			found = append(found, path)
		}
	}
	for _, f := range dbExportFiles {
		try("/" + f)
	}
	for _, dir := range dbExportDirs {
		for _, f := range dbExportFiles {
			try(dir + f)
		}
	}
	return found
}

// interestingFinders runs the always-on file checks (WPScan-style): each is
// a simple GET plus a status/content rule flagging exposed files and
// directory listings.
func (s *Scanner) interestingFinders() []string {
	var out []string
	try := func(path, needle, desc string) {
		code, body, err := s.fetch(path)
		if err != nil || code != http.StatusOK {
			return
		}
		if needle != "" && !strings.Contains(string(body), needle) {
			return
		}
		out = append(out, desc)
	}
	try("/robots.txt", "Disallow", "robots.txt with disallow rules")
	try("/readme.html", "WordPress", "WordPress readme.html exposed")

	code, body, err := s.fetch("/" + s.contentDir + "/debug.log")
	if err == nil && code == http.StatusOK {
		b := string(body)
		if strings.Contains(b, "PHP") || strings.Contains(b, "Warning") || strings.Contains(b, "Fatal") {
			out = append(out, "debug.log exposed")
		}
	}

	try("/xmlrpc.php", "XML-RPC", "xmlrpc.php exposed")

	code, body, err = s.fetch("/" + s.contentDir + "/uploads/")
	if err == nil && code == http.StatusOK {
		b := string(body)
		if strings.Contains(b, "Index of") || strings.Contains(b, "Parent Directory") {
			out = append(out, "uploads directory listing")
		}
	}

	// wp-config.php.bak is special-cased like version.php below: on
	// front-controller rewrite installs the probe lands on the 200 homepage
	// HTML, so exposure requires a body that really looks like PHP config,
	// not just any non-empty 200.
	code, body, err = s.fetch("/wp-config.php.bak")
	if err == nil && code == http.StatusOK && looksLikePHPConfig(body) {
		out = append(out, "wp-config.php.bak exposed")
	}
	// version.php is special-cased: stock WordPress answers 200 with an
	// empty body for this path (the PHP file produces no output), so a
	// non-empty body is required before calling it exposed.
	code, body, err = s.fetch("/wp-includes/version.php")
	if err == nil && code == http.StatusOK && len(body) > 0 {
		out = append(out, "wp-includes/version.php exposed")
	}
	return out
}

// restPath lists the URL forms under which a WordPress REST route answers:
// pretty-permalink installs expose /wp-json<path>, while sites running
// WITHOUT rewrite rules serve REST only through the rest_route query
// parameter (their /wp-json/* paths 404 even though the API itself works).
// Callers try the candidates in order until one yields usable data.
func restPath(path string) []string {
	return []string{"/wp-json" + path, "/?rest_route=" + path}
}

// usersFromAPI queries the REST users endpoint, trying the pretty
// /wp-json/wp/v2/users form first and the plain-permalink
// /?rest_route=/wp/v2/users fallback second. The first candidate returning
// a parseable JSON user list wins; auth rejections, wrong status codes and
// unparseable bodies fall through to the next form. The returned errors
// name every path actually tried.
func (s *Scanner) usersFromAPI() ([]User, []string) {
	var errs []string
	for _, path := range restPath("/wp/v2/users") {
		code, body, err := s.fetch(path)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			continue
		}
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			// A hardening plugin may only cover one URL spelling, so note
			// the rejection and let the other form answer before giving up.
			errs = append(errs, path+" requires authentication (skipped)")
			continue
		}
		if code != http.StatusOK {
			continue // e.g. 404 on the pretty form: the fallback may still work
		}
		// WordPress can prepend PHP Deprecated/Warning notices to the JSON
		// payload; skip everything before the first '[' or '{' so the JSON
		// decoder never sees the noise.
		start := -1
		for i, b := range body {
			if b == '[' || b == '{' {
				start = i
				break
			}
		}
		if start < 0 {
			errs = append(errs, path+" returned unparseable data")
			continue
		}
		users := usersFromJSON(body[start:])
		if users == nil {
			errs = append(errs, path+" returned unparseable data")
			continue
		}
		return users, nil
	}
	return nil, errs
}

// usersFromJSON decodes a wp-json users payload into sanitized User entries.
func usersFromJSON(body []byte) []User {
	var items []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil
	}
	var out []User
	for _, it := range items {
		slug := sanitizeText(it.Slug, maxSlugLen)
		if slug == "" {
			continue
		}
		out = append(out, User{ID: it.ID, Slug: slug, Name: sanitizeText(it.Name, maxNameLen)})
	}
	return out
}

// usersFromAuthors walks /?author=1..N following the redirect chain and
// extracting the username from /author/<slug>/ landing pages. When the
// server answers 200 instead of redirecting (WP 7.x behaviour), the slug is
// extracted from the response body itself.
func (s *Scanner) usersFromAuthors(maxN int) ([]User, []string) {
	var out []User
	var errs []string
	for n := 1; n <= maxN; n++ {
		loc, body, err := s.authorLocation(n)
		if err != nil {
			errs = append(errs, fmt.Sprintf("?author=%d: %v", n, err))
			continue
		}
		if slug := authorSlugFromLocation(loc); slug != "" {
			out = append(out, User{ID: n, Slug: slug})
			continue
		}
		if slug := authorSlugFromBody(body); slug != "" {
			out = append(out, User{ID: n, Slug: slug})
		}
	}
	return out, errs
}

// authorLocation returns the Location header of the /?author=N redirect,
// plus the response body when no redirect happens (a 200 author archive
// page that still carries the author slug, e.g. in a canonical link).
func (s *Scanner) authorLocation(n int) (string, []byte, error) {
	code, hdr, body, err := s.fetchNoRedirect(fmt.Sprintf("/?author=%d", n))
	if err != nil {
		return "", nil, err
	}
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return hdr.Get("Location"), nil, nil
	}
	return "", body, nil
}

// authorSlugFromBody extracts the username from a 200 ?author=N response
// body: either a <link rel="canonical" href=".../author/<slug>/"> reference
// or any /author/<slug>/ path mentioned in the page.
func authorSlugFromBody(body []byte) string {
	if m := authorSlugRe.FindStringSubmatch(string(body)); m != nil {
		return sanitizeText(m[1], maxSlugLen)
	}
	return ""
}

// authorSlugFromLocation extracts the username from any /author/<slug>/
// path in a redirect Location value. Site-relative Locations without a
// leading slash are tolerated.
func authorSlugFromLocation(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if m := authorSlugRe.FindStringSubmatch(u.Path); m != nil {
		return sanitizeText(m[1], maxSlugLen)
	}
	if m := authorSlugRe.FindStringSubmatch("/" + strings.TrimLeft(u.Path, "/")); m != nil {
		return sanitizeText(m[1], maxSlugLen)
	}
	return ""
}

// normalizeUsers merges user lists from the REST API and author redirects,
// de-duplicating by slug and filling missing fields, sorted by slug.
func normalizeUsers(lists ...[]User) []User {
	bySlug := make(map[string]User)
	var order []string
	for _, list := range lists {
		for _, u := range list {
			if u.Slug == "" {
				continue
			}
			prev, ok := bySlug[u.Slug]
			if !ok {
				order = append(order, u.Slug)
				bySlug[u.Slug] = u
				continue
			}
			if prev.Name == "" && u.Name != "" {
				prev.Name = u.Name
			}
			if prev.ID == 0 {
				prev.ID = u.ID
			}
			bySlug[u.Slug] = prev
		}
	}
	out := make([]User, 0, len(order))
	for _, slug := range order {
		out = append(out, bySlug[slug])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// detectWP checks the homepage, wp-login.php and the REST API root for
// WordPress fingerprints. It returns the detected core version (if any) and
// the list of evidence strings. A homepage fetch failure is returned as a
// fatal error — an unreachable target is a hard failure, not WordPress
// evidence. wp-login/wp-json fetch errors are secondary and stay silent.
//
// The core version comes from the first source that answers, tried in
// order: generator meta tag → RSS feed generator element (/?feed=rss2,
// then /feed/) → wp-links-opml.php generator attribute. The RSS/OPML
// fetches only run when the meta tag did not yield a version, keeping the
// request count low; whichever source wins is recorded in s.coreEvidence.
func (s *Scanner) detectWP() (coreVersion string, evidence []string, fatalErr error) {
	code, body, err := s.fetch("/")
	if err != nil {
		return "", nil, err
	}
	if code == 200 {
		html := string(body)
		s.homepage = html
		if v, ok := ExtractWordPressVersion(html); ok {
			coreVersion = v
			evidence = append(evidence, "generator meta tag (WordPress "+v+")")
			s.coreEvidence = append(s.coreEvidence, CoreEvidence{Source: "meta", Version: v, Confidence: confMetaGenerator})
		}
		if strings.Contains(html, "wp-content") {
			evidence = append(evidence, "wp-content path present in homepage")
		}
		if strings.Contains(html, "wp-json") || strings.Contains(html, "/wp-json/") {
			evidence = append(evidence, "wp-json REST API referenced")
		}
	}

	// Multi-source fallbacks, cheapest-first. Each stops the chain as soon
	// as it produces a version.
	if coreVersion == "" {
		for _, path := range []string{"/?feed=rss2", "/feed/"} {
			code, body, err := s.fetch(path)
			if err != nil || code != http.StatusOK {
				continue
			}
			if v, ok := ExtractRSSVersion(string(body)); ok {
				coreVersion = v
				evidence = append(evidence, "RSS feed generator tag (WordPress "+v+")")
				s.coreEvidence = append(s.coreEvidence, CoreEvidence{Source: "rss", Version: v, Confidence: confRSSGenerator})
				break
			}
		}
	}
	if coreVersion == "" {
		if code, body, err := s.fetch("/wp-links-opml.php"); err == nil && code == http.StatusOK {
			if v, ok := ExtractOPMLVersion(string(body)); ok {
				coreVersion = v
				evidence = append(evidence, "wp-links-opml.php generator (WordPress "+v+")")
				s.coreEvidence = append(s.coreEvidence, CoreEvidence{Source: "opml", Version: v, Confidence: confOPMLGenerator})
			}
		}
	}

	// Final core-version fallback: the optional --fingerprint-db md5 table.
	// Only consulted when every cheaper source came up empty and a table was
	// configured; it adds up to maxFingerprintProbes requests.
	if coreVersion == "" && s.opts.FingerprintDB != "" {
		if v, ok := s.fingerprintCore(); ok {
			coreVersion = v
			evidence = append(evidence, "core asset md5 fingerprint (WordPress "+v+")")
			s.coreEvidence = append(s.coreEvidence, CoreEvidence{Source: "fingerprint", Version: v, Confidence: confFingerprint})
		}
	}

	if code, body, err := s.fetch("/wp-login.php"); err == nil && code == 200 {
		if strings.Contains(string(body), "user_login") {
			evidence = append(evidence, "wp-login.php reachable")
		}
	}

	if code, body, err := s.fetch("/wp-json/"); err == nil && (code == 200 || code == 403) {
		if len(body) > 0 && (body[0] == '{' || body[0] == '[') {
			evidence = append(evidence, "wp-json REST API root responded")
		}
	}
	return coreVersion, evidence, nil
}

// apiPlugins queries the plugin listing endpoint, trying the pretty
// /wp-json/wp/v2/plugins URL first and the plain-permalink
// /?rest_route=/wp/v2/plugins fallback second: installs without rewrite
// rules 404 the pretty form even though REST works. The first candidate
// returning a usable plugin list wins. Unauthenticated servers return
// 401/403; that is expected and swallowed as a skip note naming the actual
// path that rejected us.
func (s *Scanner) apiPlugins() ([]Detected, []string) {
	var errs []string
	for _, path := range restPath("/wp/v2/plugins") {
		code, body, err := s.fetch(path)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			continue
		}
		if code == 401 || code == 403 {
			errs = append(errs, path+" requires authentication (skipped)")
			continue
		}
		if code != 200 {
			continue
		}
		out := parseDetectedList(body, "plugin", "rest")
		if len(out) == 0 {
			errs = append(errs, path+" returned no usable plugin list")
			continue
		}
		return out, nil
	}
	return nil, errs
}

// job is one brute-force enumeration request.
type job struct {
	kind string // "plugin" | "theme"
	slug string
	path string
}

// label describes the job for progress output, e.g. "plugin:elementor
// readme.txt". When version is non-empty it is appended in parentheses.
func (j job) label(version string) string {
	where := "readme.txt"
	switch j.kind {
	case "theme":
		where = "style.css"
	case "plugin":
		where = "readme.txt"
	}
	l := j.kind + ":" + j.slug + " " + where
	if version != "" {
		l += " (" + version + ")"
	}
	return l
}

func (s *Scanner) buildJobs() []job {
	var jobs []job
	seen := make(map[string]bool)
	passive := s.mode == "mixed" || s.mode == "passive"
	aggressive := s.mode == "mixed" || s.mode == "aggressive"

	// Passive detection: slugs referenced in the homepage HTML (WPScan-style).
	if passive && s.homepage != "" {
		passiveP, passiveT := ExtractPassiveSlugsIn(s.homepage, s.contentDir)
		for _, slug := range passiveP {
			if !s.enumeratePlugins() {
				break
			}
			seen["p:"+slug] = true
			jobs = append(jobs, job{kind: "plugin", slug: slug,
				path: "/" + s.pluginsDir + "/" + slug + "/readme.txt"})
		}
		for _, slug := range passiveT {
			if !s.enumerateThemes() {
				break
			}
			seen["t:"+slug] = true
			jobs = append(jobs, job{kind: "theme", slug: slug,
				path: "/" + s.contentDir + "/themes/" + slug + "/style.css"})
		}
	}

	// Passive detection via --crawl-pages: slugs discovered on sitemap
	// pages join the job list exactly like homepage references.
	if passive && len(s.sitemapPlugins)+len(s.sitemapThemes) > 0 {
		for _, slug := range s.sitemapPlugins {
			if !s.enumeratePlugins() || seen["p:"+slug] {
				continue
			}
			seen["p:"+slug] = true
			jobs = append(jobs, job{kind: "plugin", slug: slug,
				path: "/" + s.pluginsDir + "/" + slug + "/readme.txt"})
		}
		for _, slug := range s.sitemapThemes {
			if !s.enumerateThemes() || seen["t:"+slug] {
				continue
			}
			seen["t:"+slug] = true
			jobs = append(jobs, job{kind: "theme", slug: slug,
				path: "/" + s.contentDir + "/themes/" + slug + "/style.css"})
		}
	}

	// Aggressive detection: brute-force the explicit slug lists when
	// provided, otherwise the vuln-heavy slugs from the DB.
	budget := s.maxRequests
	if budget <= 0 {
		budget = defaultTopSlugs
	}
	if aggressive {
		if len(s.pluginsList) > 0 || len(s.themesList) > 0 {
			for _, slug := range s.pluginsList {
				if !s.enumeratePlugins() {
					break
				}
				if seen["p:"+slug] {
					continue
				}
				seen["p:"+slug] = true
				jobs = append(jobs, job{kind: "plugin", slug: slug,
					path: "/" + s.pluginsDir + "/" + slug + "/readme.txt"})
			}
			for _, slug := range s.themesList {
				if !s.enumerateThemes() {
					break
				}
				if seen["t:"+slug] {
					continue
				}
				seen["t:"+slug] = true
				jobs = append(jobs, job{kind: "theme", slug: slug,
					path: "/" + s.contentDir + "/themes/" + slug + "/style.css"})
			}
		} else {
			for _, slug := range s.db.TopSlugs(budget) {
				switch s.db.SlugType(slug) {
				case "plugin":
					if !s.enumeratePlugins() {
						continue
					}
					if seen["p:"+slug] {
						continue
					}
					seen["p:"+slug] = true
					jobs = append(jobs, job{kind: "plugin", slug: slug,
						path: "/" + s.pluginsDir + "/" + slug + "/readme.txt"})
				case "theme":
					if !s.enumerateThemes() {
						continue
					}
					if seen["t:"+slug] {
						continue
					}
					seen["t:"+slug] = true
					jobs = append(jobs, job{kind: "theme", slug: slug,
						path: "/" + s.contentDir + "/themes/" + slug + "/style.css"})
				}
			}
			// Popular slug seeds (--popular, default true): after the DB
			// top list, append well-known slugs not already queued so
			// popular-but-not-vulnerable components still get probed.
			// Ordering is the deterministic popular.go list order; the loop
			// stops as soon as the aggressive budget is exhausted.
			if s.opts.PopularSlugs {
				for _, slug := range popularPlugins {
					if len(jobs) >= budget {
						break
					}
					if !s.enumeratePlugins() || seen["p:"+slug] {
						continue
					}
					seen["p:"+slug] = true
					jobs = append(jobs, job{kind: "plugin", slug: slug,
						path: "/" + s.pluginsDir + "/" + slug + "/readme.txt"})
				}
				for _, slug := range popularThemes {
					if len(jobs) >= budget {
						break
					}
					if !s.enumerateThemes() || seen["t:"+slug] {
						continue
					}
					seen["t:"+slug] = true
					jobs = append(jobs, job{kind: "theme", slug: slug,
						path: "/" + s.contentDir + "/themes/" + slug + "/style.css"})
				}
			}
		}
	}
	return jobs
}

// matchDatabase compares an installed version against every database record
// for slug and returns the matching finding. Non-numeric ("unknown")
// versions never match: no range matching is performed, preventing false
// positives.
func (s *Scanner) matchDatabase(slug, typ, rawVersion string) Finding {
	f := Finding{Slug: slug, Name: slug, Type: typ, InstalledVersion: rawVersion}
	v, ok := version.Parse(rawVersion)
	if !ok {
		return f
	}
	recs := s.db.Lookup(slug)
	seen := make(map[string]bool, len(recs))
	for _, rec := range recs {
		for si := range rec.Software {
			sw := &rec.Software[si]
			if sw.Slug != slug {
				continue
			}
			for label, av := range sw.AffectedVersions {
				if !version.InRanges(av.Ranges, v) {
					continue
				}
				if seen[rec.ID] {
					continue
				}
				seen[rec.ID] = true
				f.Vulnerabilities = append(f.Vulnerabilities, Vulnerability{
					ID:             rec.ID,
					Title:          rec.Title,
					CVE:            rec.CVE,
					CVSSScore:      rec.CVSS.Score,
					Rating:         rec.CVSS.Rating,
					Description:    rec.Description,
					PublishedAt:    rec.PublishedAt,
					AffectedLabels: []string{label},
				})
				break
			}
		}
	}
	return f
}

// scanJob performs one enumeration request, fingerprinting the installed
// version and matching it against the database.
//
// A 200 status alone does not prove the probe hit a real readme.txt /
// style.css: servers with front-controller rewrites answer requests for
// MISSING files with a redirect that lands on 200 + full homepage HTML.
// When that HTML happens to contain a line-starting "Stable tag:" or
// "Version:" line, the bare regex extractors fire on it and EVERY
// nonexistent slug would be reported as installed with a bogus version.
// The extracted version therefore ALSO requires the body to pass the
// response-authenticity check for its artifact type (looksLikeReadme /
// looksLikeThemeCSS). Anything failing that gate — including a genuine 200
// body without a parseable version — returns NO detection at all: guessing
// "unknown" from untrusted markup pollutes the inventory with rewritten
// homepages. A non-200 answer keeps its historical behaviour of returning
// nothing as well.
func (s *Scanner) scanJob(j job) ([]Detected, []Finding) {
	var ver string
	var found bool
	source := "readme"
	switch j.kind {
	case "plugin":
		code, body, err := s.fetch(j.path)
		if err == nil && code == http.StatusOK {
			ver, found = ExtractVersionFromReadme(string(body))
			if !found {
				// Readme with no "Stable tag:" line: fall back to the first
				// version heading in its Changelog section.
				if clVer, ok := ExtractVersionFromChangelog(string(body)); ok {
					ver, found = clVer, true
					source = "readme-changelog"
				}
			}
			found = found && looksLikeReadme(body)
		}
		if !found {
			// Readme missing or versionless: the plugin's composer.json
			// carries the version too. This costs one extra request per
			// readme-less plugin (counted through s.fetch).
			if v, ok := s.composerVersion(j.slug); ok {
				ver, found = v, true
				source = "composer"
			}
		}
	case "theme":
		code, body, err := s.fetch(j.path)
		if err == nil && code == http.StatusOK {
			ver, found = ExtractVersionFromStyleCSS(string(body))
			source = "style.css"
			found = found && looksLikeThemeCSS(body)
		}
	}
	if !found {
		return nil, nil
	}
	detected := []Detected{{Slug: j.slug, Name: j.slug, Type: j.kind, Version: ver, Source: source, Confidence: sourceConfidence(source)}}
	f := s.matchDatabase(j.slug, j.kind, ver)
	if len(f.Vulnerabilities) > 0 {
		return detected, []Finding{f}
	}
	return detected, nil
}

// composerVersion fetches <pluginsDir>/<slug>/composer.json and returns its
// "version" field when present. A non-200 response, an unparseable body
// (which also rejects front-controller rewrites landing on homepage HTML)
// or a missing version yields found=false. Themes are not probed: their
// version lives in style.css.
func (s *Scanner) composerVersion(slug string) (string, bool) {
	path := "/" + s.pluginsDir + "/" + slug + "/composer.json"
	code, body, err := s.fetch(path)
	if err != nil || code != http.StatusOK {
		return "", false
	}
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", false
	}
	v := sanitizeVersion(doc.Version)
	if v == "" {
		return "", false
	}
	return v, true
}

// fetchHeaders GETs path like fetch() but also returns the response
// headers, which fetch() discards (needed for cache-layer sniffing). It
// shares the rate limiter, per-host throttle, UA transport and request
// counter with fetch(); responses are never served from or written to the
// disk cache because cached entries do not retain headers.
func (s *Scanner) fetchHeaders(path string) (int, http.Header, []byte, error) {
	s.lim.wait()
	u := s.base + path
	s.perHostWait(u)
	resp, err := s.sendRequest(s.client, func() (*http.Request, error) {
		return http.NewRequestWithContext(s.requestCtx(), http.MethodGet, u, nil)
	})
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	hdr := resp.Header.Clone()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return resp.StatusCode, hdr, body, err
}

// mergePassiveDetections upserts Detected entries for components observed
// in page HTML (homepage or --crawl-pages sitemap pages) whose asset URLs
// carried ?ver= cache-buster versions. It runs after enumeration so
// readme.txt/style.css/REST versions win; entries still at "unknown" get
// the passive version and every versioned entry is matched against the
// database. Slug-only passive references keep flowing through enumeration
// jobs and are not materialized here.
func (s *Scanner) mergePassiveDetections(res *Result, addFindings func([]Finding)) {
	versions := make(map[string]string)
	for slug, ver := range ExtractPassiveVersionsIn(s.homepage, s.contentDir) {
		versions[slug] = ver
	}
	for slug, ver := range s.sitemapVersions {
		if _, ok := versions[slug]; !ok {
			versions[slug] = ver
		}
	}
	if len(versions) == 0 {
		return
	}

	// slug -> component type; plugins win when a slug collides.
	typ := make(map[string]string)
	reg := func(slugs []string, t string) {
		for _, slug := range slugs {
			if _, ok := typ[slug]; !ok {
				typ[slug] = t
			}
		}
	}
	hp, ht := ExtractPassiveSlugsIn(s.homepage, s.contentDir)
	reg(hp, "plugin")
	reg(ht, "theme")
	reg(s.sitemapPlugins, "plugin")
	reg(s.sitemapThemes, "theme")

	index := make(map[string]int, len(res.Detected))
	for i := range res.Detected {
		index[res.Detected[i].Slug] = i
	}
	slugs := make([]string, 0, len(versions))
	for slug := range versions {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	var findings []Finding
	for _, slug := range slugs {
		t, ok := typ[slug]
		if !ok {
			continue
		}
		ver := versions[slug]
		if i, ok := index[slug]; ok {
			passive := Detected{Slug: slug, Name: slug, Type: t, Version: ver, Source: "passive-ver", Confidence: confPassiveVer}
			if !preferDetected(passive, res.Detected[i]) {
				continue // a probed/known version wins over the passive hint
			}
			res.Detected[i] = passive
		} else {
			index[slug] = len(res.Detected)
			res.Detected = append(res.Detected, Detected{
				Slug: slug, Name: slug, Type: t, Version: ver, Source: "passive-ver", Confidence: confPassiveVer,
			})
		}
		if f := s.matchDatabase(slug, t, ver); len(f.Vulnerabilities) > 0 {
			findings = append(findings, f)
		}
	}
	addFindings(findings)
}

// Scan runs the full workflow: WordPress detection, enumeration and matching.
func (s *Scanner) Scan() (*Result, error) {
	if s.opts.Findings != nil {
		defer close(s.opts.Findings)
	}

	// --scope target URL validation happens before any request.
	if s.scopeRe != nil && !s.scopeRe.MatchString(s.base) {
		return nil, ErrOutOfScope
	}

	// --max-scan-duration: a scan-wide deadline. When it expires every
	// in-flight request is canceled and the scan returns the partial
	// results collected so far.
	var cancel context.CancelFunc
	if s.opts.MaxScanDuration > 0 {
		s.ctx, cancel = context.WithTimeout(context.Background(), s.opts.MaxScanDuration)
		defer cancel()
	}

	res := &Result{Target: s.base}
	scanStart := time.Now()
	pr := s.progress
	if pr != nil {
		defer pr.Finish()
	}

	coreVersion, evidence, fatalErr := s.detectWP()

	// An unreachable homepage is a hard failure: connection refused, proxy
	// failure, timeout or DNS error means the target cannot be scanned at
	// all — never "not WordPress".
	if fatalErr != nil {
		return nil, fmt.Errorf("cannot reach target: %w", fatalErr)
	}

	// --exclude-content-based: a matching homepage means a WAF or error
	// page, so the scan stops right away.
	if s.excludeRe != nil && s.excludeRe.MatchString(s.homepage) {
		return nil, ErrBlocked
	}

	res.Evidence = evidence
	res.IsWordPress = coreVersion != "" || len(evidence) > 0
	if !res.IsWordPress {
		res.Errors = append(res.Errors, ErrNotWordPress.Error())
		s.buildSummary(res, scanStart)
		if pr != nil {
			pr.LogInf("target %s does not appear to be WordPress", s.base)
		}
		return res, ErrNotWordPress
	}
	res.WordPressVersion = coreVersion
	res.CoreEvidence = s.coreEvidence
	if pr != nil {
		ver := ""
		if coreVersion != "" {
			ver = " " + coreVersion
		}
		pr.LogInf("detected WordPress%s at %s", ver, s.base)
	}

	// Always-on interesting finders (robots.txt, readme.html, debug.log,
	// xmlrpc.php, uploads listing, wp-config.php.bak, version.php).
	res.Interesting = s.interestingFinders()

	// Drop-in/cache-layer detection: cache headers on the homepage and an
	// exposed mu-plugins directory listing.
	res.Interesting = append(res.Interesting, s.dropinFinder()...)

	// Media enumeration: a homepage reference to the uploads directory is
	// enough for the simple presence check.
	if s.enumerateMedia() && strings.Contains(s.homepage, "/"+s.contentDir+"/uploads/") {
		res.Interesting = append(res.Interesting, "media uploads present")
	}

	// XML-RPC ping check (skip with --no-xmlrpc).
	if !s.opts.NoXMLRPC && s.checkXMLRPC() {
		res.XMLRPC = true
		if pr != nil {
			pr.LogInf("XML-RPC is enabled (xmlrpc.php responded)")
		}
	}

	// Optional file-based checks: config backups (cb), DB exports (dbe)
	// and exposed TimThumb copies (timthumb).
	if s.checks["cb"] {
		res.ConfigBackups = s.configBackupFinder()
	}
	if s.checks["dbe"] {
		res.DBExports = s.dbExportFinder()
	}
	if s.checks["timthumb"] && len(s.timthumbFinder()) > 0 {
		res.Interesting = append(res.Interesting, "timthumb.php exposed")
	}

	var mu sync.Mutex
	addDetected := func(list []Detected) {
		if len(list) == 0 {
			return
		}
		mu.Lock()
		res.Detected = append(res.Detected, list...)
		mu.Unlock()
	}
	addFindings := func(list []Finding) {
		if len(list) == 0 {
			return
		}
		if s.opts.Findings != nil {
			for i := range list {
				s.opts.Findings <- list[i]
			}
		}
		mu.Lock()
		res.Findings = append(res.Findings, list...)
		n := int64(len(res.Findings))
		mu.Unlock()
		if pr != nil {
			pr.SetFindings(n)
		}
	}

	// Authenticated REST inventory (--wp-auth USER:PASS): pull the
	// installed plugins and themes from the authenticated wp-json
	// endpoints over HTTP Basic auth. Rejected credentials (401) are a
	// WARN, never an error — the scan continues.
	if s.wpUser != "" {
		authDetected, authFindings, authStatus := s.authInventory()
		switch authStatus {
		case "failed":
			res.AuthStatus = "failed"
			if pr != nil {
				pr.LogInf("[WARN] wp-auth failed — invalid credentials")
			} else {
				fmt.Fprintln(os.Stderr, "[WARN] wp-auth failed — invalid credentials")
			}
		case "authenticated":
			res.AuthStatus = "authenticated"
			if pr != nil {
				pr.LogInf("wp-auth: %d plugin(s)/theme(s) detected", len(authDetected))
			}
		}
		addDetected(authDetected)
		addFindings(authFindings)
	}

	// REST API plugin listing is always attempted when plugins are enabled
	// (skipped when --wp-auth already queried it with credentials).
	if s.enumeratePlugins() && s.wpUser == "" {
		apiDetected, apiErrs := s.apiPlugins()
		addDetected(apiDetected)
		res.Errors = append(res.Errors, apiErrs...)
	}

	// Sitemap-driven passive discovery (--crawl-pages): runs after the
	// homepage passive detection stored s.homepage and before enumeration
	// so discovered slugs join the job list below. Its fetches draw from
	// the same --max-requests budget as enumeration.
	if s.opts.CrawlPages > 0 && !s.opts.APIOnly && (s.mode == "mixed" || s.mode == "passive") {
		s.discoverViaSitemap(s.opts.CrawlPages)
	}

	jobs := s.buildJobs()
	if s.opts.APIOnly {
		jobs = nil
	}
	// --max-requests caps the brute-force request budget. Sitemap crawling
	// (--crawl-pages) spent its share first; jobs keep whatever is left,
	// and the remainder funds user enumeration.
	budget := s.maxRequests - s.sitemapRequests
	if budget < 0 {
		budget = 0
	}
	if len(jobs) > budget {
		jobs = jobs[:budget]
	}
	remaining := budget - len(jobs)

	userPlan := 0
	authorPlan := 0
	if s.enumerateUsers() && remaining > 0 {
		userPlan = 1 // wp-json/wp/v2/users
		rem := remaining - 1
		if !s.opts.APIOnly && rem > 0 {
			authorPlan = rem
			if authorPlan > maxAuthorChecks {
				authorPlan = maxAuthorChecks
			}
			userPlan += authorPlan
		}
	}

	if pr != nil {
		if len(jobs) > 0 {
			plugins, themes := countKinds(jobs)
			pr.LogInf("enumerating %d plugin(s) and %d theme(s)", plugins, themes)
		}
		if userPlan > 0 {
			pr.LogInf("enumerating users (REST API + up to %d author id(s))", authorPlan)
		}
		pr.SetTotal(int64(len(jobs) + userPlan))
	}

	if len(jobs) > 0 {
		sem := make(chan struct{}, s.opts.Threads)
		var wg sync.WaitGroup
		for _, j := range jobs {
			if s.scanDone() || s.rateLimitAbort() {
				break
			}
			j := j
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if s.rateLimitAbort() {
					if pr != nil {
						pr.AddDone(1)
					}
					return
				}
				if pr != nil {
					pr.SetCurrent(j.label(""))
				}
				detected, findings := s.scanJob(j)
				addDetected(detected)
				addFindings(findings)
				if pr != nil {
					ver := ""
					if len(detected) == 1 && detected[0].Version != "unknown" {
						ver = detected[0].Version
					}
					pr.SetCurrent(j.label(ver))
					pr.AddDone(1)
				}
			}()
		}
		wg.Wait()
	}

	// Passive ?ver= versions (homepage + sitemap pages): fill in versions
	// for passively observed components that enumeration could not pin
	// down, then match them against the database.
	s.mergePassiveDetections(res, addFindings)

	if userPlan > 0 {
		if pr != nil {
			pr.SetCurrent("user:wp-json/users")
		}
		apiUsers, userErrs := s.usersFromAPI()
		res.Errors = append(res.Errors, userErrs...)
		if pr != nil {
			pr.AddDone(1)
		}
		var authorUsers []User
		if authorPlan > 0 {
			if pr != nil {
				pr.SetCurrent(fmt.Sprintf("user:author=1..%d", authorPlan))
			}
			authorUsers, userErrs = s.usersFromAuthors(authorPlan)
			res.Errors = append(res.Errors, userErrs...)
			if pr != nil {
				pr.AddDone(int64(authorPlan))
			}
		}
		res.Users = normalizeUsers(apiUsers, authorUsers)
		// Login-error username oracle: when REST and author enumeration came
		// up empty, wp-login.php's #login_error message can still confirm
		// accounts. Candidates come from the --usernames wordlist when
		// provided, otherwise the common default set. Skipped with
		// --no-brute, capped at maxAuthorChecks probes.
		if len(res.Users) == 0 && !s.opts.NoBrute {
			candidates := s.usernames
			if len(candidates) == 0 {
				candidates = []string{"admin", "administrator"}
			}
			if len(candidates) > maxAuthorChecks {
				candidates = candidates[:maxAuthorChecks]
			}
			if pr != nil {
				pr.SetCurrent("user:wp-login oracle")
			}
			found := s.loginOracleUsernames(candidates)
			res.Users = normalizeUsers(res.Users, usersFromNames(found))
			if pr != nil {
				pr.AddDone(int64(len(candidates)))
			}
			if pr != nil && len(res.Users) > 0 {
				pr.LogInf("login oracle confirmed %d user(s)", len(res.Users))
			}
		}
		if pr != nil && len(res.Users) > 0 {
			pr.LogInf("found %d user(s)", len(res.Users))
		}
	}

	// Credential brute force: wp-login (--passwords) and the XML-RPC
	// multicall attack (--xmlrpc-brute). Both are loud by nature, so they
	// are paced by their own throttle (1 req/s unless --rate-limit is
	// set). XML-RPC only runs when xmlrpc.php answered the ping check.
	if s.loginBrute {
		creds := unique(append(append([]string{}, s.usernames...), userSlugs(res.Users)...))
		if len(creds) > 0 {
			if pr != nil {
				pr.LogInf("wp-login brute: %d user(s) x %d password(s)", len(creds), len(s.passwords))
			}
			res.LoginBrutes = append(res.LoginBrutes, s.loginBruteForce(creds, s.passwords)...)
			if pr != nil && len(res.LoginBrutes) > 0 {
				pr.LogInf("wp-login brute: %d valid credential(s)", len(res.LoginBrutes))
			}
		}
	}
	if s.xmlrpcBrute {
		if !res.XMLRPC {
			if pr != nil {
				pr.LogInf("xmlrpc brute: xmlrpc.php not detected — skipping")
			}
		} else {
			creds := unique(append(append([]string{}, s.usernames...), s.singleUser))
			if pr != nil {
				pr.LogInf("xmlrpc brute: multicall %d user(s) x %d password(s)", len(creds), len(s.xmlrpcPasswords))
			}
			brutes := s.xmlrpcBruteForce(creds, s.xmlrpcPasswords)
			if pr != nil && len(brutes) > 0 {
				pr.LogInf("xmlrpc brute: %d valid credential(s)", len(brutes))
			}
			res.LoginBrutes = append(res.LoginBrutes, brutes...)
		}
	}

	// Deduplicate detected components, keeping the highest-confidence
	// version-known entry per slug: a passive ?ver= hint (confidence 60)
	// never overrides a readme (95), and an unauthenticated REST listing
	// (100) wins ties against the equally-scored auth-rest inventory.
	bySlug := make(map[string]Detected, len(res.Detected))
	for _, d := range res.Detected {
		if prev, ok := bySlug[d.Slug]; ok {
			if !preferDetected(d, prev) {
				continue
			}
		}
		bySlug[d.Slug] = d
	}
	res.Detected = res.Detected[:0]
	for _, d := range bySlug {
		res.Detected = append(res.Detected, d)
	}
	sort.Slice(res.Detected, func(i, j int) bool { return res.Detected[i].Slug < res.Detected[j].Slug })
	sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].Slug < res.Findings[j].Slug })

	res.RateLimitHits = s.rateLimitHits()
	res.TimedOut = s.scanDone()
	res.RateLimitedAbort = s.rateLimitAbort()
	s.buildSummary(res, scanStart)
	return res, nil
}

// buildSummary fills res.Summary with scan-wide statistics gathered from
// the counters and the final result (skipped entirely with --no-summary).
func (s *Scanner) buildSummary(res *Result, scanStart time.Time) {
	if s.opts.NoSummary {
		return
	}
	critical, high, medium, low, total := severityCounts(res.Findings)
	res.Summary = &Summary{
		DurationMS:  time.Since(scanStart).Milliseconds(),
		Requests:    s.requestCount(),
		RateLimited: res.RateLimitHits,
		Detected:    len(res.Detected),
		Findings:    total,
		Critical:    critical,
		High:        high,
		Medium:      medium,
		Low:         low,
		Users:       len(res.Users),
	}
}

// severityCounts tallies the vulnerabilities of the findings by rating.
func severityCounts(findings []Finding) (critical, high, medium, low, total int) {
	for i := range findings {
		for _, v := range findings[i].Vulnerabilities {
			total++
			switch strings.ToLower(v.Rating) {
			case "critical":
				critical++
			case "high":
				high++
			case "medium":
				medium++
			case "low":
				low++
			}
		}
	}
	return
}

// requestCount returns the number of HTTP requests issued through fetch().
func (s *Scanner) requestCount() int {
	return int(s.requests.Load())
}

// rateLimitHits returns the number of 429 responses seen during the scan.
func (s *Scanner) rateLimitHits() int {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	return s.rateHits
}

// countKinds tallies job kinds for progress logging.
func countKinds(jobs []job) (plugins, themes int) {
	for _, j := range jobs {
		switch j.kind {
		case "plugin":
			plugins++
		case "theme":
			themes++
		}
	}
	return
}

// userSlugs extracts the slugs of the given users for brute-force tries.
func userSlugs(users []User) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Slug)
	}
	return out
}

// usersFromNames maps confirmed usernames (e.g. from the login-error
// oracle) onto User entries carrying the slug only.
func usersFromNames(names []string) []User {
	out := make([]User, 0, len(names))
	for _, n := range names {
		out = append(out, User{Slug: n})
	}
	return out
}
