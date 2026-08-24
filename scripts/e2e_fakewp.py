#!/usr/bin/env python3
"""Minimal fake WordPress target for the hermetic onyx e2e test (P3-19).

Emulates just enough of a WordPress install for the scanner's happy path:

  * a homepage carrying the generator meta tag (core version 7.1) plus
    wp-content/plugin and wp-content/theme asset references (?ver=)
  * a real plugin readme.txt whose "Stable tag:" matches a vulnerable
    range in the test feed (acme-toolbox 1.2.0 vs <= 1.2.3)
  * /wp-config.php.bak that answers 200 with the *homepage HTML* (a decoy:
    front-controller rewrite behaviour; must NOT be flagged as a config
    backup because it never looks like PHP config)
  * /wp-includes/version.php that answers 200 with an EMPTY body (stock
    WordPress behaviour; must NOT be flagged as exposed)
  * REST user discovery ONLY through /?rest_route=/wp/v2/users while the
    pretty /wp-json/wp/v2/users spelling 404s (no rewrite rules)
  * /robots.txt with Disallow rules
  * a front-controller fallback: every other path 301-redirects to "/"

Binds 127.0.0.1:8123. Python stdlib http.server only; no third-party
packages, no network beyond the localhost listener.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 8123

HOMEPAGE = """<!DOCTYPE html>
<html>
<head>
<title>ACME Blog</title>
<meta name="generator" content="WordPress 7.1" />
<link rel="https://api.w.org/" href="http://127.0.0.1:8123/wp-json/" />
</head>
<body>
<script src="/wp-content/plugins/acme-toolbox/assets/app.js?ver=1.2.0"></script>
<link rel="stylesheet" href="/wp-content/themes/acme-theme/style.css?ver=1.0.0" />
<p>Welcome to the ACME blog.</p>
</body>
</html>
"""

ROBOTS = """User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
"""

LOGIN = """<!DOCTYPE html>
<html><body>
<form name="loginform" id="loginform">
<input type="text" name="log" id="user_login" />
<input type="password" name="pwd" />
</form>
</body></html>
"""

# A real plugin readme.txt: "Stable tag:" must match a vulnerable range in
# the test feed (acme-toolbox installed 1.2.0, feed says <= 1.2.3).
PLUGIN_README = """=== ACME Toolbox ===
Contributors: acme
Donate link: https://example.com/donate
Tags: tools
Requires at least: 5.0
Tested up to: 7.1
Stable tag: 1.2.0

ACME Toolbox adds shiny widgets to your site.

== Changelog ==

= 1.2.0 =
* Bug fixes.

= 1.2.1 =
* Security fix.
"""

USERS_JSON = json.dumps(
    [
        {"id": 1, "name": "admin", "slug": "admin"},
        {"id": 2, "name": "Editor", "slug": "editor"},
    ]
)


class FakeWPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FakeWP/1.0"

    def log_message(self, fmt, *args):
        # Compact single-line request log (goes to stderr, captured by the
        # e2e harness for debugging).
        BaseHTTPRequestHandler.log_message(self, fmt, *args)

    # --- helpers ---------------------------------------------------------

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(self, location):
        # Front-controller emulation: missing paths bounce to "/" (which
        # then answers 200 + homepage HTML).
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- routing ---------------------------------------------------------

    def do_GET(self):
        base, _, query = self.path.partition("?")

        # REST user enumeration: only the plain-permalink rest_route form
        # works; the pretty /wp-json/... spelling 404s (no rewrite rules).
        if base == "/" and query == "rest_route=/wp/v2/users":
            self._send(200, USERS_JSON, "application/json; charset=utf-8")
            return
        if base == "/wp-json/wp/v2/users":
            self._send(404, b"")
            return

        routes = {
            "/": (200, HOMEPAGE),
            "/robots.txt": (200, ROBOTS, "text/plain; charset=utf-8"),
            "/readme.html": (404, ""),
            "/wp-content/debug.log": (404, ""),
            "/xmlrpc.php": (404, ""),
            "/wp-content/uploads/": (404, ""),
            "/wp-content/mu-plugins/": (404, ""),
            "/wp-login.php": (200, LOGIN),
            "/wp-json/": (404, ""),
            "/wp-json/wp/v2/plugins": (404, ""),
            # Decoy: 200 + homepage HTML. Must NOT be flagged as a config
            # backup (the scanner requires a body that looks like PHP
            # config: "<?php" plus DB_NAME/DB_PASSWORD/table_prefix).
            "/wp-config.php.bak": (200, HOMEPAGE),
            # Stock WP answers 200 with an EMPTY body here; must NOT be
            # flagged as exposed (scanner requires a non-empty body).
            "/wp-includes/version.php": (200, ""),
            "/wp-content/plugins/acme-toolbox/readme.txt": (200, PLUGIN_README, "text/plain; charset=utf-8"),
        }
        if base in routes:
            code, body, *rest = routes[base]
            ctype = rest[0] if rest else None
            if ctype is None:
                ctype = "text/plain; charset=utf-8" if isinstance(body, str) else "text/html; charset=utf-8"
            self._send(code, body, ctype)
            return

        # Everything else is a "missing file": front-controller rewrite.
        self._redirect("/")

    def do_POST(self):
        base, _, _ = self.path.partition("?")
        # xmlrpc.php is used by the scanner's ping check (POST); it is 404
        # here so XML-RPC is correctly reported as disabled.
        if base == "/xmlrpc.php":
            self._send(404, b"")
            return
        self._redirect("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port (default 8123)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((HOST, args.port), FakeWPHandler)
    print("fake WordPress listening on http://%s:%d" % (HOST, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
