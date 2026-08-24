#!/usr/bin/env bash
# e2e-realwp — real-WordPress end-to-end scan assertions (nightly, CI only).
#
# Usage: scripts/e2e-realwp.sh <onyx-binary> <wordpress-feed.json> <base-url>
#
# The workflow (.github/workflows/e2e-realwp.yml) owns the environment
# orchestration — MySQL + WordPress service containers, the wp-cli core
# install and the contact-form-7 activation. This script is deliberately
# focused on the SCAN assertions against that already-installed, real
# WordPress:
#
#   * scan exit code is in {0,5} (5 = findings, which the minimal feed's
#     universal-range contact-form-7 record produces; 0 = clean scan);
#   * the target is recognized as WordPress and wordpress_version is
#     non-empty (NEVER a specific version — assertions must survive WP
#     version drift);
#   * xmlrpc is true (stock installs always ship xmlrpc.php);
#   * `interesting` does NOT contain the wp-config.php.bak or
#     wp-includes/version.php false positives (a real install 404s the
#     backup and serves an empty-body version.php, neither is exposed);
#   * users is non-empty (wp-cli core install creates the "admin" user);
#   * detected contains contact-form-7 (installed by the workflow via
#     wp-cli, discovered through the readme.txt enumeration probe).
#
# Exit code 0 on all-pass, 1 on any assertion failure, 2 on usage/tooling
# errors. No network is needed beyond the target itself: the scan runs with
# --no-intel --no-update-check so nothing phones home.
set -u

BIN="${1:-}"
FEED="${2:-}"
BASE="${3:-}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/onyx-e2e-realwp.XXXXXX")"
MAX_REQUESTS="${ONYX_REALWP_MAX_REQUESTS:-600}"

PASS=0
FAIL=0

say()  { printf '%s\n' "$*"; }
tally_line() {
    case "$1" in
        PASS:*) say "$1"; PASS=$((PASS + 1)) ;;
        FAIL:*) say "$1"; FAIL=$((FAIL + 1)) ;;
    esac
}
# Runs in the current shell (process substitution) so the PASS/FAIL
# counters propagate to the summary below.
tally() {
    while IFS= read -r line; do
        tally_line "$line"
    done < <("$@")
}

# --- argument validation ---------------------------------------------------
if [ -z "$BIN" ] || [ -z "$FEED" ] || [ -z "$BASE" ]; then
    say "usage: $0 <onyx-binary> <wordpress-feed.json> <base-url>" >&2
    exit 2
fi
if [ ! -x "$BIN" ]; then say "FAIL: binary not executable: $BIN"; exit 2; fi
if [ ! -r "$FEED" ]; then say "FAIL: feed not readable: $FEED"; exit 2; fi
if ! command -v python3 >/dev/null 2>&1; then say "FAIL: python3 is required"; exit 2; fi
if ! python3 -c "import json; json.load(open('$FEED'))"; then
    say "FAIL: $FEED is not valid JSON"
    exit 2
fi

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- wait for the installed WordPress to answer ----------------------------
ready=0
for _ in $(seq 1 60); do
    if python3 -c "import urllib.request,sys; r=urllib.request.urlopen('$BASE/', timeout=2); sys.exit(0 if r.status==200 else 1)" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 2
done
if [ "$ready" != "1" ]; then
    say "FAIL: WordPress did not become reachable at $BASE"
    exit 1
fi
say "WordPress reachable at $BASE"
say ""

# --- assertions ------------------------------------------------------------
assert_result() {
    local out="$1"
    python3 - "$out" <<'PY'
import json, re, sys
ok = True
out = sys.argv[1]
try:
    with open(out) as f:
        r = json.load(f)
except Exception as e:
    print("FAIL: cannot parse scan JSON output: %s" % e)
    sys.exit(0)

def chk(cond, msg):
    global ok
    print(("PASS" if cond else "FAIL") + ": " + msg)
    if not cond:
        ok = False

chk(r.get("is_wordpress") is True, "is_wordpress is true")
chk(bool(r.get("wordpress_version")), "wordpress_version is non-empty")
chk(r.get("xmlrpc") is True, "xmlrpc is true")

interesting = r.get("interesting", [])
chk(not any("wp-config.php.bak" in i for i in interesting),
    "interesting does NOT contain wp-config.php.bak")
chk(not any("wp-includes/version.php" in i for i in interesting),
    "interesting does NOT contain wp-includes/version.php")

chk(len(r.get("users", [])) > 0, "users is non-empty")

detected = [d.get("slug") for d in r.get("detected", [])]
chk("contact-form-7" in detected, "detected contains contact-form-7")
PY
}

# --- scan ------------------------------------------------------------------
say "=== scan $BASE (--enumerate ptum) ==="
"$BIN" scan "$BASE" --db "$FEED" --enumerate ptum --max-requests "$MAX_REQUESTS" \
    --no-intel --no-update-check --format json >"$WORK/scan.json" 2>"$WORK/scan.err" || rc=$?
case "${rc:-0}" in
    0) say "PASS: scan exit code == 0 (no findings)"
       PASS=$((PASS + 1)) ;;
    5) say "PASS: scan exit code == 5 (vulnerability found)"
       PASS=$((PASS + 1)) ;;
    *) say "FAIL: scan exit code == ${rc:-0} (want 0 or 5)"
       FAIL=$((FAIL + 1)) ;;
esac
tally assert_result "$WORK/scan.json"
say ""

# --- summary ----------------------------------------------------------------
say "=== summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    say "REALWP E2E FAILED (scan log in $WORK/scan.err)"
    exit 1
fi
say "REALWP E2E PASSED"
