#!/usr/bin/env bash
# P3-19 — hermetic end-to-end scan test.
#
# Usage: scripts/e2e.sh <onyx-binary> <wordfence.json-feed>
#
# Starts the fake WordPress target (scripts/e2e_fakewp.py) on 127.0.0.1:8123,
# scans it with a freshly built onyx binary against a minimal Wordfence-shaped
# feed, and asserts the scanner's observable behaviour:
#
#   scan 1 (--enumerate ptum): exit code 5 (vulnerability found), core version
#     "7.1", the vulnerable plugin in `detected`, no false positives for the
#     wp-config.php.bak decoy or the empty-body version.php, and "admin" among
#     the enumerated users.
#   scan 2 (--enumerate u): REST users discovered via the rest_route fallback
#     (/wp-json/wp/v2/users 404s; /?rest_route=/wp/v2/users answers).
#
# Fully hermetic: no network beyond localhost, no docker, no jq — only bash,
# python3 (stdlib) and the onyx binary. Exit code 0 on all-pass, 1 on any
# failure.
set -u

BIN="${1:-}"
FEED="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${ONYX_E2E_PORT:-8123}"
BASE="http://127.0.0.1:${PORT}"

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
if [ -z "$BIN" ] || [ -z "$FEED" ]; then
    say "usage: $0 <onyx-binary> <wordfence.json-feed>" >&2
    exit 2
fi
if [ ! -x "$BIN" ]; then say "FAIL: binary not executable: $BIN"; exit 2; fi
if [ ! -r "$FEED" ]; then say "FAIL: feed not readable: $FEED"; exit 2; fi
if ! command -v python3 >/dev/null 2>&1; then say "FAIL: python3 is required"; exit 2; fi
if ! python3 -c "import json; json.load(open('$FEED'))"; then
    say "FAIL: $FEED is not valid JSON"
    exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/onyx-e2e.XXXXXX")"
SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- start the fake WordPress target --------------------------------------
python3 "$SCRIPT_DIR/e2e_fakewp.py" --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
say "started fake WordPress (pid $SRV_PID) at $BASE"

ready=0
for _ in $(seq 1 50); do
    if python3 -c "import urllib.request,sys; urllib.request.urlopen('$BASE/', timeout=1).read()" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" != "1" ]; then
    say "FAIL: fake WordPress did not become reachable at $BASE"
    cat "$WORK/server.log" >&2
    exit 1
fi
say "fake WordPress reachable at $BASE"
say ""

# --- assertions ------------------------------------------------------------
# Each assert_* function prints PASS/FAIL lines; the tally() pipe converts
# them into counters. Functions never exit non-zero (they must not abort the
# script), so pipefail/-e concerns do not apply.

assert_scan1() {
    local out="$1"
    python3 - "$out" <<'PY'
import json, sys
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

chk(r.get("wordpress_version") == "7.1", "wordpress_version == \"7.1\"")

detected = r.get("detected", [])
acme = [d for d in detected if d.get("slug") == "acme-toolbox"]
chk(len(acme) == 1, "detected contains the vulnerable plugin acme-toolbox")
chk(any(d.get("installed_version") == "1.2.0" for d in acme),
    "acme-toolbox installed_version == \"1.2.0\"")

interesting = r.get("interesting", [])
chk(not any("wp-config.php.bak" in i for i in interesting),
    "interesting does NOT contain wp-config.php.bak")
chk(not any("wp-includes/version.php" in i for i in interesting),
    "interesting does NOT contain wp-includes/version.php")

users = [u.get("slug") for u in r.get("users", [])]
chk("admin" in users, "users contains admin")
PY
}

assert_scan2() {
    local out="$1"
    python3 - "$out" <<'PY'
import json, sys
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

users = [u.get("slug") for u in r.get("users", [])]
chk("admin" in users, "users contains admin (rest_route discovery)")
PY
}

# --- scan 1: full enumeration (ptum) --------------------------------------
say "=== scan 1: --enumerate ptum (expect vulnerability found) ==="
"$BIN" scan "$BASE" --db "$FEED" --enumerate ptum --max-requests 150 \
    --no-intel --format json >"$WORK/scan1.json" 2>"$WORK/scan1.err" || rc1=$?
if [ "${rc1:-0}" -eq 5 ]; then
    say "PASS: scan exit code == 5 (vulnerability found)"
    PASS=$((PASS + 1))
else
    say "FAIL: scan exit code == ${rc1:-0} (want 5)"
    FAIL=$((FAIL + 1))
fi
tally assert_scan1 "$WORK/scan1.json"
say ""

# --- scan 2: user enumeration only (u) ------------------------------------
say "=== scan 2: --enumerate u (expect rest_route user discovery) ==="
"$BIN" scan "$BASE" --db "$FEED" --enumerate u --max-requests 150 \
    --no-intel --format json >"$WORK/scan2.json" 2>"$WORK/scan2.err" || rc2=$?
tally assert_scan2 "$WORK/scan2.json"
say ""

# --- summary ----------------------------------------------------------------
say "=== summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    say "E2E FAILED (scan logs in $WORK)"
    exit 1
fi
say "E2E PASSED"
