#!/usr/bin/env bash
# End-to-end test: real NFQUEUE rule, real blocker, real HTTP/TLS clients.
# Everything stays on 127.0.0.1 inside this machine; the iptables rule only
# matches loopback traffic to two test ports and is removed on exit.
# Usage (root): scripts/e2e.sh
set -u
cd "$(dirname "$0")/.."

QUEUE=7
HTTP_PORT=18080
TLS_PORT=18443
TMP=$(mktemp -d)
RULE=(OUTPUT -o lo -p tcp -m multiport --dports $HTTP_PORT,$TLS_PORT -j NFQUEUE --queue-num $QUEUE --queue-bypass)
pass=0 fail=0

cleanup() {
    local rc=$?
    iptables -D "${RULE[@]}" 2>/dev/null
    kill $(jobs -p) 2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
    exit $rc
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
make -s 1m-block || exit 1

# --- test servers -----------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=e2e.test \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null
(cd "$TMP" && exec python3 -m http.server $HTTP_PORT --bind 127.0.0.1 >/dev/null 2>&1) &
# Threaded TLS server with the handshake done in the worker thread: a test
# connection whose ClientHello was dropped must not stall the next one.
# (openssl s_server serves one connection at a time and caused false failures.)
cat > "$TMP/tls_server.py" <<'PY'
import http.server, ssl, sys
d, port = sys.argv[1], int(sys.argv[2])
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{d}/cert.pem", f"{d}/key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
srv.serve_forever()
PY
(cd "$TMP" && exec python3 tls_server.py "$TMP" $TLS_PORT >/dev/null 2>&1) &
sleep 1

printf '1,blocked.test\n2,ads.example\n' > "$TMP/list.csv"

http() { curl -s -o /dev/null -w '%{http_code}' -m 3 -H "Host: $1" "http://127.0.0.1:$HTTP_PORT/"; }
tls()  { curl -sk -o /dev/null -w '%{http_code}' -m 3 --resolve "$1:$TLS_PORT:127.0.0.1" "https://$1:$TLS_PORT/"; }

expect() {   # expect <name> <want> <got>
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf '  ok    %-44s %s\n' "$1" "$3"
    else fail=$((fail + 1)); printf '  FAIL  %-44s want %s got %s\n' "$1" "$2" "$3"; fi
}

echo "== without rule (sanity)"
expect "http allowed.test"            200 "$(http allowed.test)"
expect "tls  allowed.test"            200 "$(tls allowed.test)"

iptables -I "${RULE[@]}"
./1m-block -q $QUEUE "$TMP/list.csv" > "$TMP/log" 2>&1 &
BLOCKER=$!
sleep 1

echo "== blocker running"
expect "http allowed.test"            200 "$(http allowed.test)"
expect "http blocked.test (drop)"     000 "$(http blocked.test)"
expect "http WWW.Blocked.Test:80"     000 "$(http WWW.Blocked.Test:80)"
expect "http notblocked.test"         200 "$(http notblocked.test)"
expect "tls  allowed.test"            200 "$(tls allowed.test)"
expect "tls  blocked.test (drop)"     000 "$(tls blocked.test)"
expect "tls  cdn.ads.example (drop)"  000 "$(tls cdn.ads.example)"
expect "tls  ads.example.org"         200 "$(tls ads.example.org)"

kill -INT $BLOCKER; wait $BLOCKER 2>/dev/null
echo "== blocker stopped, rule still present (--queue-bypass -> fail open)"
expect "http blocked.test"            200 "$(http blocked.test)"

echo "== blocker log"
sed 's/^/  | /' "$TMP/log"
grep -q "BLOCK tls  cdn.ads.example (rule: ads.example)" "$TMP/log"
expect "log names the matched rule"   0 "$?"

echo "== $pass passed, $fail failed"
[ $fail = 0 ]
