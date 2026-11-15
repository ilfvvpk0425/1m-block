#!/usr/bin/env bash
# Throughput through NFQUEUE on loopback with iperf3 (TCP, MSS 1460 so packets
# are Ethernet-sized). Compares: no rule / rule + 1m-block with the full list /
# rule + 1m-block in monitor mode. Every client->server packet goes through the
# queue; the payload is random data, so this measures queue + parse overhead.
# Usage (root): scripts/load.sh data/top-1m.csv
set -u
cd "$(dirname "$0")/.."
LIST=${1:-data/top-1m.csv}
PORT=15201 QUEUE=8 SECS=${SECS:-8}
RULE=(OUTPUT -o lo -p tcp --dport $PORT -j NFQUEUE --queue-num $QUEUE --queue-bypass)
TMP=$(mktemp -d)

cleanup() {
    local rc=$?
    iptables -D "${RULE[@]}" 2>/dev/null
    kill $(jobs -p) 2>/dev/null; wait 2>/dev/null
    rm -rf "$TMP"
    exit $rc
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
make -s 1m-block || exit 1
cp "$LIST" "$TMP/list.csv"                       # local fs: /mnt/c is slow to read

iperf3 -s -p $PORT > "$TMP/iperf-server.log" 2>&1 &   # plain background job so cleanup() kills it
sleep 0.5

run() {   # prints Gbit/s and packets/s of the sender
    iperf3 -c 127.0.0.1 -p $PORT -t "$SECS" -M 1460 -J > "$TMP/r.json" 2>/dev/null
    python3 - "$TMP/r.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
s = r["end"]["sum_received"]
bps = s["bits_per_second"]
print(f"{bps/1e9:6.2f} Gbit/s  {bps/8/1460/1e3:8.0f} k packets/s  (cpu sender {r['end']['cpu_utilization_percent']['host_total']:.0f}%)")
PY
}

echo "== baseline: no NFQUEUE rule"
run

iptables -I "${RULE[@]}"
./1m-block -q $QUEUE "$TMP/list.csv" > "$TMP/blk.log" 2>&1 &
B=$!
for i in $(seq 1 50); do grep -q listening "$TMP/blk.log" && break; sleep 0.1; done
echo "== NFQUEUE + 1m-block (1M domains)"
run
kill -INT $B; wait $B 2>/dev/null
sed 's/^/  | /' "$TMP/blk.log"

./1m-block -n -q $QUEUE "$TMP/list.csv" > "$TMP/blk.log" 2>&1 &
B=$!
for i in $(seq 1 50); do grep -q listening "$TMP/blk.log" && break; sleep 0.1; done
echo "== NFQUEUE + 1m-block monitor mode (-n)"
run
kill -INT $B; wait $B 2>/dev/null

echo "== rule present, no listener (--queue-bypass)"
run

# Host / SNI only appear in the first data packets of a connection:
# queue just the first 10 packets client->server of each connection.
iptables -D "${RULE[@]}"
RULE=(OUTPUT -o lo -p tcp --dport $PORT -m connbytes --connbytes 0:10 --connbytes-dir original
      --connbytes-mode packets -j NFQUEUE --queue-num $QUEUE --queue-bypass)
iptables -I "${RULE[@]}"
./1m-block -q $QUEUE "$TMP/list.csv" > "$TMP/blk.log" 2>&1 &
B=$!
for i in $(seq 1 50); do grep -q listening "$TMP/blk.log" && break; sleep 0.1; done
echo "== NFQUEUE (first 10 packets per connection only) + 1m-block"
run
kill -INT $B; wait $B 2>/dev/null
sed 's/^/  | /' "$TMP/blk.log"
