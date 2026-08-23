#!/bin/sh
# obserwrt - IPFIX end-to-end test using goflow2.
#
# Validates that the exporter encodes valid IPFIX which an independent
# collector (goflow2) can decode. Sends one fixed IPv4 TCP and one IPv6 UDP flow
# via scripts/emit-test.uc and checks goflow2 decodes the expected fields.
#
# Requirements: ucode with the UCI/struct/socket/log modules, and goflow2
# (GOFLOW2 env / `goflow2` on PATH, or docker with the netsampler/goflow2 image).
#
# Usage: sh scripts/test-ipfix.sh [collector_host] [collector_port]
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HOST="${1:-127.0.0.1}"
PORT="${2:-4739}"
SCRATCH="$(mktemp -d)"
LOG="$SCRATCH/goflow2.log"
store_pid=""
cleanup_docker=""

trap 'rm -rf "$SCRATCH"; [ -n "$store_pid" ] && kill "$store_pid" 2>/dev/null || true; [ -n "$cleanup_docker" ] && docker stop "$cleanup_docker" >/dev/null 2>&1 || true' EXIT

# ---- start goflow2 -----------------------------------------------------
mkdir -p "$SCRATCH/uc"
cp "$ROOT/scripts/emit-test.uc" \
   "$ROOT/obserwrt/files/usr/share/ucode/obserwrt/flow.uc" \
   "$ROOT/obserwrt/files/usr/share/ucode/obserwrt/exporter_ipfix.uc" \
   "$SCRATCH/uc/"

if [ -n "${GOFLOW2:-}" ]; then
	$GOFLOW2 -listen "netflow://$HOST:$PORT" -format text >"$LOG" 2>&1 &
	store_pid=$!
	sleep 1
elif command -v goflow2 >/dev/null 2>&1; then
	goflow2 -listen "netflow://$HOST:$PORT" -format text >"$LOG" 2>&1 &
	store_pid=$!
	sleep 1
elif command -v docker >/dev/null 2>&1; then
	cleanup_docker=$(docker run -d --rm --network host netsampler/goflow2 \
		-listen "netflow://$HOST:$PORT" -format text)
	sleep 2
else
	echo "test-ipfix: no goflow2 (set GOFLOW2 or install/binary it, or use docker)" >&2
	exit 2
fi

# ---- emit the test flows ----------------------------------------------
COLLECTOR_HOST="$HOST" COLLECTOR_PORT="$PORT" ucode "$SCRATCH/uc/emit-test.uc"

# ---- let goflow2 flush/decode, then assert ----------------------------
sleep 2

if [ -n "$store_pid" ]; then
	kill "$store_pid" 2>/dev/null || true
	wait "$store_pid" 2>/dev/null || true
elif [ -n "$cleanup_docker" ]; then
	docker stop "$cleanup_docker" >/dev/null 2>&1 || true
fi

v4="src_addr=192.0.2.1 dst_addr=198.51.100.2 src_port=12345 dst_port=80 proto=TCP packets=10"
v6="src_addr=2001:db8::1 dst_addr=2001:db8::2 src_port=53 dst_port=443 packets=2"

ok=1
grep -q -- "$v4" "$LOG" || { echo "MISSING v4 flow: $v4"; ok=0; }
grep -q -- "$v6" "$LOG" || { echo "MISSING v6 flow: $v6"; ok=0; }

echo "---- goflow2 output ----"
cat "$LOG"

if [ "$ok" = "0" ]; then
	echo "test-ipfix: FAILED" >&2
	exit 1
fi
echo "test-ipfix: OK (goflow2 decoded v4 + v6 flows)"