#!/bin/sh
# obserwrt - IPFIX end-to-end test using goflow2.
#
# Validates that the exporter encodes valid IPFIX which an independent
# collector (goflow2) can decode. Sends one fixed IPv4 TCP and one IPv6 UDP flow
# via the native C++ emitter (obserwrt-emit, built from tests/emit_native.cpp)
# and checks goflow2 decodes the expected fields.
#
# Usage: sh scripts/test-ipfix.sh [collector_host] [collector_port]
# Env:   OBSERWRT_EMIT=<path to obserwrt-emit>  (default: $ROOT/build/obserwrt-emit)
#        GOFLOW2=<path to goflow2 binary>       (default: goflow2 or docker
#                                      netsampler/goflow2 on the host)
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HOST="${1:-127.0.0.1}"
PORT="${2:-4739}"
EMIT="${OBSERWRT_EMIT:-$ROOT/build/obserwrt-emit}"

SCRATCH="$(mktemp -d)"
LOG="$SCRATCH/goflow2.log"
store_pid=""
cleanup_docker=""

trap 'rm -rf "$SCRATCH"; [ -n "$store_pid" ] && kill "$store_pid" 2>/dev/null || true; [ -n "$cleanup_docker" ] && docker stop "$cleanup_docker" >/dev/null 2>&1 || true' EXIT

# ---- start goflow2 -----------------------------------------------------
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

# ---- emit the test flows (native C++ exporter) -------------------------
if [ ! -x "$EMIT" ]; then
	echo "test-ipfix: emitter not found at $EMIT (build obserwrt-emit first)" >&2
	exit 2
fi
"$EMIT" "$HOST" "$PORT"

# ---- let goflow2 flush/decode, then assert ----------------------------
sleep 2

if [ -n "$store_pid" ]; then
	kill "$store_pid" 2>/dev/null || true
	wait "$store_pid" 2>/dev/null || true
elif [ -n "$cleanup_docker" ]; then
	# goflow2 runs in the container; pull its decoded output into $LOG before
	# stopping it (the `-d`/native branches wrote $LOG at startup already).
	docker logs "$cleanup_docker" >"$LOG" 2>&1 || true
	docker stop "$cleanup_docker" >/dev/null 2>&1 || true
fi

# goflow2's text output is `key=val` pairs in a fixed but non-obvious order, so
# assert each flow by its distinguishing fields (order-independent).
ok=1
check() {
	if ! grep -q -- "$1" "$LOG"; then echo "MISSING: $1"; ok=0; fi
}
check "src_addr=192.0.2.1 dst_addr=198.51.100.2"
check "src_port=12345"
check "dst_port=80"
check "proto=TCP"
check "packets=10"
check "bytes=12340"
check "src_addr=2001:db8::1 dst_addr=2001:db8::2"
check "src_port=53"
check "dst_port=443"
check "proto=UDP"
check "packets=2"
check "bytes=200"

echo "---- goflow2 output ----"
cat "$LOG"

if [ "$ok" = "0" ]; then
	echo "test-ipfix: FAILED" >&2
	exit 1
fi
echo "test-ipfix: OK (goflow2 decoded v4 + v6 flows)"
