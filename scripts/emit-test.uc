/*
 * obserwrt - emit a couple of known flows to a collector (test harness).
 *
 * Used by scripts/test-ipfix.sh to validate the IPFIX exporter end-to-end with
 * goflow2 (or any IPFIX collector). Sends one IPv4 TCP and one IPv6 UDP flow
 * with fixed, checkable fields.
 *
 * Imports are relative - scripts/test-ipfix.sh copies this file together with
 * the obserwrt modules into a scratch dir and runs ucode there.
 *
 * Environment:
 *   COLLECTOR_HOST (default 127.0.0.1)
 *   COLLECTOR_PORT (default 4739)
 */
"use strict";

import { connect, emit, flush } from './exporter_ipfix.uc';
import { INGRESS } from './flow.uc';

const HOST = getenv('COLLECTOR_HOST') || '127.0.0.1';
const PORT = getenv('COLLECTOR_PORT') || '4739';
const NOW_NS = clock(true)[0] * 1000000000 + clock(true)[1];

function v4in6(a, b, c, d)
{
	/* ::ffff:a.b.c.d */
	return chr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d);
}

if (!connect(HOST, PORT, null))
	die('exporter connect failed');

/* IPv4 TCP, egress (direction=1), ifindex 29, src 192.0.2.1 -> dst 198.51.100.2 */
emit(
	{
		ifindex:   29,
		direction: 1,
		family:    4,
		protocol:  6,
		src:       v4in6(192, 0, 2, 1),
		dst:       v4in6(198, 51, 100, 2),
		sport:     12345,
		dport:     80,
		icmp_type: 0,
		icmp_code: 0,
	},
	{
		packets:    10,
		bytes:      12340,
		first_seen: NOW_NS - 5000000000,
		last_seen:  NOW_NS,
		tcp_flags:  0x18,
	},
	false);

/* IPv6 UDP, ingress (direction=0), ifindex 30, src 2001:db8::1 -> 2001:db8::2 */
const ip6_1 = '\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01';
const ip6_2 = '\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02';

emit(
	{
		ifindex:   30,
		direction: INGRESS,
		family:    6,
		protocol:  17,
		src:       ip6_1,
		dst:       ip6_2,
		sport:     53,
		dport:     443,
		icmp_type: 0,
		icmp_code: 0,
	},
	{
		packets:    2,
		bytes:      200,
		first_seen: NOW_NS - 2000000000,
		last_seen:  NOW_NS,
		tcp_flags:  0,
	},
	false);

flush();
printf('emit-test: sent to %s:%s\n', HOST, PORT);