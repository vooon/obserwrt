/*
 * obserwrt - IPFIX exporter (exporter.uc)
 *
 * Encodes the normalized flow observations as IPFIX (RFC 7011) over UDP and
 * sends them to a collector. Serialization uses big-endian ('!') struct formats.
 *
 * Two templates are used, branching on family:
 *   - IPv4 (mapped ::ffff:*) -> sourceIPv4Address/destinationIPv4Address
 *   - IPv6 -> sourceIPv6Address/destinationIPv6Address
 *
 * Data is batched into datagrams sized below MAX_UDP and flushed periodically;
 * templates are retransmitted every TEMPLATE_INTERVAL_S. Sequence number counts
 * data records per observation domain.
 *
 * The collector destination is an IP[:port] for now; hostname resolution is a
 * follow-up (see docs/design.md §8.1).
 */
"use strict";

import * as socket from 'socket';
import * as struct from 'struct';
import { cursor } from 'uci';
import { WARN, INFO } from 'log';
import { INGRESS, EGRESS } from './flow.uc';
import { bool_option } from './util.uc';

const VERSION   = 10;
const SET_TEMPLATE = 2;
const IPV4_TID = 256;
const IPV6_TID = 257;

const MAX_UDP           = 1200;        /* avoid IP fragmentation on normal MTU */
const TEMPLATE_INTERVAL_S = 60;
const OBS_DOMAIN        = 1;           /* per-router; TODO make configurable */

/* Data record formats, big-endian:
 * addr(4|16),addr,sport,dport,proto,packets,bytes,flowStart,flowEnd,tcp,ingr,egr */
const FMT_V4 = '!4s4sHHBQQQQHII';
const FMT_V6 = '!16s16sHHBQQQQHII';

/* Template field lists: [ieId, length] */
const FIELDS_V4 = [
	[  8, 4],  /* sourceIPv4Address */
	[ 12, 4],  /* destinationIPv4Address */
	[  7, 2],  /* sourceTransportPort */
	[ 11, 2],  /* destinationTransportPort */
	[  4, 1],  /* protocolIdentifier */
	[  2, 8],  /* packetDeltaCount */
	[  1, 8],  /* octetDeltaCount */
	[150, 8],  /* flowStartMilliseconds */
	[151, 8],  /* flowEndMilliseconds */
	[  6, 2],  /* tcpControlBits */
	[ 10, 4],  /* ingressInterface */
	[ 14, 4],  /* egressInterface */
];
const FIELDS_V6 = [
	[ 27, 16], /* sourceIPv6Address */
	[ 28, 16], /* destinationIPv6Address */
	[  7,  2],
	[ 11,  2],
	[  4,  1],
	[  2,  8],
	[  1,  8],
	[150,  8],
	[151,  8],
	[  6,  2],
	[ 10,  4],
	[ 14,  4],
];

let sock = null;
let dest = null;              /* "ip:port" */
let offset_ms = 0;            /* monotonic -> epoch conversion */
let seq = 0;
let pending4 = [];            /* raw v4 record byte strings */
let pending6 = [];            /* raw v6 record byte strings */
let last_template_sent = 0;

/* monotonic "now" in ms (CLOCK_MONOTONIC, same as bpf_ktime_get_ns) */
function mono_ms()
{
	let c = clock(true);

	return c[0] * 1000 + int(c[1] / 1000000);
}

/* ---- wire building --------------------------------------------------- */

function msg_header(msg_len)
{
	return struct.pack('!HHIII', VERSION, msg_len, time(), seq, OBS_DOMAIN);
}

function template_set(tid, fields)
{
	let rec = struct.pack('!HH', tid, length(fields));

	for (let i = 0; i < length(fields); i++)
		rec += struct.pack('!HH', fields[i][0], fields[i][1]);

	return struct.pack('!HH', SET_TEMPLATE, 4 + length(rec)) + rec;
}

/* Send one set as one datagram (single data set per datagram). */
function emit_set(set_id, body, cnt)
{
	sock.send(msg_header(16 + length(body)) + struct.pack('!HH', set_id, 4 + length(body)) + body, 0, dest);
	seq += cnt;
}

/* Pack the given raw records into one or more datagrams, each <= MAX_UDP. */
function flush_set(set_id, records)
{
	let body = '';
	let cnt = 0;

	for (let i = 0; i < length(records); i++) {
		let r = records[i];

		if (cnt > 0 && 16 + 4 + length(body) + length(r) > MAX_UDP) {
			emit_set(set_id, body, cnt);
			body = '';
			cnt = 0;
		}
		body += r;
		cnt++;
	}

	if (cnt > 0)
		emit_set(set_id, body, cnt);
}

/* Send both templates; call at init and then every TEMPLATE_INTERVAL_S. */
function send_templates()
{
	let body = template_set(IPV4_TID, FIELDS_V4) + template_set(IPV6_TID, FIELDS_V6);

	sock.send(msg_header(16 + length(body)) + body, 0, dest);
	last_template_sent = time();
	INFO('ipfix: templates sent (domain %d)', OBS_DOMAIN);
}

/* Flush buffered data records (and templates when their retransmit interval
 * is due). Called by the entry after each lifecycle pass. */
export function flush()
{
	if (time() - last_template_sent >= TEMPLATE_INTERVAL_S)
		send_templates();

	flush_set(IPV4_TID, pending4);
	flush_set(IPV6_TID, pending6);
	pending4 = [];
	pending6 = [];
};

/* Encode and buffer one flow observation. `k`/`v` are parsed from flow.uc. */
export function emit(k, v, expired)
{
	let rec;

	if (k.family == 4) {
		rec = struct.pack(FMT_V4,
			substr(k.src, 12, 4), substr(k.dst, 12, 4),
			k.sport, k.dport, k.protocol,
			v.packets, v.bytes,
			offset_ms + int(v.first_seen / 1000000),
			offset_ms + int(v.last_seen / 1000000),
			v.tcp_flags,
			(k.direction == INGRESS) ? k.ifindex : 0,
			(k.direction == EGRESS)  ? k.ifindex : 0);
		push(pending4, rec);
	}
	else {
		rec = struct.pack(FMT_V6,
			k.src, k.dst,
			k.sport, k.dport, k.protocol,
			v.packets, v.bytes,
			offset_ms + int(v.first_seen / 1000000),
			offset_ms + int(v.last_seen / 1000000),
			v.tcp_flags,
			(k.direction == INGRESS) ? k.ifindex : 0,
			(k.direction == EGRESS)  ? k.ifindex : 0);
		push(pending6, rec);
	}
};

/* Open the UDP socket to a collector and start exporting from this call-hour
 * offset. `host:port` is the collector address; `source_addr` optionally pins
 * the local source IP. Returns true on success. Reusable (e.g. by tests). */
export function connect(host, port, source_addr)
{
	offset_ms = time() * 1000 - mono_ms();
	dest = host + ':' + port;
	sock = socket.create(socket.AF_INET, socket.SOCK_DGRAM, 0);

	if (!sock) {
		WARN('ipfix: socket create failed');
		return false;
	}

	if (source_addr && !sock.bind(source_addr + ':0'))
		WARN('ipfix: bind source %s failed (%s)', source_addr, socket.error());

	send_templates();
	return true;
};

/* Initialise the exporter from the exporter_ipfix UCI section. */
export function init()
{
	let host = null, port = '4739', source_addr = null;

	try {
		const ctx = cursor();
		let enabled = ctx.get('obserwrt', 'ipfix', 'enabled');

		if (!bool_option(enabled, false))
			return false;

		host = ctx.get('obserwrt', 'ipfix', 'collector_host');
		source_addr = ctx.get('obserwrt', 'ipfix', 'source_address');

		let p = ctx.get('obserwrt', 'ipfix', 'collector_port');
		if (p)
			port = p;
	}
	catch (e) {
		return false;
	}

	if (!host) {
		WARN('ipfix: no collector_host configured');
		return false;
	}

	return connect(host, port, source_addr);
};
