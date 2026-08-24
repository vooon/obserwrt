/*
 * obserwrt - flow lifecycle (lifecycle.uc)
 *
 * Periodically walks the flow map, hands each flow to an exporter callback with
 * a *delta* since the last export (active-flow delta accounting), and deletes
 * flows idle longer than their per-protocol timeout. This bounds the map
 * (alongside the LRU) and produces completed flow records for the exporters.
 *
 * Delta accounting: the BPF value holds cumulative packet/byte counters for a
 * flow. Active flows are re-exported on every pass; without deltas that would
 * double-count on the collector. We track the last-exported counters per flow
 * key and hand the exporter only the growth since then, so the sum of deltas
 * over a flow's lifetime equals its total. The tracker is pruned each pass so
 * LRU-evicted flows do not leak state.
 *
 * Timestamps: the BPF value stores `last_seen` from bpf_ktime_get_ns(), which is
 * CLOCK_MONOTONIC. ucode's clock(true) reads the same clock, so ages are
 * comparable directly.
 */

"use strict";

import { flows, parse_key, parse_value } from './flow.uc';
import { cursor } from 'uci';

/* Per-protocol idle timeouts (seconds), configurable via the `main` UCI
 * section (tcp_timeout / udp_timeout / icmp_timeout / general_timeout), plus the
 * (informational) active_timeout. */
let timeout = { tcp: 300, udp: 60, icmp: 30, general: 10 };
let last = {};   /* flow fingerprint -> { p, b } last-exported counters */

function load_timeouts()
{
	try {
		const ctx = cursor();
		let m = [
			[ 'tcp_timeout',      'tcp' ],
			[ 'udp_timeout',      'udp' ],
			[ 'icmp_timeout',     'icmp' ],
			[ 'general_timeout',  'general' ],
		];

		for (let item in m) {
			let v = ctx.get('obserwrt', 'main', item[0]);

			if (v !== null && match(v, /^[0-9]+$/))
				timeout[item[1]] = int(v);
		}
	}
	catch (e) {
		/* no/malformed config - keep defaults */
	}
}
load_timeouts();

/* Stable identity for the delta tracker (mirrors the flow key fields). */
function flow_key(k)
{
	return sprintf('%d|%d|%d|%d|%s|%s|%d|%d|%d|%d',
		k.ifindex, k.direction, k.family, k.protocol,
		hexenc(k.src), hexenc(k.dst), k.sport, k.dport,
		k.icmp_type, k.icmp_code);
}

function proto_timeout(proto)
{
	if (proto == 6)
		return timeout.tcp;
	if (proto == 17)
		return timeout.udp;
	if (proto == 1 || proto == 58)
		return timeout.icmp;

	return timeout.general;
};

/* monotonic "now" in nanoseconds - same clock as bpf_ktime_get_ns() */
function now_ns()
{
	let c = clock(true);

	return c[0] * 1000000000 + c[1];
};

/* One lifecycle pass. `exporter(k, v, expired, delta)` receives the parsed key
 * and value objects plus the delta since the last export. Returns
 * { active, expired, map }. */
export function run(exporter)
{
	let now = now_ns();
	let n = { active: 0, expired: 0, map: 0 };
	let seen = {};

	flows().foreach(function (key) {
		let k = parse_key(key);
		let v = parse_value(flows().get(key));
		let fk = flow_key(k);
		let age_s = (now - v.last_seen) / 1000000000.0;
		let p0 = last[fk] ? last[fk].p : 0;
		let b0 = last[fk] ? last[fk].b : 0;
		let dp = v.packets - p0, db = v.bytes - b0;

		if (dp < 0) dp = v.packets;
		if (db < 0) db = v.bytes;

		seen[fk] = true;
		last[fk] = { p: v.packets, b: v.bytes };

		if (age_s > proto_timeout(k.protocol)) {
			exporter(k, v, true, { packets: dp, bytes: db });
			delete last[fk];
			flows().delete(key);
			n.expired++;
		}
		else {
			exporter(k, v, false, { packets: dp, bytes: db });
			n.active++;
		}

		n.map++;
	});

	/* Drop tracker entries for flows no longer in the map (LRU-evicted or
	 * expired) so the tracker does not grow without bound. */
	for (let fk in last)
		if (!seen[fk])
			delete last[fk];

	return n;
};