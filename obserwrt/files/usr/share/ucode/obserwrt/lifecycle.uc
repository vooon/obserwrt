/*
 * obserwrt - flow lifecycle (lifecycle.uc)
 *
 * Periodically walks the flow map, hands each flow to an exporter callback with
 * a *delta* since the last export (active-flow delta accounting), and deletes
 * flows idle longer than their per-protocol timeout. This bounds the map
 * (alongside the LRU) and produces completed flow records for the exporters.
 *
 * Delta accounting: the BPF value holds cumulative packet/byte counters for a
 * flow. Handed to the exporter is only the growth since the last export (the
 * sum of deltas over a flow's lifetime equals its total), so the collector is
 * not double-counted. A pass is O(map size) in userspace, so on a slow (MIPS)
 * host re-exporting *every* live flow every tick wastes CPU and sends zero-value
 * records; flows with no new traffic since the last pass are therefore not
 * re-emitted (their delta is zero anyway). The tracker is keyed by the hex of
 * the raw map key - ucode object keys cannot hold NUL bytes, and the 46-byte
 * raw key is mostly zeroes - and pruned each pass so LRU-evicted flows do not
 * leak state.
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
let last = {};   /* flow key hex -> { p, b, t } last-exported counters/last_seen */

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

/* Tracker identity: hex of the raw map key. The 46-byte key is mostly zero
 * bytes (and ucode object keys cannot hold NULs), so the raw string cannot be
 * an object key; hexenc is a single allocation vs. the old sprintf of every
 * key field. */
function track_key(key)
{
	return hexenc(key);
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
		let raw = flows().get(key);

		/* The key may have been LRU-evicted between iteration and the read. */
		if (raw === null)
			return;

		let v = parse_value(raw);
		let fk = track_key(key);
		let age_s = (now - v.last_seen) / 1000000000.0;
		let prev = last[fk];
		let p0 = prev ? prev.p : 0;
		let b0 = prev ? prev.b : 0;
		let dp = v.packets - p0, db = v.bytes - b0;

		if (dp < 0) dp = v.packets;
		if (db < 0) db = v.bytes;

		/* Re-export only when something changed since the last pass (new flow,
		 * or counters/last_seen advanced). A flow with no new traffic has a
		 * zero delta, so emitting it is pure waste - on a full map that is the
		 * bulk of the per-pass work. */
		let changed = !prev || v.last_seen != prev.t ||
			v.packets != prev.p || v.bytes != prev.b;

		seen[fk] = true;
		last[fk] = { p: v.packets, b: v.bytes, t: v.last_seen };

		if (age_s > proto_timeout(k.protocol)) {
			exporter(k, v, true, { packets: dp, bytes: db });
			delete last[fk];
			flows().delete(key);
			n.expired++;
		}
		else {
			n.active++;
			if (changed)
				exporter(k, v, false, { packets: dp, bytes: db });
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