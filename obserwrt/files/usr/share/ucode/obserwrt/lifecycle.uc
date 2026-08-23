/*
 * obserwrt - flow lifecycle (lifecycle.uc)
 *
 * Periodically walks the flow map, hands each flow to an exporter callback and
 * deletes flows that have been idle for more than the inactive timeout. This
 * bounds the map (alongside the LRU) and produces completed flow records for the
 * exporters (debug now, IPFIX later).
 *
 * Timestamps: the BPF value stores `last_seen` from bpf_ktime_get_ns(), which is
 * CLOCK_MONOTONIC. ucode's clock(true) reads the same clock, so ages are
 * comparable directly.
 */

"use strict";

import { flows, parse_key, parse_value } from './flow.uc';
import { cursor } from 'uci';

/* Flow expiry/active timeouts (seconds), configurable via the `main` UCI
 * section (`inactive_timeout` / `active_timeout`). */
let inactive_s = 10;
let active_s   = 60;

function load_timeouts()
{
	try {
		const ctx = cursor();
		let v = ctx.get('obserwrt', 'main', 'inactive_timeout');

		if (v !== null && match(v, /^[0-9]+$/))
			inactive_s = int(v);

		let a = ctx.get('obserwrt', 'main', 'active_timeout');

		if (a !== null && match(a, /^[0-9]+$/))
			active_s = int(a);
	}
	catch (e) {
		/* no/malformed config - keep defaults */
	}
}
load_timeouts();

/* monotonic "now" in nanoseconds - same clock as bpf_ktime_get_ns() */
function now_ns()
{
	let c = clock(true);

	return c[0] * 1000000000 + c[1];
};

/* One lifecycle pass. `exporter(k, v, expired)` receives the parsed flow key
 * and value objects. Returns { active, expired } counts. Flows idle longer than
 * inactive_s are exported as expired and deleted from the map. */
export function run(exporter)
{
	let now = now_ns();
	let n = { active: 0, expired: 0 };

	flows().foreach(function (key) {
		let k = parse_key(key);
		let v = parse_value(flows().get(key));
		let age_s = (now - v.last_seen) / 1000000000.0;

		if (age_s > inactive_s) {
			exporter(k, v, true);
			flows().delete(key);
			n.expired++;
		}
		else {
			exporter(k, v, false);
			n.active++;
		}
	});

	return n;
};