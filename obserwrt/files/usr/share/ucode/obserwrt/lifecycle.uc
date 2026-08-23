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
import { flows, parse_key, parse_value } from './flow.uc';

const INACTIVE_S = 10;   /* expire/delete a flow idle longer than this */
const ACTIVE_S   = 60;   /* active timeout: long-lived flows are re-exported
                          * every pass (no extra state needed for v1) */

export const timeouts = { inactive: INACTIVE_S, active: ACTIVE_S };

/* monotonic "now" in nanoseconds - same clock as bpf_ktime_get_ns() */
const now_ns = function()
{
	let c = clock(true);

	return c[0] * 1000000000 + c[1];
};

/* One lifecycle pass. `exporter(k, v, expired)` receives the parsed flow key
 * and value objects. Returns { active, expired } counts. Flows idle longer than
 * INACTIVE_S are exported as expired and deleted from the map. */
export const run = function(exporter)
{
	let now = now_ns();
	let n = { active: 0, expired: 0 };

	flows().foreach(function (key) {
		let k = parse_key(key);
		let v = parse_value(flows().get(key));
		let age_s = (now - v.last_seen) / 1000000000.0;

		if (age_s > INACTIVE_S) {
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