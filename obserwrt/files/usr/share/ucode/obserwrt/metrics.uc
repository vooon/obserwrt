/*
 * obserwrt - Prometheus self-observability (metrics.uc)
 *
 * Publishes aggregate gauges/counters via the node-exporter textfile collector
 * (no HTTP server; labels are per-device, never per-flow). Enabled only when the
 * `main` UCI option `prometheus_textfile` is set to the output path. The file
 * is rewritten atomically (temp + rename) by a dedicated uloop timer at
 * `interval()` seconds.
 *
 * The metric formatting below (counter()/gauge(), label escaping, govalue,
 * decl-gating) is adapted from OpenWrt's prometheus-node-exporter-ucode
 * (metrics.uc), licensed Apache-2.0; attribution is retained per that license.
 * The original emits over HTTP (uhttpd.send); here `puts` accumulates into a
 * string that is written to the textfile collector instead.
 *
 * The flow map is an LRU hash, so at capacity it evicts rather than failing;
 * saturation is surfaced as (current entries, capacity) so utilization can be
 * watched/alarmed on.
 */
"use strict";

import { cursor } from 'uci';
import { writefile, rename, error as fs_error } from 'fs';
import { WARN } from 'log';
import { parse_uint } from './util.uc';
import { bpf_stats } from './flow.uc';

/* Must match obserwrt_flows max_entries in bpf.c (FLOW_MAP_ENTRIES). The package
 * Makefile rewrites this line to the configured value at install time. */
const BPF_MAP_LIMIT = 4096;

let active = false;
let file = '';
let interval_s = 20;
let out = '';            /* accumulator for the current textfile snapshot */
let total_flows = 0;
let total_errors = 0;
let flows_active = 0;
let map_entries = 0;
let devices = [];

/* ---- node-exporter metric formatting (adapted) ---------------------- */

function debug(...s) { /* unused in textfile mode */ }

function puts(...s) { out += join('', s) + '\n'; }

function govalue(value) {
	if (value == Infinity)
		return "+Inf";
	else if (value == -Infinity)
		return "-Inf";
	else if (value != value)
		return "NaN";
	else if (type(value) in [ "int", "double" ])
		return value;
	else if (type(value) in [ "bool", "string" ])
		return +value;

	return null;
}

function metric(name, mtype, help, skipdecl) {
	let func;
	let decl = skipdecl == true ? false : true;

	let yld = function(labels, value) {
		let v = govalue(value);

		if (v == null) {
			debug(`skipping metric: unsupported value '${value}' (${name})`);
			return func;
		}

		let labels_str = "";
		if (length(labels)) {
			let sep = "";
			let s;
			labels_str = "{";
			for (let l in labels) {
				if (labels[l] == null)
					s = "";
				else if (type(labels[l]) == "string") {
					s = replace(labels[l], "\\", "\\\\");
					s = replace(s, "\"", "\\\"");
					s = replace(s, "\n", "\\n");
				} else {
					s = govalue(labels[l]);

					if (!s)
						continue;
				}

				labels_str += sep + l + "=\"" + s + "\"";
				sep = ",";
			}
			labels_str += "}";
		}

		if (decl) {
			if (help)
				puts("# HELP ", name, " ", help);
			puts("# TYPE ", name, " ", mtype);
			decl = false;
		}

		puts(name, labels_str, " ", v);
		return func;
	};

	func = yld;
	return func;
}

function counter(name, help, skipdecl) { return metric(name, "counter", help, skipdecl); }

function gauge(name, help, skipdecl) { return metric(name, "gauge", help, skipdecl); }

/* ---- config --------------------------------------------------------- */

/* Read the output path and write interval from the `main` section. Returns true
 * when enabled. */
export function init()
{
	let ctx = cursor();
	file = ctx.get('obserwrt', 'main', 'prometheus_textfile') || '';
	interval_s = parse_uint(ctx.get('obserwrt', 'main', 'prometheus_interval'), 20, 86400, 'prometheus_interval');

	active = (file != '');
	return active;
};

/* Records one dispatched flow (cheap dispatch counter; per-flow args are
 * retained only for call-site symmetry). */
export function observe(k, v, expired)
{
	if (active)
		total_flows++;
};

export function record_error()
{
	if (active)
		total_errors++;
};

/* Set the gauges from one lifecycle pass. `n` carries { active, map, packets,
 * bytes }; `devs` is the list of currently attached netdev names. */
export function set_state(n, devs)
{
	if (!active)
		return;

	flows_active = n.active;
	map_entries = n.map;

	devices = [];
	for (let d in devs)
		push(devices, d);
};

/* Write cadence in seconds, for the caller to schedule a uloop interval. */
export function interval()
{
	return interval_s;
};

/* Write the textfile-collector snapshot atomically. Called from a dedicated
 * uloop timer at `interval()` seconds. A missing/unwritable target is not
 * fatal: it logs a warning and is retried on the next tick, so a later
 * directory creation takes effect. */
export function write()
{
	if (!active)
		return;

	let st = bpf_stats();

	out = '';

	counter('obserwrt_flows_exported_total', 'Flow records dispatched to exporters.')({}, total_flows);
	counter('obserwrt_export_errors_total', 'Export/lifecycle failures.')({}, total_errors);
	counter('obserwrt_packets_total', 'Packets seen at TC (all, incl. non-IP).')({}, st.packets);
	counter('obserwrt_bytes_total', 'Bytes seen at TC (all).')({}, st.bytes);
	counter('obserwrt_packets_accounted_total', 'Packets that entered flow accounting (IP).')({}, st.parsed);
	counter('obserwrt_flows_created_total', 'Flow entries created in the BPF map.')({}, st.flows_created);
	gauge('obserwrt_flows_active', 'Currently live flows.')({}, flows_active);
	gauge('obserwrt_bpf_map_entries', 'Current flow map entries.')({}, map_entries);
	gauge('obserwrt_bpf_map_limit', 'Flow map capacity (LRU).')({}, BPF_MAP_LIMIT);
	gauge('obserwrt_devices_attached', 'Number of attached netdevs.')({}, length(devices));

	let dev = gauge('obserwrt_device_attached', 'Attached netdev (1 if attached).');

	for (let d in devices)
		dev({ ifname: d }, 1);

	let tmp = file + '.tmp';

	if (writefile(tmp, out) === null) {
		WARN('metrics: cannot write %s: %s', file, fs_error());
		return;
	}

	if (rename(tmp, file) === null)
		WARN('metrics: cannot rename %s: %s', tmp, fs_error());
};