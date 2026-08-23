/*
 * obserwrt - Prometheus self-observability (metrics.uc)
 *
 * Publishes aggregate counters/gauges via the node-exporter textfile collector
 * (no HTTP server, no per-flow labels). Enabled only when the `main` UCI option
 * `prometheus_textfile` is set to the output path (e.g.
 * /run/prometheus/textfile/obserwrt.prom). The file is rewritten atomically
 * (temp + rename) on each export cycle.
 *
 * `packets`/`bytes` are cumulative counters accumulated from per-flow deltas,
 * so a long-lived flow is counted exactly once even though it is re-exported
 * every pass.
 */
"use strict";

import { cursor } from 'uci';
import { writefile, rename, error as fs_error } from 'fs';
import { WARN } from 'log';
import { parse_uint } from './util.uc';

let active = false;
let file = '';
let interval_s = 20;         /* seconds between file writes (dedicated timer) */
let total_packets = 0;
let total_bytes = 0;
let total_flows = 0;
let total_errors = 0;
let flows_active = 0;
let map_entries = 0;
let devices = 0;
let seen = {};           /* flow-key fingerprint -> { p, b } for deltas */

function flow_key(k)
{
	return sprintf('%d|%d|%d|%d|%d|%s|%s|%d|%d',
		k.ifindex, k.direction, k.family, k.protocol, k.icmp_type,
		hexenc(k.src), hexenc(k.dst), k.sport, k.dport);
};

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

/* Write cadence in seconds, for the caller to schedule a uloop interval. */
export function interval()
{
	return interval_s;
};

/* Include one exported flow in the aggregate totals. */
export function observe(k, v, expired)
{
	if (!active)
		return;

	let fk = flow_key(k);
	let prev = seen[fk];
	let dp = v.packets, db = v.bytes;

	if (prev !== null) {
		dp -= prev.p;
		db -= prev.b;
	}

	if (dp > 0)
		total_packets += dp;
	if (db > 0)
		total_bytes += db;

	seen[fk] = { p: v.packets, b: v.bytes };
	if (expired)
		delete seen[fk];

	total_flows++;
};

export function record_error()
{
	if (active)
		total_errors++;
};

export function set_gauges(active_flows, map, n_devices)
{
	if (!active)
		return;

	flows_active = active_flows;
	map_entries = map;
	devices = n_devices;
};

/* Write the textfile-collector snapshot atomically. Called from a dedicated
 * uloop timer at `interval()` seconds. A missing/unwritable target (e.g. the
 * textfile dir not yet created) is not fatal: it logs a warning and is retried
 * on the next timer tick, so a later directory creation takes effect. */
export function write()
{
	if (!active)
		return;

	let body =
		'# HELP obserwrt_packets_total Observed packets (cumulative).\n' +
		'# TYPE obserwrt_packets_total counter\n' +
		sprintf('obserwrt_packets_total %d\n', total_packets) +
		'# HELP obserwrt_bytes_total Observed bytes (cumulative).\n' +
		'# TYPE obserwrt_bytes_total counter\n' +
		sprintf('obserwrt_bytes_total %d\n', total_bytes) +
		'# HELP obserwrt_flows_exported_total Flow records dispatched to exporters.\n' +
		'# TYPE obserwrt_flows_exported_total counter\n' +
		sprintf('obserwrt_flows_exported_total %d\n', total_flows) +
		'# HELP obserwrt_export_errors_total Export/lifecycle failures.\n' +
		'# TYPE obserwrt_export_errors_total counter\n' +
		sprintf('obserwrt_export_errors_total %d\n', total_errors) +
		'# HELP obserwrt_flows_active Currently live flows.\n' +
		'# TYPE obserwrt_flows_active gauge\n' +
		sprintf('obserwrt_flows_active %d\n', flows_active) +
		'# HELP obserwrt_bpf_map_entries Flow map entry count.\n' +
		'# TYPE obserwrt_bpf_map_entries gauge\n' +
		sprintf('obserwrt_bpf_map_entries %d\n', map_entries) +
		'# HELP obserwrt_devices_attached Number of attached netdevs.\n' +
		'# TYPE obserwrt_devices_attached gauge\n' +
		sprintf('obserwrt_devices_attached %d\n', devices);

	let tmp = file + '.tmp';

	if (writefile(tmp, body) === null) {
		WARN('metrics: cannot write %s: %s', file, fs_error());
		return;
	}

	if (rename(tmp, file) === null)
		WARN('metrics: cannot rename %s: %s', tmp, fs_error());
};
