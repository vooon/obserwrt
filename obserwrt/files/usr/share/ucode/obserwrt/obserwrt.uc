/*
 * obserwrt - procd entry (obserwrt.uc)
 *
 * Loads the eBPF module (flow.uc), reconciles configured devices via netifd
 * (reconcile.uc), and runs the main loop: attach/detach on network.device
 * events + an infrequent status snapshot, and periodic flow reporting.
 */

"use strict";

import { connect } from 'ubus';
import { init as uloop_init, run as uloop_run, interval } from 'uloop';
import { ulog_open, ulog, WARN, ERR, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG } from 'log';
import { load_bpf } from './flow.uc';
import { snapshot, on_device_event, attached_names } from './reconcile.uc';
import { run as lifecycle_pass } from './lifecycle.uc';
import { init as metrics_init, observe as metrics_observe, record_error as metrics_error, set_state as metrics_state, write as metrics_write, interval as metrics_interval } from './metrics.uc';
import { init as ipfix_init, emit as ipfix_emit, flush as ipfix_flush } from './exporter_ipfix.uc';
import { init as syslog_init, emit as syslog_emit } from './exporter_syslog.uc';

const SNAP_S = 5;       /* counter snapshot interval (seconds) */
const RECONCIL_S = 30;  /* slow safety device reconcile interval (seconds) */

let ipfix_active = false;
let syslog_active = false;

ulog_open(ULOG_SYSLOG, LOG_DAEMON, "obserwrt");

/* Dispatches one normalized observation to all configured exporters and folds
 * it into the Prometheus aggregates. `delta` is the per-export interval growth
 * supplied by lifecycle.uc. */
function emit_flow(k, v, expired, delta)
{
	metrics_observe(k, v, expired);

	if (syslog_active)
		syslog_emit(k, v, expired, delta);

	if (ipfix_active)
		ipfix_emit(k, v, expired, delta);
}

function main()
{
	uloop_init();

	load_bpf();

	ipfix_active = ipfix_init();
	syslog_active = syslog_init();
	if (!ipfix_active && !syslog_active)
		WARN('no exporters enabled; observations will not be exported');

	if (metrics_init()) {
		/* Self-observability runs on its own cadence, independent of the 5s
		 * lifecycle flush. */
		metrics_write();
		interval(metrics_interval() * 1000, function () {
			try {
				metrics_write();
			}
			catch (e) {
				metrics_error();
				WARN('metrics: %s', e);
			}
		});
	}

	let ubus = connect();
	if (!ubus)
		die('ubus connect failed');

	let sub = ubus.subscriber(on_device_event, null, []);
	sub.subscribe('network.device');

	try {
		snapshot(ubus);
	}
	catch (e) {
		WARN('initial snapshot: %s', e);
	}

	/* Slow safety reconcile only (design §6.4): netifd `status` for every device
	 * is expensive - polling it per-second hammers netifd. Devices attach/detach
	 * responsively via network.device events; this is a periodic safety net. */
	interval(RECONCIL_S * 1000, function () {
		try {
			snapshot(ubus);
		}
		catch (e) {
			WARN('snapshot: %s', e);
		}
	});

	interval(SNAP_S * 1000, function () {
		try {
			let n = lifecycle_pass(emit_flow);
			if (n.active == 0 && n.expired == 0)
				ulog(LOG_DEBUG, 'snapshot: no counters observed yet');
			if (ipfix_active)
				ipfix_flush();
			metrics_state(n, attached_names());
		}
		catch (e) {
			metrics_error();
			WARN('lifecycle: %s', e);
		}
	});

	uloop_run();   /* block forever on the uloop event loop */
}

try {
	main();
}
catch (e) {
	ERR('fatal: %s', e);
	exit(1);
}
