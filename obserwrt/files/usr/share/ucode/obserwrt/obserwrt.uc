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
import { snapshot, on_device_event, export_flow } from './reconcile.uc';
import { run as lifecycle_pass } from './lifecycle.uc';
import { init as ipfix_init, emit as ipfix_emit, flush as ipfix_flush } from './exporter_ipfix.uc';

const SNAP_S = 5;       /* counter snapshot interval (seconds) */
const RECONCIL_S = 30;  /* slow safety device reconcile interval (seconds) */

let ipfix_active = false;

ulog_open(ULOG_SYSLOG, LOG_DAEMON, "obserwrt");

/* Dispatches one flow to all exporters (debug log + IPFIX). */
function emit_flow(k, v, expired)
{
	export_flow(k, v, expired);

	if (ipfix_active)
		ipfix_emit(k, v, expired);
}

function main()
{
	uloop_init();

	load_bpf();

	ipfix_active = ipfix_init();

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
		}
		catch (e) {
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