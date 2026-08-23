/*
 * obserwrt - procd entry (obserwrt.uc)
 *
 * Loads the eBPF module (flow.uc), reconciles configured devices via netifd
 * (reconcile.uc), and runs the main loop: attach/detach on network.device
 * events + an infrequent status snapshot, and periodic flow reporting.
 */

"use strict";

import { connect } from 'ubus';
import { ulog_open, ulog, WARN, ERR, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG } from 'log';
import { load_bpf } from './flow.uc';
import { snapshot, on_device_event, export_flow } from './reconcile.uc';
import { run } from './lifecycle.uc';

const SNAP_S = 5;       /* counter snapshot interval (seconds) */
const RECONCIL_S = 30;  /* slow safety device reconcile interval (seconds) */

ulog_open(ULOG_SYSLOG, LOG_DAEMON, "obserwrt");

function main()
{
	load_bpf();

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

	let last = time();
	let last_reconcil = time();
	for (;;) {
		sleep(1);
		let now = time();

		/* Slow safety reconcile only (design §6.4): netifd `status` for every
		 * device is expensive - polling it per-second hammers netifd. Devices
		 * are attached/detached responsively via network.device events instead. */
		if (now - last_reconcil >= RECONCIL_S) {
			try {
				snapshot(ubus);
			}
			catch (e) {
				WARN('snapshot: %s', e);
			}
			last_reconcil = now;
		}

		if (now - last >= SNAP_S) {
			try {
				let n = run(export_flow);
				if (n.active == 0 && n.expired == 0)
					ulog(LOG_DEBUG, 'snapshot: no counters observed yet');
			}
			catch (e) {
				WARN('lifecycle: %s', e);
			}
			last = now;
		}
	}
}

try {
	main();
}
catch (e) {
	ERR('fatal: %s', e);
	exit(1);
}