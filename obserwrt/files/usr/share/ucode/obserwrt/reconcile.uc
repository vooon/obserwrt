/*
 * obserwrt - device reconciliation + flow reporting (reconcile.uc)
 *
 * Attaches/detaches the TC programs on the configured netdevs via netifd
 * (`network.device` events + an infrequent startup/safety status snapshot),
 * and reports the flow map. Imported by obserwrt.uc.
 */

"use strict";

import { cursor } from 'uci';
import { readfile } from 'fs';
import { INFO, NOTE, WARN } from 'log';
import { attach, detach, purge_device, DIR } from './flow.uc';

const PRIO = 10;      /* tc filter priority */

let device_pats = [];
let attached = {};          /* attached[name] = { ifindex } */
let name_by_index = {};     /* ifindex -> netdev name (debug output) */

function load_devices()
{
	let pats = [];
	try {
		const ctx = cursor();
		let v = ctx.get('obserwrt', 'main', 'device');
		if (v === null)
			return pats;
		if (type(v) == 'array') {
			/* ucode: `for..in` over arrays yields elements, not indices */
			for (let i = 0; i < length(v); i++)
				push(pats, sprintf('%s', v[i]));
		}
		else {
			push(pats, sprintf('%s', v));
		}
	}
	catch (e) {
		/* config missing/empty: fall through to empty device set */
	}
	return pats;
};
device_pats = load_devices();

/* matches a netdev name against the configured patterns (fnmatch wildcard) */
function glob_match(name)
{
	for (let i = 0; i < length(device_pats); i++) {
		if (wildcard(name, device_pats[i]))
			return true;
	}
	return false;
};

/* Real kernel ifIndex via sysfs; netifd's network.device status does not
 * expose it. Returns 0 if the netdev is absent. */
function ifindex_of(name)
{
	let v = readfile('/sys/class/net/' + name + '/ifindex');

	return (v === null) ? 0 : int(v);
};

function attach_device(name, ifindex)
{
	if (attached[name]) {
		if (ifindex)
			attached[name].ifindex = ifindex;
		return;
	}

	let e;

	if ((e = attach(name, DIR.INGRESS, PRIO)))
		WARN('ingress attach %s: %s', name, e);
	if ((e = attach(name, DIR.EGRESS, PRIO)))
		WARN('egress attach %s: %s', name, e);

	attached[name] = { ifindex: ifindex || ifindex_of(name) };
	NOTE('attached %s (ifindex %d)', name, attached[name].ifindex);
};

function detach_device(name, ifindex)
{
	if (!attached[name])
		return;

	detach(name, DIR.INGRESS, PRIO);
	detach(name, DIR.EGRESS, PRIO);
	purge_device(ifindex);

	delete attached[name];
	NOTE('detached %s (ifindex %d)', name, ifindex);
};

/* Enumerate current netifd devices and attach any that match (startup/safety).
 * `ubus` is the connection passed in by the entry script. */
export function snapshot(ubus)
{
	let status = ubus.call('network.device', 'status', {});

	if (status && type(status) == 'object') {
		for (let name in status) {
			let dev = status[name];
			let ifindex = ifindex_of(name);

			if (ifindex)
				name_by_index[ifindex] = name;

			if (glob_match(name) && dev.present && ifindex)
				attach_device(name, ifindex);
		}
	}

	if (length(device_pats) > 0 && length(attached) == 0)
		INFO('no matching devices present yet');
};

/* netifd network.device notification handler. Runs outside the entry's
 * try/catch, so it must never throw. */
export function on_device_event(ev)
{
	try {
		let type = ev && ev.type;
		let data = ev ? ev.data : null;
		let name = (data && type(data) == 'object') ? data.name : null;

		if (!name)
			return;

		switch (type) {
		case 'add':
		case 'up':
			if (glob_match(name))
				attach_device(name, data.ifindex);
			break;
		case 'remove':
		case 'down':
			if (attached[name])
				detach_device(name, attached[name].ifindex);
			break;
		}
	}
	catch (e) {
		WARN('device event error: %s', sprintf('%s', e));
	}
};

/* Resolve an ifindex to a netdev name for human-readable output. */
export function rname(ifindex)
{
	return name_by_index[ifindex] || sprintf('%d', ifindex);
};

/* Emit a single flow to the exporter (debug output for now; later IPFIX).
 * `k`/`v` are parsed key/value objects (see flow.uc); `expired` marks an
 * inactive flow that lifecycle.uc is about to remove. */
export function export_flow(k, v, expired)
{
	let dir = (k.direction == DIR.INGRESS) ? 'ingress' : 'egress';

	INFO('flow ifindex=%d ifname=%s direction=%s family=%d proto=%d sport=%d dport=%d icmp=%d/%d tcp_flags=0x%x packets=%d bytes=%d%s',
	     k.ifindex, rname(k.ifindex), dir, k.family, k.protocol,
	     k.sport, k.dport, k.icmp_type, k.icmp_code,
	     v.tcp_flags, v.packets, v.bytes,
	     expired ? ' [expired]' : '');
};