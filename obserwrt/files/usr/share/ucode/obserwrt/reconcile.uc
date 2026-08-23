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
import { attach, detach, purge_device, INGRESS, EGRESS } from './flow.uc';

const PRIO = 10;      /* tc filter priority */

let device_pats = [];
let attached = {};          /* attached[name] = { ifindex } */
let name_by_index = {};     /* ifindex -> current netdev name */

function load_devices()
{
	let pats = [];
	try {
		const ctx = cursor();
		let v = ctx.get('obserwrt', 'main', 'device');
		if (v === null)
			return pats;
		if (type(v) == 'array') {
			/* ucode `for..in` yields the elements; uci returns strings already */
			for (let item in v)
				push(pats, item);
		}
		else {
			push(pats, v);
		}
	}
	catch (e) {
		/* a missing/empty config returns null above (not an error); an exception
		 * here is a real problem - surface it instead of silently observing
		 * nothing */
		WARN('cannot read device config: %s', e);
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
	let v = readfile(`/sys/class/net/${name}/ifindex`);

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

	if ((e = attach(name, INGRESS, PRIO)))
		WARN('ingress attach %s: %s', name, e);
	if ((e = attach(name, EGRESS, PRIO)))
		WARN('egress attach %s: %s', name, e);

	attached[name] = { ifindex: ifindex || ifindex_of(name) };
	name_by_index[attached[name].ifindex] = name;
	NOTE('attached %s (ifindex %d)', name, attached[name].ifindex);
};

function detach_device(name)
{
	let info = attached[name];

	if (!info)
		return;

	detach(name, INGRESS, PRIO);
	detach(name, EGRESS, PRIO);
	purge_device(info.ifindex);

	delete attached[name];
	delete name_by_index[info.ifindex];
	NOTE('detached %s (ifindex %d)', name, info.ifindex);
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

export function ifname(ifindex)
{
	return name_by_index[ifindex] || sprintf('%d', ifindex);
};

/* Number of currently attached netdevs (for self-observability metrics). */
export function attached_count()
{
	return length(attached);
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
			detach_device(name);   /* detach_device guards on attached[name] */
			break;
		}
	}
	catch (e) {
		WARN('device event error: %s', e);
	}
};
