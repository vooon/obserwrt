/*
 * obserwrt - device reconciliation + flow reporting (reconcile.uc)
 *
 * Attaches/detaches the TC programs on the configured netdevs via netifd
 * (`network.device` events + an infrequent startup/safety status snapshot),
 * and reports the flow map. Imported by obserwrt.uc.
 */
import { tc_detach, error as bpf_error } from 'bpf';
import { cursor } from 'uci';
import { readfile } from 'fs';
import { INFO, NOTE, WARN } from 'log';
import { ing, eg, purge_device } from './flow.uc';

const PRIO = 10;      /* tc filter priority */

let device_pats = [];
let attached = {};          /* attached[name] = { ifindex } */
let name_by_index = {};     /* ifindex -> netdev name (debug output) */

const load_devices = function()
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
const glob_match = function(name)
{
	for (let i = 0; i < length(device_pats); i++) {
		if (wildcard(name, device_pats[i]))
			return true;
	}
	return false;
};

/* Real kernel ifIndex via sysfs; netifd's network.device status does not
 * expose it. Returns 0 if the netdev is absent. */
const ifindex_of = function(name)
{
	let v = readfile('/sys/class/net/' + name + '/ifindex');

	return (v === null) ? 0 : int(v);
};

const attach_device = function(name, ifindex)
{
	if (attached[name]) {
		if (ifindex)
			attached[name].ifindex = ifindex;
		return;
	}

	if (!ing().tc_attach(name, 'ingress', PRIO, 0))
		WARN('ingress attach %s: %s', name, bpf_error());
	if (!eg().tc_attach(name, 'egress', PRIO, 0))
		WARN('egress attach %s: %s', name, bpf_error());

	attached[name] = { ifindex: ifindex || ifindex_of(name) };
	NOTE('attached %s (ifindex %d)', name, attached[name].ifindex);
};

const detach_device = function(name, ifindex)
{
	if (!attached[name])
		return;

	tc_detach(name, 'ingress', PRIO);
	tc_detach(name, 'egress', PRIO);
	purge_device(ifindex);

	delete attached[name];
	NOTE('detached %s (ifindex %d)', name, ifindex);
};

/* Enumerate current netifd devices and attach any that match (startup/safety).
 * `ubus` is the connection passed in by the entry script. */
export const snapshot = function(ubus)
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
export const on_device_event = function(ev)
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
export const rname = function(ifindex)
{
	return name_by_index[ifindex] || sprintf('%d', ifindex);
};

/* Emit a single flow to the exporter (debug output for now; later IPFIX).
 * `k`/`v` are the unpacked key/value arrays; `expired` marks an inactive flow
 * that lifecycle.uc is about to remove. */
export const export_flow = function(k, v, expired)
{
	let dir = (k[1] == 0) ? 'ingress' : 'egress';

	INFO('flow ifindex=%d ifname=%s direction=%s family=%d proto=%d sport=%d dport=%d icmp=%d/%d tcp_flags=0x%x packets=%d bytes=%d%s',
	     k[0], rname(k[0]), dir, k[2], k[3], k[6], k[7], k[8], k[9], v[4], v[0], v[1],
	     expired ? ' [expired]' : '');
};