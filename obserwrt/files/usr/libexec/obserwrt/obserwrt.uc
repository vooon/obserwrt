/*
 * obserwrt - P0 TC visibility agent.
 *
 * Loads the eBPF module, reconciles the configured devices via netifd
 * (startup enumeration + `network.device` events), attaches the ingress/egress
 * TC programs, and periodically dumps the per-(ifindex,direction,family,proto)
 * counters to the log for validation.
 *
 * No exporter is active yet; P0 is purely the TC-visibility probe.
 */
import { open_module, tc_detach, error as bpf_error } from 'bpf';
import { connect } from 'ubus';
import { cursor } from 'uci';
import * as struct from 'struct';

/* ------------------------------------------------------------------ config */

const BPF_OBJ = getenv('BPF_OBJ') || '/usr/lib/obserwrt/obserwrt-bpf.o';
const PRIO   = 10;      /* tc filter priority */
const SNAP_S = 5;       /* counter snapshot interval (seconds) */

/* flow key/value layouts (docs/design.md §5) */
const KFMT = '<LBBBx16s16sHH';   /* 44 B */
const VFMT = '<QQQQB7x';         /* 40 B */

const device_pats = load_devices_once();

function load_devices_once()
{
	let pats = [];
	try {
		const ctx = cursor();
		let v = ctx.get('obserwrt', 'main', 'device');
		if (v === null)
			return pats;
		if (type(v) == 'array')
			for (let i in v) pats.push(sprintf('%s', v[i]));
		else
			pats.push(sprintf('%s', v));
	}
	catch (e) {
		/* config missing/empty: fall through to empty device set */
	}
	return pats;
}

function glob_match(name)
{
	for (let p in device_pats) {
		let re = new RegExp('^' + p.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
		if (re.test(name))
			return true;
	}
	return false;
}

/* ------------------------------------------------------------------- bpf */

let bpf = null;

function load_bpf()
{
	let mod = open_module(BPF_OBJ);
	if (!mod)
		throw sprintf('open_module(%s): %s', BPF_OBJ, bpf_error());

	bpf = {
		flows: mod.get_map('obs_flows'),
		ing:   mod.get_program('obserwrt_ingress'),
		eg:    mod.get_program('obserwrt_egress'),
	};
}

/* attached[name] = { ifindex } (ifindex refreshed each snapshot) */
const attached = {};

/* ifindex -> netdev name, refreshed each snapshot for debug output */
const name_by_index = {};

function purge_device(ifindex)
{
	bpf.flows.delete_all(
		function (key) {
			return struct.unpack(KFMT, key)[0] == ifindex;
		});
}

function attach_device(name, ifindex)
{
	if (ifindex)
		attached[name] = { ifindex: ifindex };

	if (attached[name])
		return;

	if (!bpf.ing.tc_attach(name, 'ingress', PRIO, 0))
		warn('obserwrt: ingress attach %s: %s\n', name, bpf_error());
	if (!bpf.eg.tc_attach(name, 'egress', PRIO, 0))
		warn('obserwrt: egress attach %s: %s\n', name, bpf_error());

	attached[name] = { ifindex: ifindex || 0 };
	print(sprintf('obserwrt: attached %s (ifindex %d)\n', name, ifindex || attached[name].ifindex));
}

function detach_device(name, ifindex)
{
	if (!attached[name])
		return;

	tc_detach(name, 'ingress', PRIO);
	tc_detach(name, 'egress', PRIO);
	purge_device(ifindex);

	delete attached[name];
	print(sprintf('obserwrt: detached %s (ifindex %d)\n', name, ifindex));
}

/* ----------------------------------------------------------- reconciliation */

let ubus = null;

function snapshot()
{
	let status = ubus.call('network.device', 'status', {});

	if (status && type(status) == 'object') {
		for (let name in status) {
			let ifindex = status[name].ifindex;

			if (ifindex)
				name_by_index[ifindex] = name;

			if (glob_match(name) && ifindex)
				attach_device(name, ifindex);
		}
	}

	if (length(attached) == 0)
		print(sprintf('obserwrt: no matching devices present\n'));
}

function on_device_event(ev)
{
	let type = ev && ev.type;
	let data = ev && ev.data ? ev.data : {};

	switch (type) {
	case 'add':
	case 'up':
		if (glob_match(data.name))
			attach_device(data.name, data.ifindex);
		break;
	case 'remove':
	case 'down':
		if (attached[data.name])
			detach_device(data.name, attached[data.name].ifindex);
		break;
	}
}

/* ------------------------------------------------------------------ dump */

function dump_counters()
{
	let n = 0;
	bpf.flows.foreach(function (key) {
		let k = struct.unpack(KFMT, key);
		let v = struct.unpack(VFMT, bpf.flows.get(key));
		let name = name_by_index[k[0]] || sprintf('%d', k[0]);
		let dir = (k[1] == 0) ? 'ingress' : 'egress';

		print(sprintf('flow ifindex=%d ifname=%s direction=%s family=%d proto=%d'
		              ' packets=%d bytes=%d\n',
		              k[0], name, dir, k[2], k[3], v[0], v[1]));
		n++;
	});
	if (n == 0)
		print(sprintf('obserwrt: snapshot: no counters observed\n'));
}

/* ------------------------------------------------------------------- main */

function main()
{
	load_bpf();

	ubus = connect();
	if (!ubus)
		throw 'ubus connect failed';

	let sub = ubus.subscriber(on_device_event, null, []);
	sub.subscribe('network.device');

	snapshot();

	let last = time();
	for (;;) {
		sleep(1);
		let now = time();
		if (now - last >= SNAP_S) {
			dump_counters();
			last = now;
		}
	}
}

try {
	main();
}
catch (e) {
	die(sprintf('obserwrt fatal: %s', sprintf('%s', e)));
}