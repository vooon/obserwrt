/*
 * obserwrt - P0 TC visibility agent.
 *
 * Loads the eBPF module, reconciles the configured devices via netifd
 * (startup enumeration + `network.device` events), attaches the ingress/egress
 * TC programs, and periodically dumps the per-(ifindex,direction,family,proto)
 * counters for validation.
 *
 * No exporter is active yet; P0 is purely the TC-visibility probe.
 */
import { open_module, tc_detach, error as bpf_error, BPF_PROG_TYPE_SCHED_CLS } from 'bpf';
import { connect } from 'ubus';
import { cursor } from 'uci';
import * as struct from 'struct';
import { readfile } from 'fs';
import { ulog_open, ulog, INFO, NOTE, WARN, ERR, ULOG_SYSLOG, LOG_DAEMON, LOG_DEBUG } from 'log';

ulog_open(ULOG_SYSLOG, LOG_DAEMON, "obserwrt");

/* ------------------------------------------------------------------ config */

const BPF_OBJ = getenv('BPF_OBJ') || '/usr/lib/obserwrt/obserwrt-bpf.o';
const PRIO   = 10;      /* tc filter priority */
const SNAP_S = 5;       /* counter snapshot interval (seconds) */

/* flow key/value layouts (docs/design.md §5) */
const KFMT = '<LBBBx16s16sHH';   /* 44 B */
const VFMT = '<QQQQB7x';         /* 40 B */

/* device patterns; assigned below once load_devices_once() is defined
 * (ucode does not hoist function declarations) */
let device_pats;

function load_devices_once()
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
}

device_pats = load_devices_once();

/* matches a netdev name against the configured patterns using ucode's
 * built-in fnmatch-based wildcard() */
function glob_match(name)
{
	for (let i = 0; i < length(device_pats); i++) {
		if (wildcard(name, device_pats[i]))
			return true;
	}
	return false;
}

/* ------------------------------------------------------------------- bpf */

let bpf = null;

function load_bpf()
{
	/* libbpf 1.6 no longer infers SCHED_CLS from "classifier/<sub>"; force it. */
	let mod = open_module(BPF_OBJ, {
		'program-type': {
			obserwrt_ingress: BPF_PROG_TYPE_SCHED_CLS,
			obserwrt_egress: BPF_PROG_TYPE_SCHED_CLS,
		},
	});

	if (!mod)
		die(sprintf('open_module(%s) failed: %s', BPF_OBJ, bpf_error()));

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

/* Real kernel ifIndex via sysfs; netifd's network.device status does not
 * expose it. Returns 0 if the netdev is absent. */
function ifindex_of(name)
{
	let v = readfile('/sys/class/net/' + name + '/ifindex');

	return (v === null) ? 0 : int(v);
}

function purge_device(ifindex)
{
	bpf.flows.delete_all(
		function (key) {
			return struct.unpack(KFMT, key)[0] == ifindex;
		});
}

function attach_device(name, ifindex)
{
	if (attached[name]) {
		if (ifindex)
			attached[name].ifindex = ifindex;
		return;
	}

	if (!bpf.ing.tc_attach(name, 'ingress', PRIO, 0))
		WARN('ingress attach %s: %s', name, bpf_error());
	if (!bpf.eg.tc_attach(name, 'egress', PRIO, 0))
		WARN('egress attach %s: %s', name, bpf_error());

	attached[name] = { ifindex: ifindex || ifindex_of(name) };
	NOTE('attached %s (ifindex %d)', name, attached[name].ifindex);
}

function detach_device(name, ifindex)
{
	if (!attached[name])
		return;

	tc_detach(name, 'ingress', PRIO);
	tc_detach(name, 'egress', PRIO);
	purge_device(ifindex);

	delete attached[name];
	NOTE('detached %s (ifindex %d)', name, ifindex);
}

/* ----------------------------------------------------------- reconciliation */

let ubus = null;

function snapshot()
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
}

function on_device_event(ev)
{
	/* ubus subscriber callbacks run outside main()'s try/catch: never let a
	 * malformed notification crash the agent. */
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

		INFO('flow ifindex=%d ifname=%s direction=%s family=%d proto=%d packets=%d bytes=%d',
		     k[0], name, dir, k[2], k[3], v[0], v[1]);
		n++;
	});
	if (n == 0)
		ulog(LOG_DEBUG, 'snapshot: no counters observed yet');
}

/* ------------------------------------------------------------------- main */

function main()
{
	load_bpf();

	ubus = connect();
	if (!ubus)
		die('ubus connect failed');

	let sub = ubus.subscriber(on_device_event, null, []);
	sub.subscribe('network.device');

	try {
		snapshot();
	}
	catch (e) {
		WARN('initial snapshot: %s', sprintf('%s', e));
	}

	let last = time();
	for (;;) {
		sleep(1);
		let now = time();
		try {
			snapshot();              /* continuous reconciliation */
		}
		catch (e) {
			WARN('snapshot: %s', sprintf('%s', e));
		}
		if (now - last >= SNAP_S) {
			try {
				dump_counters();
			}
			catch (e) {
				WARN('dump: %s', sprintf('%s', e));
			}
			last = now;
		}
	}
}

try {
	main();
}
catch (e) {
	ERR('fatal: %s', sprintf('%s', e));
	exit(1);
}