/*
 * obserwrt - BPF flow map access (flow.uc)
 *
 * Single point of ownership for the flow key/value wire formats and the BPF
 * map. Other modules never touch `struct` directly - they use the parse
 * helpers and map accessors exported here:
 *   import { flows, parse_key, purge_device } from './flow.uc'
 */

"use strict";

import { open_module, error as bpf_error, BPF_PROG_TYPE_SCHED_CLS } from 'bpf';
import * as struct from 'struct';

const BPF_OBJ_LOC = getenv('BPF_OBJ') || '/lib/bpf/obserwrt-bpf.o';

/* flow key/value layouts (docs/design.md §5) - private, use the parse helpers */
const KFMT = '<LBBBx16s16sHHBB';   /* 46 B */
const VFMT = '<QQQQH6x';           /* 40 B */

/* Direction at the observation point (mirrors the BPF enum). */
export const DIR = { INGRESS: 0, EGRESS: 1 };

let bpf = null;   /* loaded module refs */

/* --- map access ------------------------------------------------------ */

/* Load and verify the eBPF module. Idempotent; returns the refs. */
export function load_bpf() {
	if (bpf)
		return bpf;

	/* libbpf 1.6 no longer infers SCHED_CLS from "classifier/<sub>". */
	let mod = open_module(BPF_OBJ_LOC, {
		'program-type': {
			obserwrt_ingress: BPF_PROG_TYPE_SCHED_CLS,
			obserwrt_egress:  BPF_PROG_TYPE_SCHED_CLS,
		},
	});

	if (!mod)
		die(sprintf('open_module(%s) failed: %s', BPF_OBJ_LOC, bpf_error()));

	bpf = {
		flows: mod.get_map('obs_flows'),
		ing:   mod.get_program('obserwrt_ingress'),
		eg:    mod.get_program('obserwrt_egress'),
	};

	return bpf;
};

export function flows() { return bpf.flows; };
export function ing()   { return bpf.ing; };
export function eg()    { return bpf.eg; };

/* Drop every flow map entry recorded for the given device incarnation. */
export function purge_device(ifindex) {
	flows().delete_all(
		function (key) {
			return parse_key(key).ifindex == ifindex;
		});
};

/* --- wire-format parsing (the single struct owner) ------------------- */

/* Decode a raw flow-map key (bytes) into a structured object. */
export function parse_key(raw)
{
	let u = struct.unpack(KFMT, raw);

	return {
		ifindex:   u[0],
		direction: u[1],
		family:    u[2],
		protocol:  u[3],
		src:       u[4],
		dst:       u[5],
		sport:     u[6],
		dport:     u[7],
		icmp_type: u[8],
		icmp_code: u[9],
	};
};

/* Decode a raw flow-map value (bytes) into a structured object. */
export function parse_value(raw)
{
	let u = struct.unpack(VFMT, raw);

	return {
		packets:    u[0],
		bytes:      u[1],
		first_seen: u[2],
		last_seen:  u[3],
		tcp_flags:  u[4],
	};
};