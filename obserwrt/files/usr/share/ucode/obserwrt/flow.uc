/*
 * obserwrt - BPF flow map access (flow.uc)
 *
 * Single point of ownership for the flow key/value wire formats and the BPF
 * map. Other modules never touch `struct` directly - they use the parse
 * helpers and map accessors exported here:
 *   import { flows, parse_key, purge_device } from './flow.uc'
 */

"use strict";

import { open_module, tc_detach, error as bpf_error, BPF_PROG_TYPE_SCHED_CLS } from 'bpf';
import * as struct from 'struct';

const BPF_OBJ_LOC = getenv('BPF_OBJ') || '/lib/bpf/obserwrt-bpf.o';

/* Direction at the observation point (mirrors the BPF enum). */
export const INGRESS = 0;
export const EGRESS  = 1;

let handle = null;   /* loaded module refs { flows, ingress, egress } */

/* --- map access ------------------------------------------------------ */

/* Load and verify the eBPF module. Idempotent; returns the handles. */
export function load_bpf() {
	if (handle)
		return handle;

	/* libbpf 1.6 no longer infers SCHED_CLS from "classifier/<sub>". */
	let mod = open_module(BPF_OBJ_LOC, {
		'program-type': {
			obserwrt_ingress: BPF_PROG_TYPE_SCHED_CLS,
			obserwrt_egress:  BPF_PROG_TYPE_SCHED_CLS,
		},
	});

	if (!mod)
		die(sprintf('open_module(%s) failed: %s', BPF_OBJ_LOC, bpf_error()));

	handle = {
		flows:   mod.get_map('obserwrt_flows'),
		ingress: mod.get_program('obserwrt_ingress'),
		egress:  mod.get_program('obserwrt_egress'),
	};

	return handle;
};

export function flows() {
	return handle.flows;
};

/* tc hook name for a direction */
function dir_str(d) {
	return (d == INGRESS) ? 'ingress' : 'egress';
};

/* Attach the TC program at `direction` to a netdev. Returns null on success or
 * an error message string. All the bpf() interaction lives here so that
 * importing modules never need to touch the `bpf` module directly. */
export function attach(name, direction, prio)
{
	let prog = (direction == INGRESS) ? handle.ingress : handle.egress;
	let ok = prog.tc_attach(name, dir_str(direction), prio, 0);

	return ok ? null : bpf_error();
};

/* Detach the TC program at `direction` from a netdev. */
export function detach(name, direction, prio)
{
	tc_detach(name, dir_str(direction), prio);
};

/* --- wire-format parsing (the single struct owner) ------------------- */

/* Precompiled formats (flow key = 46 B '<LBBBx16s16sHHBB', value = 40 B
 * '<QQQQH6x'; struct/type owner - see docs/design.md §5). */
const KEY_FMT = struct.new('<LBBBx16s16sHHBB');
const VAL_FMT = struct.new('<QQQQH6x');

/* Decode a raw flow-map key (bytes) into a key object. */
export function parse_key(raw)
{
	let u = KEY_FMT.unpack(raw);

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

/* Decode a raw flow-map value (bytes) into a value object. */
export function parse_value(raw)
{
	let u = VAL_FMT.unpack(raw);

	return {
		packets:    u[0],
		bytes:      u[1],
		first_seen: u[2],
		last_seen:  u[3],
		tcp_flags:  u[4],
	};
};

/* Drop every flow map entry recorded for the given device incarnation. Define
 * after parse_key: closures capture by position (no hoisting in ucode). */
export function purge_device(ifindex) {
	flows().delete_all(
		function (key) {
			return parse_key(key).ifindex == ifindex;
		});
};
