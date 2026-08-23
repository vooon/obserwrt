/*
 * obserwrt - BPF map access (flow.uc)
 *
 * Loads the eBPF module and exposes the flow map and TC programs. Imported by
 * obserwrt.uc and reconcile.uc. Uses ucode's .uc module idiom:
 *   import { flows, load_bpf } from './flow.uc'
 * (this ucode only supports `export const`, functions assigned to consts).
 */
import { open_module, error as bpf_error, BPF_PROG_TYPE_SCHED_CLS } from 'bpf';
import * as struct from 'struct';

const BPF_OBJ_LOC = getenv('BPF_OBJ') || '/lib/bpf/obserwrt-bpf.o';

/* flow key/value layouts (docs/design.md §5) */
export const KFMT = '<LBBBx16s16sHHBB';   /* 46 B */
export const VFMT = '<QQQQH6x';           /* 40 B */

let bpf = null;   /* loaded module refs */

/* Load and verify the eBPF module. Idempotent; returns the refs. */
export const load_bpf = function() {
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

export const flows = function() { return bpf.flows; };
export const ing   = function() { return bpf.ing; };
export const eg    = function() { return bpf.eg; };

/* Drop every flow map entry recorded for the given device incarnation. */
export const purge_device = function(ifindex) {
	flows().delete_all(
		function (key) {
			return struct.unpack(KFMT, key)[0] == ifindex;
		});
};