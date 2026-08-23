/* obserwrt - bpf module mock
 *
 * Lets flow.uc (and therefore exporter_ipfix.uc's `import { INGRESS, EGRESS }
 * from './flow.uc'`) compile without a real eBPF object or kernel. The
 * map/program accessors return inert stubs.
 */
"use strict";

function error() { return 'mock bpf error'; }

function tc_detach() { return null; }

function open_module(path, opts) {
	return {
		get_map: (name) => ({ delete_all: () => null }),
		get_program: (name) => ({ tc_attach: () => true }),
	};
}

export const BPF_PROG_TYPE_SCHED_CLS = 2;
export { error, tc_detach, open_module };