/* obserwrt - bpf module mock
 *
 * Lets flow.uc compile without a real eBPF object or kernel. `get_map` returns
 * an in-memory string-keyed map (get/set/delete/foreach/delete_all) so the flow
 * map and lifecycle delta accounting can be exercised; `get_program` is inert.
 */
"use strict";

function error() { return 'mock bpf error'; }

function tc_detach() { return null; }

function get_map(name) {
	/* ucode object keys cannot hold NUL bytes, so key the store by the hex of
	 * the raw map key; decode back to binary at the API boundary. */
	let store = {};

	return {
		get: (k) => { let e = hexenc(k); return (e in store) ? store[e] : null; },
		set: (k, v) => { store[hexenc(k)] = v; },
		delete: (k) => { delete store[hexenc(k)]; },
		delete_all: (fn) => {
			for (let e in store) {
				let raw = hexdec(e);
				if (!fn || fn(raw))
					delete store[e];
			}
		},
		foreach: (cb) => { for (let e in store) cb(hexdec(e)); },
	};
}

function open_module(path, opts) {
	return {
		get_map,
		get_program: (name) => ({ tc_attach: () => true }),
	};
}

export const BPF_PROG_TYPE_SCHED_CLS = 2;
export { error, tc_detach, open_module, get_map };