/* obserwrt - socket module mock
 *
 * Replaces the real socket module (loaded via compile-time `import`), so tests
 * can capture every outgoing IPFIX datagram without a network. `create()`
 * returns an in-memory handle whose `send()` records { host, port, data } into
 * global.MOCK_SENT.
 */
"use strict";

if (!exists(global, 'MOCK_SENT'))
	global.MOCK_SENT = [];

function error() { return 'mock socket error'; }

function create(family, type, proto) {
	return {
		bind: (addr) => true,

		send: (data, flags, hostport) => {
			let i = index(hostport, ':'),
			    host = hostport,
			    port = null;

			if (i != -1) {
				host = substr(hostport, 0, i);
				port = int(substr(hostport, i + 1));
			}

			push(global.MOCK_SENT, { host, port, data });
			return length(data);
		},
	};
}

export const AF_INET = 2;
export const SOCK_DGRAM = 2;
export { error, create };