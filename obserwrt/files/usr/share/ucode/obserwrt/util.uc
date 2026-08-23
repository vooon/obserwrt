/* Shared configuration and observation helpers. */
"use strict";

import { readfile } from 'fs';
import * as socket from 'socket';

/* Match OpenWrt's get_bool() accepted spellings. */
export function bool_option(value, fallback)
{
	switch (value) {
	case '1':
	case 'on':
	case 'true':
	case 'yes':
	case 'enabled':
		return true;
	case '0':
	case 'off':
	case 'false':
	case 'no':
	case 'disabled':
		return false;
	default:
		return fallback;
	}
};

/* Router hostname. Returns '' if it cannot be read. */
export function sys_hostname()
{
	let name = readfile('/proc/sys/kernel/hostname');

	if (name === null)
		return '';
	return rtrim(name);
};

/* RFC 3339 UTC timestamp (RFC 5424 TIMESTAMP form). */
export function iso_timestamp()
{
	let t = gmtime(time());

	return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
		t.year, t.mon, t.mday, t.hour, t.min, t.sec);
};

/* Resolve a destination hostname to a numeric address. `sendto()` needs an IP,
 * not a hostname. IP literals pass through unchanged; otherwise an addrinfo
 * lookup is done, preferring IPv4 (senders use AF_INET sockets). Returns null
 * if resolution fails. */
export function resolve_dest(host)
{
	if (iptoarr(host) !== null)
		return host;

	let infos = socket.addrinfo(host, null, { socktype: socket.SOCK_DGRAM });

	if (!infos || length(infos) == 0)
		return null;

	for (let info in infos)
		if (info.family == socket.AF_INET)
			return info.addr.address;

	return infos[0].addr.address;
};
