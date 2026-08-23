/*
 * obserwrt - syslog flow exporter
 *
 * Sends normalized observations as RFC 5424-compatible syslog messages. An
 * An empty syslog_host uses the process-local OpenWrt syslog facility; a remote
 * syslog_host uses one connected UDP socket for the lifetime of the agent.
 */
"use strict";

import * as socket from 'socket';
import { cursor } from 'uci';
import { ulog, WARN, LOG_INFO } from 'log';
import { INGRESS } from './flow.uc';
import { ifname } from './reconcile.uc';
import { bool_option } from './util.uc';

let active = false;
let local = false;
let format = 'json';
let sock = null;

function key_ip(value, family)
{
	let offset = (family == 4) ? 12 : 0;
	let count = (family == 4) ? 4 : 16;
	let bytes = [];

	for (let i = 0; i < count; i++)
		push(bytes, ord(value, offset + i));

	return arrtoip(bytes);
};

function flow_record(k, v, expired)
{
	return {
		ifindex: k.ifindex,
		ifname: ifname(k.ifindex),
		direction: (k.direction == INGRESS) ? 'ingress' : 'egress',
		family: k.family,
		protocol: k.protocol,
		icmp_type: k.icmp_type,
		icmp_code: k.icmp_code,
		src: key_ip(k.src, k.family),
		dst: key_ip(k.dst, k.family),
		sport: k.sport,
		dport: k.dport,
		packets: v.packets,
		bytes: v.bytes,
		first_seen_ns: v.first_seen,
		last_seen_ns: v.last_seen,
		tcp_flags: v.tcp_flags,
		expired: !!expired,
	};
};

function encode(record)
{
	if (format == 'json')
		return sprintf('%J', record);

	return sprintf('ifindex=%d direction=%s family=%d protocol=%d icmp_type=%d icmp_code=%d src=%J dst=%J sport=%d dport=%d packets=%d bytes=%d first_seen_ns=%d last_seen_ns=%d tcp_flags=%d expired=%d',
		record.ifindex, record.direction, record.family, record.protocol,
		record.icmp_type, record.icmp_code, record.src, record.dst,
		record.sport, record.dport, record.packets, record.bytes,
		record.first_seen_ns, record.last_seen_ns, record.tcp_flags,
		record.expired ? 1 : 0);
};

function send(message)
{
	if (local) {
		/* Keep the payload an argument, not the ulog format string. */
		ulog(LOG_INFO, '%s', message);
		return;
	}

	if (sock)
		sock.send('<134>1 - obserwrt - - - ' + message);
};

export function init()
{
	let ctx = cursor();
	let enabled = ctx.get('obserwrt', 'syslog', 'enabled');

	if (!bool_option(enabled, false))
		return false;

	format = ctx.get('obserwrt', 'syslog', 'format') || 'json';
	if (format != 'json' && format != 'logfmt') {
		WARN('syslog: unsupported format %s', format);
		return false;
	}

	let protocol = ctx.get('obserwrt', 'syslog', 'protocol') || 'udp';
	if (protocol != 'udp') {
		WARN('syslog: unsupported protocol %s', protocol);
		return false;
	}

	let host = ctx.get('obserwrt', 'syslog', 'syslog_host') || '';
	if (!host) {
		local = true;
		active = true;
		return true;
	}

	let port = int(ctx.get('obserwrt', 'syslog', 'syslog_port') || '514');
	try {
		sock = socket.connect(host, port, { socktype: socket.SOCK_DGRAM });
	}
	catch (e) {
		WARN('syslog: cannot connect %s:%d: %s', host, port, e);
		return false;
	}

	if (!sock) {
		WARN('syslog: cannot connect %s:%d: %s', host, port, socket.error());
		return false;
	}

	active = true;
	return true;
};

export function emit(k, v, expired)
{
	if (active)
		send(encode(flow_record(k, v, expired)));
};
