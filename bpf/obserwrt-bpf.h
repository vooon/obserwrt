/* SPDX-License-Identifier: GPL-2.0-only */
/* obserwrt - definitions shared by the eBPF objects (obserwrt-bpf.h).
 *
 * Included by obserwrt-bpf.c (TC flow observation) and obserwrt-drops.c (the
 * tp_btf/kfree_skb drop tracer). Each object defines its own
 * `obserwrt_stats` map from this header; the agent loads the tracer with
 * the TC object's map fd reused (bpf_map__reuse_fd), so both count into one
 * map. Keep this header free of anything that needs kernel BTF: the TC
 * object must stay loadable without it (docs/design.md §7.1).
 */
#pragma once

#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <bpf/bpf_helpers.h>

/* Shared flow key/value layouts (docs/design.md §5) - the single owner of
 * the wire format, also included by the C++ agent (flow.hpp). */
#include "obserwrt-flow.h"

/* Per-instance aggregate counters ("set A" of the "two sets" design).
 * Packets/bytes count everything the TC filter sees; flows_created counts new
 * flow inserts (exact even under LRU eviction); parsed counts the subset of
 * packets that entered flow accounting (all IP, incl. non-first fragments and
 * non-TCP/UDP/ICMP protocols, but excluding ARP / non-IP / malformed). */
enum {
	STAT_PACKETS = 0,
	STAT_BYTES,
	STAT_FLOWS_CREATED,
	STAT_PARSED,
	STAT_DROPS,          /* drops on attached devices (tp_btf/kfree_skb) */
	STAT_DROPS_UNPARSED, /* ... of which not IPv4/IPv6 or no network header */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obserwrt_stats SEC(".maps");

/* Entries of the per-device maps (two per attached device in
 * obserwrt_devstats; one in obserwrt_attached). */
#ifndef DEV_MAP_ENTRIES
#define DEV_MAP_ENTRIES 1024
#endif

static inline void
stat_add(__u32 idx, __u64 n)
{
	__u64 *c = bpf_map_lookup_elem(&obserwrt_stats, &idx);

	if (c)
		*c += n;   /* per-CPU slot: no atomic needed */
}

/* Store a 4-byte IPv4 address as IPv4-mapped IPv6 (::ffff:a.b.c.d). */
static inline void
ip4_to_in6(__u8 out[16], const __u8 *ip)
{
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, ip, 4);
}
