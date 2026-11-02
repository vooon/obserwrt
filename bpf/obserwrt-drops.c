/* SPDX-License-Identifier: GPL-2.0-only */
/* obserwrt - kernel drop tracing (tp_btf/kfree_skb).
 *
 * Records packets the kernel DROPS on attached devices (obserwrt_drops, keyed
 * by flow tuple + raw drop reason). The agent loads this object only when
 * drop tracking is on (docs/design.md §7.1), with `obserwrt_stats` reused
 * from the TC object so STAT_DROPS lands in the same counters.
 *
 * A separate object on purpose: the minimal CO-RE struct views below put
 * relocations into the object, and libbpf then needs the running kernel's
 * vmlinux BTF to load it at all. Kept out of obserwrt-bpf.c, a kernel without
 * BTF costs the drop tracer and never flow collection.
 *
 * It reads the dropped packet's headers with bpf_probe_read_kernel, a GPL-only
 * helper, hence the GPL license of this object.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <uapi/linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Shared flow layouts (§5), the aggregate stats map and helpers. */
#include "obserwrt-bpf.h"

/* --- maps ------------------------------------------------------------- */

/* Attached ifindexes (agent-maintained): the drop tracer records only drops
 * on observed devices. Value unused. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, DEV_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, __u8);
} obserwrt_attached SEC(".maps");

/* Dropped packets, aggregated per flow tuple + raw reason; the agent drains
 * it (lookup-and-delete) every lifecycle pass. LRU: a drop flood evicts
 * rather than fails; obserwrt_stats STAT_DROPS stays exact. */
#ifndef DROP_MAP_ENTRIES
#define DROP_MAP_ENTRIES 2048
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DROP_MAP_ENTRIES);
	__type(key, struct drop_key);
	__type(value, struct flow_val);
} obserwrt_drops SEC(".maps");

/* --- drop tracing --------------------------------------------------- */

/* Minimal CO-RE views of kernel structs: libbpf relocates these field
 * offsets against the running kernel's BTF at load (no vmlinux.h needed). */
struct net_device {
	int ifindex;
} __attribute__((preserve_access_index));

struct sk_buff {
	struct net_device *dev;
	unsigned int len;
	int skb_iif;
	__u16 protocol; /* __be16 */
	__u16 network_header;
	unsigned char *head;
} __attribute__((preserve_access_index));

/* Parse the dropped packet's L3/L4 headers from kernel memory into `dk`.
 * Returns the L3 length (IP total length) or 0 if not parseable. Simpler
 * than the TC parser on purpose: IPv6 extension headers are not walked (the
 * next-header value is recorded as the protocol, ports 0). */
static __always_inline __u32
drop_parse(unsigned char *l3, __u16 proto, struct drop_key *dk, __u8 *tcpf, __u8 *tos)
{
	__u8 hdr[40];
	__u8 l4[14];
	__u32 l3len, ihl = 0;
	__u8 ip_proto;
	int have_l4 = 1;

	if (proto == ETH_P_IP) {
		if (bpf_probe_read_kernel(hdr, 20, l3) != 0 || (hdr[0] >> 4) != 4)
			return 0;
		ihl = (__u32)(hdr[0] & 0x0f) << 2;
		if (ihl < 20)
			return 0;
		ip_proto = hdr[9];
		dk->flow.family = 4;
		*tos = hdr[1];
		ip4_to_in6(dk->flow.src, hdr + 12);
		ip4_to_in6(dk->flow.dst, hdr + 16);
		l3len = bpf_ntohs(*(__u16 *)(hdr + 2));
		have_l4 = (bpf_ntohs(*(__u16 *)(hdr + 6)) & 0x1fff) == 0;
	} else if (proto == ETH_P_IPV6) {
		if (bpf_probe_read_kernel(hdr, 40, l3) != 0 || (hdr[0] >> 4) != 6)
			return 0;
		ihl = 40;
		ip_proto = hdr[6];
		dk->flow.family = 6;
		*tos = (__u8)((hdr[0] << 4) | (hdr[1] >> 4));
		__builtin_memcpy(dk->flow.src, hdr + 8, 16);
		__builtin_memcpy(dk->flow.dst, hdr + 24, 16);
		l3len = 40 + bpf_ntohs(*(__u16 *)(hdr + 4));
	} else {
		return 0;
	}

	dk->flow.protocol = ip_proto;
	if (have_l4 && (ip_proto == 6 || ip_proto == 17 || ip_proto == 1 || ip_proto == 58) &&
	    bpf_probe_read_kernel(l4, sizeof(l4), l3 + ihl) == 0) {
		if (ip_proto == 6 || ip_proto == 17) {
			dk->flow.sport = bpf_ntohs(*(__u16 *)l4);
			dk->flow.dport = bpf_ntohs(*(__u16 *)(l4 + 2));
			if (ip_proto == 6)
				*tcpf = l4[13];
		} else {
			dk->flow.icmp_type = l4[0];
			dk->flow.icmp_code = l4[1];
		}
	}
	return l3len;
}

/* kfree_skb(skb, location, reason, ...): fires only for drops (normal frees
 * go through consume_skb). Records drops whose skb device is attached.
 * Direction: received on this device (skb_iif == dev) -> ingress, otherwise
 * (forwarded out of / originated on it) -> egress. */
SEC("tp_btf/kfree_skb")
int obserwrt_kfree_skb(__u64 *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx[0];
	__u32 reason = (__u32)ctx[2];
	struct drop_key dk = { 0 };
	struct flow_val *v;
	struct net_device *dev;
	unsigned char *head;
	__u32 ifindex, l3len = 0;
	__u16 nh, proto;
	__u8 tcpf = 0, tos = 0;

	dev = skb->dev;
	if (!dev)
		return 0;
	ifindex = dev->ifindex;
	if (!bpf_map_lookup_elem(&obserwrt_attached, &ifindex))
		return 0;

	stat_add(STAT_DROPS, 1);

	head = skb->head;
	nh = skb->network_header;
	proto = bpf_ntohs(skb->protocol);
	if (head && nh != (__u16)~0U)
		l3len = drop_parse(head + nh, proto, &dk, &tcpf, &tos);
	if (l3len == 0) {
		stat_add(STAT_DROPS_UNPARSED, 1);
		return 0;
	}

	dk.flow.ifindex = ifindex;
	dk.flow.direction = skb->skb_iif == (int)ifindex ? OBSERWRT_INGRESS : OBSERWRT_EGRESS;
	dk.reason = reason;

	v = bpf_map_lookup_elem(&obserwrt_drops, &dk);
	if (v) {
		__sync_fetch_and_add(&v->packets, 1);
		__sync_fetch_and_add(&v->bytes, l3len);
		v->tcp_flags |= tcpf;
		v->last_seen = bpf_ktime_get_ns();
	} else {
		struct flow_val nv = { 0 };
		__u64 now = bpf_ktime_get_ns();

		nv.packets = 1;
		nv.bytes = l3len;
		nv.first_seen = now;
		nv.last_seen = now;
		nv.tcp_flags = tcpf;
		nv.tos = tos;
		bpf_map_update_elem(&obserwrt_drops, &dk, &nv, BPF_ANY);
	}
	return 0;
}

/* GPL: the drop tracer needs bpf_probe_read_kernel (GPL-only helper). */
char LICENSE[] SEC("license") = "GPL";
