/* SPDX-License-Identifier: GPL-2.0-only */
/* obserwrt - TC classifier flow observation + drop tracing.
 *
 * Two TC classifier programs (ingress + egress) share one LRU hash map. For each
 * packet they parse the L3/L4 headers and aggregate a flow keyed by
 * (ifindex, direction, family, protocol, src, dst, sport, dport, icmp type/code).
 *
 * Program type is BPF_PROG_TYPE_SCHED_CLS (forced via ucode program-type; libbpf
 * 1.6 no longer infers it from "classifier/<sub>").
 *
 * Framing is a property of the device, not of the packet, so each direction
 * has two programs and the agent picks the pair by the link type (ARPHRD) at
 * attach time:
 *   - *_l3: L3 devices (WireGuard/AmneziaWG, ip6gre/FOU, tun, PPP) hand the skb
 *     to TC with `data` pointing directly at the IP header (no link layer).
 *   - *_eth: Ethernet devices have a 14-byte link-layer header; the L3 offset
 *     is found by parsing the EtherType, walking one or two 802.1Q/802.1ad
 *     VLAN tags. (Guessing from the first byte would misread every frame whose
 *     destination MAC starts with 0x4_/0x6_ as an IP header.)
 *
 * Counts are GSO-aware: a GRO/TSO super-packet counts as gso_segs packets, and
 * flow bytes are L3 octets (IP header + payload, as IPFIX octetDeltaCount),
 * with the L3/L4 headers re-added for every segment beyond the first.
 *
 * A PERCPU_ARRAY map `obserwrt_stats` tracks aggregate packets/bytes/flow
 * creations exactly (independent of LRU eviction) for Prometheus counters;
 * per-CPU slots keep the hot path free of shared atomics (the agent sums).
 * A PERCPU_HASH `obserwrt_devstats` splits what was seen per device and
 * direction into packet classes (IPv4/IPv6/ARP/other).
 *
 * The map uses the final flow-key/value layouts (see docs/design.md §5); IPv4
 * addresses are stored as IPv4-mapped IPv6 ::ffff:a.b.c.d in the 16-byte fields.
 *
 * A tp_btf/kfree_skb program records packets the kernel DROPS on attached
 * devices (obserwrt_drops, keyed by flow tuple + raw drop reason). It is
 * loaded only when the agent enables drop tracking (§7.1). It reads the
 * dropped packet's headers with bpf_probe_read_kernel, a GPL-only helper,
 * hence the GPL license of this object.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

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

/* Bounded IPv6 extension-header walk (verifier-friendly fixed cap). */
#define MAX_EXT_HDR 8

/* Flow-map capacity. Override at build time via -DFLOW_MAP_ENTRIES
 * (OpenWrt CONFIG_OBSERWRT_FLOW_MAP_ENTRIES); must exceed zero. The map is an
 * LRU hash, so at capacity it evicts rather than failing. */
#ifndef FLOW_MAP_ENTRIES
#define FLOW_MAP_ENTRIES 4096
#endif

/* --- maps ------------------------------------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_MAP_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} obserwrt_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obserwrt_stats SEC(".maps");

/* Per-device, per-direction packet-class counters (§9). Two entries per
 * attached device; the agent deletes them on detach, so the map tracks
 * attached incarnations only. */
#ifndef DEV_MAP_ENTRIES
#define DEV_MAP_ENTRIES 1024
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, DEV_MAP_ENTRIES);
	__type(key, struct dev_key);
	__type(value, struct dev_val);
} obserwrt_devstats SEC(".maps");

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

/* --- helpers --------------------------------------------------------- */

static inline void
stat_add(__u32 idx, __u64 n)
{
	__u64 *c = bpf_map_lookup_elem(&obserwrt_stats, &idx);

	if (c)
		*c += n;   /* per-CPU slot: no atomic needed */
}

/* Packet class (OBSERWRT_CLASS_*): EtherType after up to two VLAN tags on
 * Ethernet, the IP version nibble on L3 devices. Re-reads a few bytes rather
 * than sharing the flow parser's state. */
static __always_inline __u32
pkt_class(struct __sk_buff *skb, int eth)
{
	__u8 *data = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u16 et;

	if (!eth) {
		if (data + 1 > data_end)
			return OBSERWRT_CLASS_OTHER;
		if ((data[0] >> 4) == 4)
			return OBSERWRT_CLASS_IPV4;
		if ((data[0] >> 4) == 6)
			return OBSERWRT_CLASS_IPV6;
		return OBSERWRT_CLASS_OTHER;
	}

	if (data + 14 > data_end)
		return OBSERWRT_CLASS_OTHER;
	et = bpf_ntohs(*(__u16 *)(data + 12));
	if (et == ETH_P_8021Q || et == ETH_P_8021AD || et == 0x9100) {
		if (data + 18 > data_end)
			return OBSERWRT_CLASS_OTHER;
		et = bpf_ntohs(*(__u16 *)(data + 16));
		if (et == ETH_P_8021Q || et == ETH_P_8021AD) {
			if (data + 22 > data_end)
				return OBSERWRT_CLASS_OTHER;
			et = bpf_ntohs(*(__u16 *)(data + 20));
		}
	}

	if (et == ETH_P_IP)
		return OBSERWRT_CLASS_IPV4;
	if (et == ETH_P_IPV6)
		return OBSERWRT_CLASS_IPV6;
	if (et == ETH_P_ARP)
		return OBSERWRT_CLASS_ARP;
	return OBSERWRT_CLASS_OTHER;
}

/* Add one (GSO-aware) packet to its device/direction/class counters.
 *
 * A GLOBAL (non-static, noinline) function on purpose: the verifier checks
 * it once on its own, and the caller only sees "returns a scalar". Inlined,
 * its branches multiply the states the verifier walks through the flow
 * parser, and the eth programs exceed the 1M-instruction limit (E2BIG). */
__attribute__((noinline)) int
obserwrt_dev_count(struct __sk_buff *skb, __u32 direction, int eth, __u32 segs)
{
	struct dev_key k = { 0 };
	struct dev_val *v;
	__u32 cls = pkt_class(skb, eth);

	k.ifindex = skb->ifindex;
	k.direction = direction;

	v = bpf_map_lookup_elem(&obserwrt_devstats, &k);
	if (!v) {
		struct dev_val z = { 0 };

		/* first packet of this device/direction: insert, then re-read
		 * (another CPU may have inserted it concurrently - fine). */
		bpf_map_update_elem(&obserwrt_devstats, &k, &z, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&obserwrt_devstats, &k);
		if (!v)
			return 0;
	}

	cls &= OBSERWRT_CLASS_MAX - 1;   /* bound for the verifier */
	v->packets[cls] += segs;       /* per-CPU slot: no atomic needed */
	v->bytes[cls] += skb->len;
	return 0;
}

/* Store a 4-byte IPv4 address as IPv4-mapped IPv6 (::ffff:a.b.c.d). */
static inline void
ip4_to_in6(__u8 out[16], const __u8 *ip)
{
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, ip, 4);
}

/* Advance `l4` across an IPv6 extension header (not Fragment, which is fixed
 * size and handled by the caller). Returns the new next-header value, or 0 on
 * bound fault. Hdr Ext Len counts 8-octet units beyond the first 8 (RFC 8200
 * §4.3), except AH, which counts 4-octet units minus 2 (RFC 4302 §2.2). */
static inline __u8
ext_next(__u8 *data_end, __u8 **l4, int ah)
{
	__u8 *p = *l4;
	__u8 nh, len;
	__u32 hlen;

	if (p + 8 > data_end)
		return 0;

	nh = p[0];
	len = p[1];
	if (ah)
		hlen = ((__u32)len + 2) << 2;
	else
		hlen = ((__u32)len + 1) << 3;
	*l4 = p + hlen;

	if (*l4 > data_end)
		return 0;

	return nh;
}

/* Outer VLAN id of an Ethernet frame, 0 if untagged. An offloaded (stripped)
 * tag lives in skb metadata and is the outer one; otherwise the first
 * in-packet 802.1Q/802.1ad tag. Read only when a flow is created, not while
 * parsing: carrying it through the parser doubles the verifier's states
 * across the IPv6 extension-header walk. */
static __always_inline __u16
outer_vlan(struct __sk_buff *skb)
{
	__u8 *data = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u16 et;

	if (skb->vlan_present)
		return skb->vlan_tci & 0x0fff;
	if (data + 18 > data_end)
		return 0;
	et = bpf_ntohs(*(__u16 *)(data + 12));
	if (et != ETH_P_8021Q && et != ETH_P_8021AD && et != 0x9100)
		return 0;
	return bpf_ntohs(*(__u16 *)(data + 14)) & 0x0fff;
}

/*
 * Observe a packet seen at `direction` on the device the TC filter is attached
 * to. `eth` (a compile-time constant per program) selects the framing.
 * Aggregates into obserwrt_flows and returns TC_ACT_OK (pass).
 */
static __always_inline int
observe(struct __sk_buff *skb, __u8 direction, const int eth)
{
	__u8 *data = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u8 *ip, *l4;
	__u8  family = 0, proto = 0;
	__u8  icmp_type = 0, icmp_code = 0, tcpf = 0;
	__u16 sport = 0, dport = 0;
	__u32 ihl = 0;
	__u32 frag_off = 0;   /* !=0 means a non-first fragment: no L4 */
	__u32 l4hdr = 0;      /* L4 header bytes repeated in every GSO segment */
	__u32 segs, l3len;
	int have_l4 = 0;

	/* A GRO/TSO super-packet stands for gso_segs wire packets. */
	segs = skb->gso_segs;
	if (segs == 0)
		segs = 1;

	stat_add(STAT_PACKETS, segs);
	stat_add(STAT_BYTES, skb->len);
	obserwrt_dev_count(skb, direction, eth, segs);

	if (data + 2 > data_end)
		return TC_ACT_OK;

	if (!eth) {
		ip = data;                 /* L3 device (awg/gre/tun) */
	} else {
		/* Ethernet: parse EtherType, walk one or two VLAN tags. */
		__u8 *p = data;
		__u16 et;
		__u32 l3off;

		if (p + 14 > data_end)
			return TC_ACT_OK;

		et = bpf_ntohs(*(__u16 *)(p + 12));
		l3off = ETH_HLEN;
		if (et == ETH_P_8021Q || et == ETH_P_8021AD || et == 0x9100) {
			if (p + 18 > data_end)
				return TC_ACT_OK;
			et = bpf_ntohs(*(__u16 *)(p + 16));
			l3off = ETH_HLEN + 4;
			if (et == ETH_P_8021Q || et == ETH_P_8021AD) {
				if (p + 22 > data_end)
					return TC_ACT_OK;
				et = bpf_ntohs(*(__u16 *)(p + 20));
				l3off = ETH_HLEN + 8;
			}
		}

		if (et != ETH_P_IP && et != ETH_P_IPV6)
			return TC_ACT_OK;      /* not IPv4/IPv6 (ARP, PPPoE, ...) */

		ip = data + l3off;
	}

	/* Enough for the IP version nibble; family branches re-check the full
	 * header length below (computed `ip` may sit past the Ethernet+2-VLAN
	 * offset, so this is not covered by the frame-length check above). */
	if (ip + 2 > data_end)
		return TC_ACT_OK;

	/* IP header. */
	if ((ip[0] >> 4) == 4) {
		if (ip + 20 > data_end)
			return TC_ACT_OK;

		family = 4;
		ihl = (__u32)(ip[0] & 0x0f) << 2;
		if (ihl < 20 || ip + ihl > data_end)
			return TC_ACT_OK;
		proto = ip[9];
		l4 = ip + ihl;

		/* Fragment handling: only the first fragment carries a transport
		 * header; non-first fragments are accounted as IP-only flows. */
		frag_off = bpf_ntohs(*(__u16 *)(ip + 6)) & 0x1fff;
		have_l4 = (frag_off == 0);
	} else if ((ip[0] >> 4) == 6) {
		int iter;

		if (ip + 40 > data_end)
			return TC_ACT_OK;

		family = 6;
		proto = ip[6];
		l4 = ip + 40;
		have_l4 = 1;

		/* Bounded extension-header walk (Hop-by-Hop / Routing / Dest-Opts /
		 * Fragment / AH). Fragment: non-first has no L4. */
		for (iter = 0; iter < MAX_EXT_HDR; iter++) {
			if (proto == 0 || proto == 43 || proto == 60 || proto == 51) {
				proto = ext_next(data_end, &l4, proto == 51);
				if (proto == 0)
					return TC_ACT_OK;
			} else if (proto == 44) {      /* fragment header */
				__u8 *fh = l4;

				if (fh + 8 > data_end)
					return TC_ACT_OK;

				frag_off = bpf_ntohs(*(__u16 *)(fh + 2)) >> 3;
				proto = fh[0];
				l4 = fh + 8;
				if (frag_off != 0) {
					have_l4 = 0;         /* non-first fragment */
					break;
				}
			} else if (proto == 59) {
				return TC_ACT_OK;          /* no next header */
			} else {
				break;                     /* proto is a real L4 */
			}
		}
	} else {
		return TC_ACT_OK;
	}

	if (have_l4) {
		/* L4: ports / ICMP type+code / TCP flags.
		 * Unknown protocols (OSPF, GRE, ...) keep sport=dport=icmp=0 and are
		 * still observed, distinguished by protocol in the flow key. */
		if (proto == 6) {                       /* TCP */
			if (l4 + 14 > data_end)
				return TC_ACT_OK;
			sport = bpf_ntohs(*(__u16 *)l4);
			dport = bpf_ntohs(*(__u16 *)(l4 + 2));
			tcpf = *(l4 + 13);
			l4hdr = (__u32)(*(l4 + 12) >> 4) << 2;
		} else if (proto == 17) {               /* UDP */
			if (l4 + 4 > data_end)
				return TC_ACT_OK;
			sport = bpf_ntohs(*(__u16 *)l4);
			dport = bpf_ntohs(*(__u16 *)(l4 + 2));
			l4hdr = 8;
		} else if (proto == 1 || proto == 58) { /* ICMP/ICMPv6 */
			if (l4 + 2 > data_end)
				return TC_ACT_OK;
			icmp_type = *l4;
			icmp_code = *(l4 + 1);
		}
		/* other protocols: no ports/icmp, sport/dport/icmp stay 0 */
	}

	/* Reached the flow accounting path: count as "parsed/accounted". */
	stat_add(STAT_PARSED, segs);

	/* L3 octets: drop the link-layer header, then add back the per-segment
	 * L3(+ext)/L4 headers the GSO super-packet carries only once. */
	l3len = skb->len - (__u32)(ip - data);
	if (segs > 1)
		l3len += (segs - 1) * ((__u32)(l4 - ip) + l4hdr);

	struct flow_key key = { 0 };

	key.ifindex = skb->ifindex;
	key.direction = direction;
	key.family = family;
	key.protocol = proto;

	if (family == 4) {
		ip4_to_in6(key.src, ip + 12);
		ip4_to_in6(key.dst, ip + 16);
	} else {
		__builtin_memcpy(key.src, ip + 8, 16);
		__builtin_memcpy(key.dst, ip + 24, 16);
	}

	key.sport = sport;
	key.dport = dport;
	key.icmp_type = icmp_type;
	key.icmp_code = icmp_code;

	struct flow_val *val = bpf_map_lookup_elem(&obserwrt_flows, &key);

	if (val) {
		__sync_fetch_and_add(&val->packets, segs);
		__sync_fetch_and_add(&val->bytes, l3len);
		val->tcp_flags |= tcpf;   /* union of observed flags */
		val->last_seen = bpf_ktime_get_ns();
	} else {
		struct flow_val nv = { 0 };
		__u64 now = bpf_ktime_get_ns();

		nv.packets = segs;
		nv.bytes = l3len;
		nv.first_seen = now;
		nv.last_seen = now;
		nv.tcp_flags = tcpf;
		if (eth)              /* VLAN is not identity (§4): first packet's */
			nv.vlan_id = outer_vlan(skb);
		if (bpf_map_update_elem(&obserwrt_flows, &key, &nv, BPF_ANY) == 0)
			stat_add(STAT_FLOWS_CREATED, 1);
	}

	return TC_ACT_OK;
}

SEC("classifier/ingress")
int obserwrt_ingress_eth(struct __sk_buff *skb)
{
	return observe(skb, OBSERWRT_INGRESS, 1);
}

SEC("classifier/egress")
int obserwrt_egress_eth(struct __sk_buff *skb)
{
	return observe(skb, OBSERWRT_EGRESS, 1);
}

SEC("classifier/ingress")
int obserwrt_ingress_l3(struct __sk_buff *skb)
{
	return observe(skb, OBSERWRT_INGRESS, 0);
}

SEC("classifier/egress")
int obserwrt_egress_l3(struct __sk_buff *skb)
{
	return observe(skb, OBSERWRT_EGRESS, 0);
}

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
drop_parse(unsigned char *l3, __u16 proto, struct drop_key *dk, __u8 *tcpf)
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
	__u8 tcpf = 0;

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
		l3len = drop_parse(head + nh, proto, &dk, &tcpf);
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
		bpf_map_update_elem(&obserwrt_drops, &dk, &nv, BPF_ANY);
	}
	return 0;
}

/* GPL: the drop tracer needs bpf_probe_read_kernel (GPL-only helper). */
char LICENSE[] SEC("license") = "GPL";
