/* obserwrt - TC classifier flow observation (P0/P1).
 *
 * Two TC classifier programs (ingress + egress) share one LRU hash map. For each
 * packet they parse the L3/L4 headers and aggregate a flow keyed by
 * (ifindex, direction, family, protocol, src, dst, sport, dport, icmp type/code).
 *
 * Program type is BPF_PROG_TYPE_SCHED_CLS (forced via ucode program-type; libbpf
 * 1.6 no longer infers it from "classifier/<sub>").
 *
 * Framing:
 *   - L3 devices (WireGuard/AmneziaWG tun, ARPHRD_NONE) hand the skb to TC with
 *     `data` pointing directly at the IP header (no link layer). Detected by the
 *     IP version nibble at data[0].
 *   - Ethernet devices have a 14-byte link-layer header; the L3 offset is found
 *     by parsing the EtherType, walking one or two 802.1Q/802.1ad VLAN tags.
 *
 * A per-cpu-free ARRAY map `obserwrt_stats` tracks aggregate packets/bytes/flow
 * creations exactly (independent of LRU eviction) for Prometheus counters.
 *
 * The map uses the final flow-key/value layouts (see docs/design.md §5); IPv4
 * addresses are stored as IPv4-mapped IPv6 ::ffff:a.b.c.d in the 16-byte fields.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Direction at the observation point. */
enum direction {
	INGRESS = 0,
	EGRESS  = 1,
};

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

struct flow_key {
	__u32 ifindex;   /*  0 */
	__u8  direction; /*  4 0=ingress, 1=egress */
	__u8  family;    /*  5 4|6 */
	__u8  protocol;  /*  6 IP protocol number */
	__u8  reserved;  /*  7 */
	__u8  src[16];   /*  8 IPv4 as ::ffff:a.b.c.d */
	__u8  dst[16];   /* 24 */
	__u16 sport;     /* 40 0 for ICMP */
	__u16 dport;     /* 42 0 for ICMP */
	__u8  icmp_type; /* 44 */
	__u8  icmp_code; /* 45 */
} __attribute__((packed));

struct flow_val {
	__u64 packets;    /*  0 */
	__u64 bytes;      /*  8 */
	__u64 first_seen; /* 16 */
	__u64 last_seen;  /* 24 */
	__u16 tcp_flags;  /* 32 16-bit tcpControlBits (only low 8 standard flags) */
	/* natural alignment -> sizeof == 40 */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_MAP_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} obserwrt_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obserwrt_stats SEC(".maps");

/* --- helpers --------------------------------------------------------- */

static inline void
stat_add(__u32 idx, __u64 n)
{
	__u64 *c = bpf_map_lookup_elem(&obserwrt_stats, &idx);

	if (c)
		__sync_fetch_and_add(c, n);
}

/* Store a 4-byte IPv4 address as IPv4-mapped IPv6 (::ffff:a.b.c.d). */
static inline void
ip4_to_in6(__u8 out[16], const __u8 *ip)
{
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, ip, 4);
}

/* Advance `l4` across an IPv6 extension header. Returns the new next-header
 * value, or 0 on bound fault. `hdrlen` is the header's `len` field (for the
 * fixed-size fragment header this is ignored/excluded). */
static inline __u8
ext_next(__u8 *data_end, __u8 **l4)
{
	__u8 *p = *l4;
	__u8 nh, len;
	__u32 hlen;

	if (p + 8 > data_end)
		return 0;

	nh = p[0];
	len = p[1];
	hlen = 8 + ((__u32)(len + 1) << 3);   /* length field excludes the first 8 */
	*l4 = p + hlen;

	if (*l4 > data_end)
		return 0;

	return nh;
}

/*
 * Observe a packet seen at `direction` on the device the TC filter is attached
 * to. Aggregates into obserwrt_flows and returns TC_ACT_OK (pass).
 */
static int
observe(struct __sk_buff *skb, __u8 direction)
{
	__u8 *data = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u8 *ip, *l4;
	__u8  family = 0, proto = 0;
	__u8  icmp_type = 0, icmp_code = 0, tcpf = 0;
	__u16 sport = 0, dport = 0;
	__u32 ihl = 0;
	__u32 frag_off = 0;   /* !=0 means a non-first fragment: no L4 */
	int have_l4 = 0;

	stat_add(STAT_PACKETS, 1);
	stat_add(STAT_BYTES, skb->len);

	if (data + 2 > data_end)
		return TC_ACT_OK;

	/* Framing detection. */
	if ((data[0] >> 4) == 4 || (data[0] >> 4) == 6) {
		ip = data;                 /* L3 device (tun/awg) */
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
				proto = ext_next(data_end, &l4);
				if (proto == 0)
					return TC_ACT_OK;
			} else if (proto == 44) {      /* fragment header */
				__u8 *fh = l4;
				__u16 fi;

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
		} else if (proto == 17) {               /* UDP */
			if (l4 + 4 > data_end)
				return TC_ACT_OK;
			sport = bpf_ntohs(*(__u16 *)l4);
			dport = bpf_ntohs(*(__u16 *)(l4 + 2));
		} else if (proto == 1 || proto == 58) { /* ICMP/ICMPv6 */
			if (l4 + 2 > data_end)
				return TC_ACT_OK;
			icmp_type = *l4;
			icmp_code = *(l4 + 1);
		}
		/* other protocols: no ports/icmp, sport/dport/icmp stay 0 */
	}

	/* Reached the flow accounting path: count as "parsed/accounted". */
	stat_add(STAT_PARSED, 1);

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
		__sync_fetch_and_add(&val->packets, 1);
		__sync_fetch_and_add(&val->bytes, skb->len);
		val->tcp_flags |= tcpf;   /* union of observed flags */
		val->last_seen = bpf_ktime_get_ns();
	} else {
		struct flow_val nv = { 0 };
		__u64 now = bpf_ktime_get_ns();

		nv.packets = 1;
		nv.bytes = skb->len;
		nv.first_seen = now;
		nv.last_seen = now;
		nv.tcp_flags = tcpf;
		if (bpf_map_update_elem(&obserwrt_flows, &key, &nv, BPF_ANY) == 0)
			stat_add(STAT_FLOWS_CREATED, 1);
	}

	return TC_ACT_OK;
}

SEC("classifier/ingress")
int obserwrt_ingress(struct __sk_buff *skb)
{
	return observe(skb, INGRESS);
}

SEC("classifier/egress")
int obserwrt_egress(struct __sk_buff *skb)
{
	return observe(skb, EGRESS);
}

char LICENSE[] SEC("license") = "Apache-2.0";