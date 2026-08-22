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
 *     `data` pointing directly at the IP header (no link layer).
 *   - Ethernet devices have a 14-byte link-layer header in front.
 * We detect which by checking the IP version nibble at data[0] vs data[14].
 *
 * The map uses the final flow-key/value layouts (see docs/design.md §5); IPv4
 * addresses are stored as IPv4-mapped IPv6 ::ffff:a.b.c.d in the 16-byte fields.
 */
#include "bpf_helpers.h"

/* --- flow key / value (match docs/design.md §5) ---------------------- */

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
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} obs_flows SEC(".maps");

/* --- packet helpers --------------------------------------------------- */

/* Read a big-endian u16 from a packet buffer. */
static inline __u16
rd_be16(const void *p)
{
	const __u8 *b = p;

	return (__u16)((__u16)b[0] << 8 | b[1]);
}

/* Store a 4-byte IPv4 address as IPv4-mapped IPv6 (::ffff:a.b.c.d). */
static inline void
ip4_to_in6(__u8 out[16], const __u8 *ip)
{
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, ip, 4);
}

/*
 * Observe a packet seen at `direction` on the device the TC filter is attached
 * to. Aggregates into obs_flows and returns TC_ACT_OK (pass).
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

	/* Enough to peek the IP version nibble at data[0] AND data[14]. */
	if (data + 15 > data_end)
		return TC_ACT_OK;

	/* Framing detection. */
	if ((data[0] >> 4) == 4 || (data[0] >> 4) == 6)
		ip = data;                 /* L3 device */
	else if ((data[14] >> 4) == 4 || (data[14] >> 4) == 6)
		ip = data + 14;            /* Ethernet */
	else
		return TC_ACT_OK;

	/* IP header. */
	if ((ip[0] >> 4) == 4) {
		if (ip + 20 > data_end)
			return TC_ACT_OK;

		family = 4;
		ihl = (__u32)(ip[0] & 0x0f) << 2;
		proto = ip[9];
		l4 = ip + ihl;
	} else if ((ip[0] >> 4) == 6) {
		if (ip + 40 > data_end)
			return TC_ACT_OK;

		family = 6;
		proto = ip[6];
		l4 = ip + 40;
	} else {
		return TC_ACT_OK;
	}

	/* L4: ports / ICMP / TCP flags. */
	if (proto == 6) {                       /* TCP */
		if (l4 + 14 > data_end)
			return TC_ACT_OK;

		sport = rd_be16(l4);
		dport = rd_be16(l4 + 2);
		tcpf = *(l4 + 13);
	} else if (proto == 17) {               /* UDP */
		if (l4 + 4 > data_end)
			return TC_ACT_OK;

		sport = rd_be16(l4);
		dport = rd_be16(l4 + 2);
	} else if (proto == 1 || proto == 58) { /* ICMP/ICMPv6 */
		if (l4 + 2 > data_end)
			return TC_ACT_OK;

		icmp_type = *l4;
		icmp_code = *(l4 + 1);
	} else {
		/* no L4 ports (e.g. OSPF/GRE); flow key still distinct by proto */
		return TC_ACT_OK;
	}

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

	struct flow_val *val = obserw_bpf_map_lookup_elem(&obs_flows, &key);

	if (val) {
		__sync_fetch_and_add(&val->packets, 1);
		__sync_fetch_and_add(&val->bytes, skb->len);
		val->tcp_flags |= tcpf;   /* union of observed flags */
		val->last_seen = obserw_bpf_ktime_get_ns();
	} else {
		struct flow_val nv = { 0 };
		__u64 now = obserw_bpf_ktime_get_ns();

		nv.packets = 1;
		nv.bytes = skb->len;
		nv.first_seen = now;
		nv.last_seen = now;
		nv.tcp_flags = tcpf;
		obserw_bpf_map_update_elem(&obs_flows, &key, &nv, BPF_ANY);
	}

	return TC_ACT_OK;
}

SEC("classifier/ingress")
int obserwrt_ingress(struct __sk_buff *skb)
{
	return observe(skb, 0);
}

SEC("classifier/egress")
int obserwrt_egress(struct __sk_buff *skb)
{
	return observe(skb, 1);
}

char LICENSE[] SEC("license") = "Apache-2.0";