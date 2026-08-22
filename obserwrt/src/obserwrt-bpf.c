/* obserwrt - P0 TC visibility probe.
 *
 * Two tiny TC classifier programs (ingress + egress) that parse the L3 header
 * of every packet and count (ifindex, direction, family, protocol). This is the
 * P0 feasibility probe: proving that TC actually observes the decrypted
 * traffic on the selected netdev before any flow tracking / exporters are built.
 *
 * Program type is BPF_PROG_TYPE_SCHED_CLS, inferred by libbpf from the
 * "classifier/..." section names. Both programs share one LRU hash map. The map
 * uses the full final flow-key/value layouts (see docs/design.md §5) so later
 * milestones do not need to change the wire/struct format; P0 only populates
 * ifindex/direction/family/protocol (addresses and ports are left zero).
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
	__u16 sport;     /* 40 */
	__u16 dport;     /* 42 */
} __attribute__((packed));

struct flow_val {
	__u64 packets;    /*  0 */
	__u64 bytes;      /*  8 */
	__u64 first_seen; /* 16 */
	__u64 last_seen;  /* 24 */
	__u8  tcp_flags;  /* 32 */
	/* natural alignment: sizeof == 40 (33 + 7 pad) */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} obs_flows SEC(".maps");

/* --- packet helpers --------------------------------------------------- */

/*
 * Observe a packet seen at `direction` on the device the TC filter is attached
 * to.
 *
 * Framing: L3 devices (WireGuard/AmneziaWG tun, ARPHRD_NONE) hand the skb to TC
 * with `data` pointing at the IP header (no link layer). Ethernet devices have
 * a 14-byte link-layer header in front. We detect which by checking the IP
 * version nibble at the start of the data vs at data+14.
 */
static int
observe(struct __sk_buff *skb, __u8 direction)
{
	__u8 *data = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u8  family = 0, proto = 0;

	/* Enough to peek both `data` and `data + 14` framings. */
	if (data + 16 > data_end)
		return TC_ACT_OK;

	if ((data[0] >> 4) == 4) {
		/* L3 device, IPv4 */
		family = 4;
		if (data + 10 > data_end)
			return TC_ACT_OK;
		proto = data[9];
	}
	else if ((data[0] >> 4) == 6) {
		/* L3 device, IPv6 */
		family = 6;
		if (data + 7 > data_end)
			return TC_ACT_OK;
		proto = data[6];
	}
	else if ((data[14] >> 4) == 4) {
		/* Ethernet, IPv4 */
		family = 4;
		if (data + 24 > data_end)
			return TC_ACT_OK;
		proto = data[23];
	}
	else if ((data[14] >> 4) == 6) {
		/* Ethernet, IPv6 */
		family = 6;
		if (data + 21 > data_end)
			return TC_ACT_OK;
		proto = data[20];
	}
	else {
		return TC_ACT_OK;
	}

	struct flow_key key = { 0 };

	key.ifindex = skb->ifindex;
	key.direction = direction;
	key.family = family;
	key.protocol = proto;

	struct flow_val *val = obserw_bpf_map_lookup_elem(&obs_flows, &key);

	if (val) {
		__sync_fetch_and_add(&val->packets, 1);
		__sync_fetch_and_add(&val->bytes, skb->len);
		val->last_seen = obserw_bpf_ktime_get_ns();
	} else {
		struct flow_val nv = { 0 };
		__u64 now = obserw_bpf_ktime_get_ns();

		nv.packets = 1;
		nv.bytes = skb->len;
		nv.first_seen = now;
		nv.last_seen = now;
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