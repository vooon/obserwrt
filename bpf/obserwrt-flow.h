/*
 * obserwrt - BPF flow-map key/value layouts (obserwrt-flow.h)
 *
 * Single source for the flow key/value wire formats (docs/design.md §5),
 * shared by BOTH the eBPF program (obserwrt-bpf.c) and the C++ agent
 * (flow.hpp). Native byte order on the local machine - the map is written
 * and read on the same host, so there is no byte-swapping anywhere.
 *
 * Address bytes are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d) for IPv4.
 *
 * Types are the kernel-style __uN (linux/types.h): that header is already a
 * build dependency on both sides (libbpf for the agent, the uapi shim for the
 * BPF object) and avoids pulling libc stdint into the -target bpf compile.
 */

#ifndef OBSERWRT_FLOW_H
#define OBSERWRT_FLOW_H

#include <linux/types.h>

#ifdef __cplusplus
#define OBSERWRT_FLOW_ASSERT(e) static_assert(e, #e)
#else
#define OBSERWRT_FLOW_ASSERT(e) _Static_assert(e, #e)
#endif

/* Direction at the observation point. */
#define OBSERWRT_INGRESS 0
#define OBSERWRT_EGRESS 1

/* Flow key (46 bytes, packed, native endian) - §5.1. */
struct flow_key {
	__u32 ifindex;   /*  0 */
	__u8  direction; /*  4 */
	__u8  family;    /*  5 */
	__u8  protocol;  /*  6 */
	__u8  reserved;  /*  7 */
	__u8  src[16];   /*  8 */
	__u8  dst[16];   /* 24 */
	__u16 sport;     /* 40 */
	__u16 dport;     /* 42 */
	__u8  icmp_type; /* 44 */
	__u8  icmp_code; /* 45 */
} __attribute__((packed));

/* Flow value (40 bytes, native endian) - §5.2. NOT packed: the 8-byte
 * counters need natural alignment for in-kernel atomic increments; the 6
 * trailing bytes of padding complete sizeof() == 40. */
struct flow_val {
	__u64 packets;    /*  0 */
	__u64 bytes;      /*  8 */
	__u64 first_seen; /* 16 */
	__u64 last_seen;  /* 24 */
	__u16 tcp_flags;  /* 32 */
};

OBSERWRT_FLOW_ASSERT(sizeof(struct flow_key) == 46);
OBSERWRT_FLOW_ASSERT(sizeof(struct flow_val) == 40);

#endif /* OBSERWRT_FLOW_H */