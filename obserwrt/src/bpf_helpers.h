/* Minimal self-contained helpers for obserwrt BPF programs.
 *
 * Deliberately does NOT include kernel UAPI headers. obserwrt runs a simple
 * TC classifier and needs only a handful of helper ids and type shims, so we
 * declare them here directly. This keeps the program compilable with a plain
 * `clang -target bpfel|bpfeb -O2 -g` (as the CI smoke does) without depending
 * on a specific tree of bpf-headers.
 *
 * The ctx type is `struct __sk_buff` (Linux UAPI linux/bpf.h). Only the
 * leading fields up to data_end are declared; the packet-data pointers
 * `data`/`data_end` must sit at their fixed UAPI offsets (76/80), which the
 * kernel's verifier maps for BPF_PROG_TYPE_SCHED_CLS.
 */
#ifndef __OBSERWRT_BPF_HELPERS__
#define __OBSERWRT_BPF_HELPERS__

typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;

/* Endian-aware byte-swap (network <-> host) using the compiler builtin, so it
 * is a compile-time no-op on big-endian targets and a bswap on little-endian.
 * (OpenWrt's bpf.mk compiles in kernel mode where <linux/bpf.h> is the kernel
 * header, so we define these here instead.) */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#endif

#define SEC(name) __attribute__((section(name), used))

/* BTF map definition macros (libbpf-compatible). */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* bpf_map_type (uapi) values used by obserwrt. */
enum bpf_map_type_upi {
	BPF_MAP_TYPE_LRU_HASH = 9,
};

/* bpf_attr flags used by obserwrt. */
#define BPF_ANY              0UL
#define BPF_F_NO_PREALLOC    (1UL << 0)

/* TC return codes. */
#define TC_ACT_OK  0

/* BPF helper ids (uapi enum bpf_func_id). */
enum bpf_func_id_upi {
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_ktime_get_ns    = 5,
};

static void *(*obserw_bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*obserw_bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*obserw_bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

/* struct __sk_buff (partial, up to data_end) as seen by SCHED_CLS programs.
 * Field offsets are the fixed Linux UAPI offsets.
 */
struct __sk_buff {
	__u32 len;              /*  0 */
	__u32 pkt_type;         /*  4 */
	__u32 mark;             /*  8 */
	__u32 queue_mapping;    /* 12 */
	__u32 protocol;         /* 16 */
	__u32 vlan_present;     /* 20 */
	__u32 vlan_tci;         /* 24 */
	__u32 vlan_proto;       /* 28 */
	__u32 priority;         /* 32 */
	__u32 ingress_ifindex;  /* 36 */
	__u32 ifindex;          /* 40 */
	__u32 tc_index;         /* 44 */
	__u32 cb[5];            /* 48 */
	__u32 hash;             /* 68 */
	__u32 tc_classid;       /* 72 */
	__u32 data;             /* 76 */
	__u32 data_end;         /* 80 */
	__u32 napi_id;          /* 84 */
};

#endif /* __OBSERWRT_BPF_HELPERS__ */