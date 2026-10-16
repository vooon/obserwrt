/*
 * obserwrt - eBPF behaviour test (tests/bpf_run.cpp)
 *
 * Loads obserwrt-bpf.o (no attach) and feeds crafted frames to the *_eth
 * programs via BPF_PROG_TEST_RUN, then checks the flow map and the per-CPU
 * stats. Covers what the golden harness cannot: the in-kernel parser and
 * counters (design §4 framing/parsing, §7 GSO/L3 octets, §9 stats).
 *
 * Needs CAP_BPF (root): exits 77 (ctest SKIP_RETURN_CODE) when the object
 * cannot be loaded for lack of privilege. CI runs it under sudo.
 *
 * The *_l3 programs are not exercised: test-run always prepends an Ethernet
 * header for SCHED_CLS, so a bare IP packet cannot be presented.
 *
 *   obserwrt-bpf-run <obserwrt-bpf.o>
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "flow.hpp"

static int g_failures = 0;

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		if (!((a) == (b))) {                                                               \
			std::fprintf(stderr, "FAIL %s:%d: %s (%lld) != %s (%lld)\n", __FILE__,     \
				     __LINE__, #a, (long long)(a), #b, (long long)(b));            \
			g_failures++;                                                              \
		}                                                                                  \
	} while (0)

namespace
{

enum { STAT_PACKETS, STAT_BYTES, STAT_FLOWS_CREATED, STAT_PARSED };

struct Ctx {
	int ingress = -1;
	int flows = -1;
	int stats = -1;
};

int run(const Ctx &c, std::vector<uint8_t> &pkt, uint32_t gso_segs)
{
	struct __sk_buff skb;
	std::memset(&skb, 0, sizeof(skb));
	skb.gso_segs = gso_segs;
	skb.gso_size = gso_segs > 1 ? 1000 : 0;
	LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = pkt.data(),
		    .data_size_in = static_cast<uint32_t>(pkt.size()), .ctx_in = &skb,
		    .ctx_size_in = sizeof(skb), .repeat = 1);
	const int r = bpf_prog_test_run_opts(c.ingress, &o);
	if (r != 0)
		std::fprintf(stderr, "test_run: %s\n", std::strerror(errno));
	return r;
}

/* Ethernet header: dst, a fixed src, and the EtherType (optionally tagged). */
std::vector<uint8_t> eth(const uint8_t dst[6], uint16_t ethertype, int vlan = -1)
{
	std::vector<uint8_t> p(dst, dst + 6);
	const uint8_t src[6] = {0x02, 0, 0, 0, 0, 0x01};
	p.insert(p.end(), src, src + 6);
	if (vlan >= 0) {
		p.push_back(0x81);
		p.push_back(0x00);
		p.push_back(static_cast<uint8_t>(vlan >> 8));
		p.push_back(static_cast<uint8_t>(vlan));
	}
	p.push_back(static_cast<uint8_t>(ethertype >> 8));
	p.push_back(static_cast<uint8_t>(ethertype));
	return p;
}

void ipv4(std::vector<uint8_t> &p, uint8_t proto, const uint8_t s[4], const uint8_t d[4])
{
	uint8_t h[20] = {0x45};
	h[8] = 64;
	h[9] = proto;
	std::memcpy(h + 12, s, 4);
	std::memcpy(h + 16, d, 4);
	p.insert(p.end(), h, h + 20);
}

flow_key v4_key(uint8_t proto, const uint8_t s[4], const uint8_t d[4], uint16_t sport,
		uint16_t dport)
{
	flow_key k;
	std::memset(&k, 0, sizeof(k));
	k.ifindex = 1; /* test-run skbs sit on loopback */
	k.direction = OBSERWRT_INGRESS;
	k.family = 4;
	k.protocol = proto;
	k.src[10] = k.src[11] = k.dst[10] = k.dst[11] = 0xff;
	std::memcpy(k.src + 12, s, 4);
	std::memcpy(k.dst + 12, d, 4);
	k.sport = sport;
	k.dport = dport;
	return k;
}

bool lookup(const Ctx &c, const flow_key &k, flow_val &v)
{
	return bpf_map_lookup_elem(c.flows, &k, &v) == 0;
}

/* Frame to a 4x: destination MAC: the first byte must not be taken for an IP
 * version nibble. TCP as a 10-segment GSO super-packet: 10 packets, and L3
 * octets with the 40-byte IPv4+TCP headers re-added for segments 2..10. */
void test_eth_tcp_gso(const Ctx &c)
{
	const uint8_t dmac[6] = {0x46, 0x11, 0x22, 0x33, 0x44, 0x55};
	const uint8_t s[4] = {192, 0, 2, 1}, d[4] = {198, 51, 100, 2};
	std::vector<uint8_t> p = eth(dmac, 0x0800);
	ipv4(p, 6, s, d);
	uint8_t tcp[20] = {0xc0, 0x01, 0x01, 0xbb}; /* 49153 -> 443 */
	tcp[12] = 5 << 4;
	tcp[13] = 0x18; /* PSH|ACK */
	p.insert(p.end(), tcp, tcp + 20);
	p.resize(p.size() + 10000);
	run(c, p, 10);

	flow_val v;
	if (!lookup(c, v4_key(6, s, d, 49153, 443), v)) {
		std::fprintf(stderr, "FAIL %s: flow missing\n", __func__);
		g_failures++;
		return;
	}
	CHECK_EQ(v.packets, 10);
	CHECK_EQ(v.bytes, 10040 + 9 * 40);
	CHECK_EQ(v.tcp_flags, 0x18);
}

/* 802.1Q-tagged UDP: the parser walks the tag to L3. */
void test_vlan_udp(const Ctx &c)
{
	const uint8_t dmac[6] = {0x02, 0xaa, 0, 0, 0, 0x02};
	const uint8_t s[4] = {192, 0, 2, 3}, d[4] = {198, 51, 100, 4};
	std::vector<uint8_t> p = eth(dmac, 0x0800, 100);
	ipv4(p, 17, s, d);
	const uint8_t udp[8] = {0x12, 0x34, 0x00, 0x35}; /* 4660 -> 53 */
	p.insert(p.end(), udp, udp + 8);
	p.resize(p.size() + 100);
	run(c, p, 0);

	flow_val v;
	if (!lookup(c, v4_key(17, s, d, 4660, 53), v)) {
		std::fprintf(stderr, "FAIL %s: flow missing\n", __func__);
		g_failures++;
		return;
	}
	CHECK_EQ(v.packets, 1);
	CHECK_EQ(v.bytes, 20 + 8 + 100);
}

/* IPv6 Hop-by-Hop (Hdr Ext Len 0 = 8 bytes) in front of an ICMPv6 MLDv2
 * report (type 143), the MLD shape. */
void test_ipv6_hbh(const Ctx &c)
{
	const uint8_t dmac[6] = {0x33, 0x33, 0, 0, 0, 0x16};
	std::vector<uint8_t> p = eth(dmac, 0x86dd);
	uint8_t h[40] = {0x60};
	h[5] = 16; /* payload: HBH 8 + ICMPv6 8 */
	h[6] = 0;  /* next: Hop-by-Hop */
	h[7] = 1;
	h[8] = 0xfe;
	h[9] = 0x80;
	h[24] = 0xff;
	h[25] = 0x02;
	h[39] = 0x16;
	p.insert(p.end(), h, h + 40);
	const uint8_t hbh[8] = {58, 0}; /* next: ICMPv6 */
	p.insert(p.end(), hbh, hbh + 8);
	const uint8_t icmp[8] = {143};
	p.insert(p.end(), icmp, icmp + 8);
	run(c, p, 0);

	flow_key k;
	std::memset(&k, 0, sizeof(k));
	k.ifindex = 1;
	k.direction = OBSERWRT_INGRESS;
	k.family = 6;
	k.protocol = 58;
	std::memcpy(k.src, h + 8, 16);
	std::memcpy(k.dst, h + 24, 16);
	k.icmp_type = 143;
	flow_val v;
	if (!lookup(c, k, v)) {
		std::fprintf(stderr, "FAIL %s: flow missing\n", __func__);
		g_failures++;
		return;
	}
	CHECK_EQ(v.bytes, 40 + 8 + 8);
}

/* ARP is seen but not accounted. */
void test_arp(const Ctx &c)
{
	const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	std::vector<uint8_t> p = eth(bcast, 0x0806);
	p.resize(p.size() + 28);
	run(c, p, 0);
}

/* PERCPU_ARRAY slots summed over CPUs: 10 + 1 + 1 + 1 packets seen,
 * the ARP frame not accounted, three flows created. */
void test_stats(const Ctx &c)
{
	const int ncpu = libbpf_num_possible_cpus();
	std::vector<uint64_t> slots(ncpu > 0 ? static_cast<size_t>(ncpu) : 1);
	uint64_t sum[4] = {};
	for (uint32_t i = 0; i < 4; i++) {
		if (bpf_map_lookup_elem(c.stats, &i, slots.data()) != 0)
			continue;
		for (const uint64_t s : slots)
			sum[i] += s;
	}
	CHECK_EQ(sum[STAT_PACKETS], 13);
	CHECK_EQ(sum[STAT_PARSED], 12);
	CHECK_EQ(sum[STAT_FLOWS_CREATED], 3);
}

} /* namespace */

int main(int argc, char **argv)
{
	if (argc != 2) {
		std::fprintf(stderr, "usage: %s <obserwrt-bpf.o>\n", argv[0]);
		return 2;
	}
	struct bpf_object *obj = bpf_object__open_file(argv[1], nullptr);
	if (!obj) {
		std::fprintf(stderr, "open %s: %s\n", argv[1], std::strerror(errno));
		return 2;
	}
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj)
	{
		bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
	}
	if (bpf_object__load(obj) != 0) {
		const int e = errno;
		bpf_object__close(obj);
		if (e == EPERM || e == EACCES) {
			std::fprintf(stderr, "bpf_run: no CAP_BPF, skipping\n");
			return 77;
		}
		std::fprintf(stderr, "load: %s\n", std::strerror(e));
		return 2;
	}

	Ctx c;
	c.ingress = bpf_program__fd(bpf_object__find_program_by_name(obj, "obserwrt_ingress_eth"));
	c.flows = bpf_object__find_map_fd_by_name(obj, "obserwrt_flows");
	c.stats = bpf_object__find_map_fd_by_name(obj, "obserwrt_stats");
	if (c.ingress < 0 || c.flows < 0 || c.stats < 0) {
		std::fprintf(stderr, "obserwrt-bpf.o: missing program/map\n");
		bpf_object__close(obj);
		return 2;
	}

	test_eth_tcp_gso(c);
	test_vlan_udp(c);
	test_ipv6_hbh(c);
	test_arp(c);
	test_stats(c);
	bpf_object__close(obj);

	if (g_failures != 0) {
		std::fprintf(stderr, "bpf_run: %d failures\n", g_failures);
		return 1;
	}
	std::printf("bpf_run: all eBPF checks passed\n");
	return 0;
}
