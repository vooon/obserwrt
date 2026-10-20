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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "bpf.hpp"
#include "drop_reasons.hpp"
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
	int devstats = -1;
	int attached = -1;
	int drops = -1;
	struct bpf_program *drop_prog = nullptr;
};

int run(const Ctx &c, std::vector<uint8_t> &pkt, uint32_t gso_segs)
{
	struct __sk_buff skb;
	std::memset(&skb, 0, sizeof(skb));
	skb.gso_segs = gso_segs;
	skb.gso_size = gso_segs > 1 ? 300 : 0;
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
 * octets with the 40-byte IPv4+TCP headers re-added for segments 2..10.
 * Kept under a page: older kernels reject larger test-run packets (EINVAL). */
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
	p.resize(p.size() + 3000);
	run(c, p, 10);

	flow_val v;
	if (!lookup(c, v4_key(6, s, d, 49153, 443), v)) {
		std::fprintf(stderr, "FAIL %s: flow missing\n", __func__);
		g_failures++;
		return;
	}
	CHECK_EQ(v.packets, 10);
	CHECK_EQ(v.bytes, 3040 + 9 * 40);
	CHECK_EQ(v.tcp_flags, 0x18);
	CHECK_EQ(v.vlan_id, 0); /* untagged */
}

/* 802.1Q-tagged UDP: the parser walks the tag to L3 and records the VID
 * in the value (not the key). */
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
	CHECK_EQ(v.vlan_id, 100);
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

/* A non-IP, non-ARP frame (LLDP): seen, class "other", not accounted. */
void test_lldp(const Ctx &c)
{
	const uint8_t lldp[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
	std::vector<uint8_t> p = eth(lldp, 0x88cc);
	p.resize(p.size() + 50);
	run(c, p, 0);
}

/* PERCPU_ARRAY slots summed over CPUs: 10 + 1 + 1 + 1 + 1 packets seen,
 * the ARP and LLDP frames not accounted, three flows created. */
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
	CHECK_EQ(sum[STAT_PACKETS], 14);
	CHECK_EQ(sum[STAT_PARSED], 12);
	CHECK_EQ(sum[STAT_FLOWS_CREATED], 3);
}

/* Per-device class counters: all frames ran as ingress on ifindex 1. IPv4 =
 * the 10-segment GSO frame + the VLAN-tagged one (classed by the inner
 * EtherType); classes add up to the 14 packets seen. */
void test_dev_counters(const Ctx &c)
{
	std::vector<obserwrt::DevCounters> devs;
	if (!obserwrt::read_dev_counters(c.devstats, devs)) {
		std::fprintf(stderr, "FAIL %s: read_dev_counters: %s\n", __func__,
			     std::strerror(errno));
		g_failures++;
		return;
	}
	CHECK_EQ(devs.size(), 1);
	if (devs.empty())
		return;
	const obserwrt::DevCounters &d = devs[0];
	CHECK_EQ(d.ifindex, 1);
	CHECK_EQ(d.direction, OBSERWRT_INGRESS);
	CHECK_EQ(d.packets[OBSERWRT_CLASS_IPV4], 11);
	CHECK_EQ(d.packets[OBSERWRT_CLASS_IPV6], 1);
	CHECK_EQ(d.packets[OBSERWRT_CLASS_ARP], 1);
	CHECK_EQ(d.packets[OBSERWRT_CLASS_OTHER], 1);
	CHECK_EQ(d.bytes[OBSERWRT_CLASS_ARP], 14 + 28);
	CHECK_EQ(d.bytes[OBSERWRT_CLASS_OTHER], 14 + 50);
}

/* The agent's batched map walk returns every flow with its value. */
void test_read_flows(const Ctx &c)
{
	std::vector<flow_key> keys;
	std::vector<flow_val> values;
	if (!obserwrt::read_flows(c.flows, keys, values)) {
		std::fprintf(stderr, "FAIL %s: read_flows: %s\n", __func__, std::strerror(errno));
		g_failures++;
		return;
	}
	CHECK_EQ(keys.size(), 3);
	CHECK_EQ(values.size(), keys.size());
	for (size_t i = 0; i < keys.size() && i < values.size(); i++) {
		flow_val v;
		if (!lookup(c, keys[i], v)) {
			std::fprintf(stderr, "FAIL %s: key %zu not in map\n", __func__, i);
			g_failures++;
			continue;
		}
		CHECK_EQ(values[i].packets, v.packets);
		CHECK_EQ(values[i].bytes, v.bytes);
	}
}

/* A real kernel drop: UDP to a closed port on 127.0.0.1 is freed with
 * SKB_DROP_REASON_NO_SOCKET on lo (ifindex 1, received there -> ingress).
 * The tracer must record it with the 5-tuple and the raw reason, which the
 * agent resolves by name from kernel BTF. */
void test_drops(const Ctx &c)
{
	const uint32_t lo = 1;
	const uint8_t one = 1;
	if (bpf_map_update_elem(c.attached, &lo, &one, BPF_ANY) != 0) {
		std::fprintf(stderr, "FAIL %s: attached map: %s\n", __func__, std::strerror(errno));
		g_failures++;
		return;
	}
	struct bpf_link *link = bpf_program__attach(c.drop_prog);
	if (!link) {
		std::fprintf(stderr, "FAIL %s: attach tp_btf: %s\n", __func__,
			     std::strerror(errno));
		g_failures++;
		return;
	}

	/* Find a free port: bind, read it back, close (nothing listens after). */
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t al = sizeof(a);
	const int probe = socket(AF_INET, SOCK_DGRAM, 0);
	bind(probe, reinterpret_cast<sockaddr *>(&a), sizeof(a));
	getsockname(probe, reinterpret_cast<sockaddr *>(&a), &al);
	close(probe);
	const uint16_t port = ntohs(a.sin_port);

	const int s = socket(AF_INET, SOCK_DGRAM, 0);
	const char msg[32] = "obserwrt drop test";
	for (int i = 0; i < 3; i++)
		sendto(s, msg, sizeof(msg), 0, reinterpret_cast<sockaddr *>(&a), sizeof(a));
	close(s);
	usleep(100000);
	bpf_link__destroy(link);

	obserwrt::DropReasons reasons;
	std::string err;
	CHECK_EQ(reasons.load(&err), true);

	std::vector<obserwrt::DropKey> keys;
	std::vector<obserwrt::FlowValue> vals;
	if (!obserwrt::drain_drops(c.drops, keys, vals)) {
		std::fprintf(stderr, "FAIL %s: drain_drops: %s\n", __func__, std::strerror(errno));
		g_failures++;
		return;
	}
	bool found = false;
	for (size_t i = 0; i < keys.size(); i++) {
		const flow_key &k = keys[i].flow;
		if (k.protocol != 17 || k.dport != port)
			continue;
		found = true;
		CHECK_EQ(k.ifindex, 1);
		CHECK_EQ(k.direction, OBSERWRT_INGRESS);
		CHECK_EQ(k.family, 4);
		CHECK_EQ(k.dst[15], 1); /* 127.0.0.1 */
		CHECK_EQ(vals[i].packets, 3);
		CHECK_EQ(vals[i].bytes, 3 * (20 + 8 + 32));
		const auto r = reasons.lookup(keys[i].reason);
		if (r.name != "NO_SOCKET") {
			std::fprintf(stderr, "FAIL %s: reason %s, want NO_SOCKET\n", __func__,
				     r.name.c_str());
			g_failures++;
		}
	}
	if (!found) {
		std::fprintf(stderr, "FAIL %s: no drop record for udp/%u (%zu records)\n", __func__,
			     port, keys.size());
		g_failures++;
	}

	/* drained: a second pass sees nothing for this flow. */
	obserwrt::drain_drops(c.drops, keys, vals);
	for (const auto &k : keys)
		if (k.flow.protocol == 17 && k.flow.dport == port) {
			std::fprintf(stderr, "FAIL %s: drop map not drained\n", __func__);
			g_failures++;
		}
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
		/* The TC classifiers only; the tp_btf drop tracer keeps its type. */
		if (std::strncmp(bpf_program__section_name(prog), "classifier", 10) == 0)
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
	c.devstats = bpf_object__find_map_fd_by_name(obj, "obserwrt_devstats");
	c.attached = bpf_object__find_map_fd_by_name(obj, "obserwrt_attached");
	c.drops = bpf_object__find_map_fd_by_name(obj, "obserwrt_drops");
	c.drop_prog = bpf_object__find_program_by_name(obj, "obserwrt_kfree_skb");
	if (c.ingress < 0 || c.flows < 0 || c.stats < 0 || c.devstats < 0 || c.attached < 0 ||
	    c.drops < 0 || !c.drop_prog) {
		std::fprintf(stderr, "obserwrt-bpf.o: missing program/map\n");
		bpf_object__close(obj);
		return 2;
	}

	test_eth_tcp_gso(c);
	test_vlan_udp(c);
	test_ipv6_hbh(c);
	test_arp(c);
	test_lldp(c);
	test_stats(c);
	test_dev_counters(c);
	test_drops(c);
	test_read_flows(c);
	bpf_object__close(obj);

	if (g_failures != 0) {
		std::fprintf(stderr, "bpf_run: %d failures\n", g_failures);
		return 1;
	}
	std::printf("bpf_run: all eBPF checks passed\n");
	return 0;
}
