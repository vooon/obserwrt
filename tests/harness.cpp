/*
 * obserwrt - golden-vector parity harness (tests/harness.cpp)
 *
 * Locks the C++ implementation to the wire-format expectations that were
 * validated against the deprecated ucode agent (its fw4 test suite). The
 * expectations here are byte/memory equivalents of the pinned ucode tests:
 *   - obserwrt/tests/01_exporter/01_ipfix_wire_encoding
 *   - obserwrt/tests/04_lifecycle/01_delta
 * plus the §5 key/value layouts.
 *
 * ucode-free by design: the parity contract exists to survive the ucode
 * removal, so the harness must run on a plain C++ toolchain (CI, hosts).
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "exporter_ipfix.hpp"
#include "flow.hpp"
#include "lifecycle.hpp"

typedef obserwrt::FlowKey FK;
typedef obserwrt::FlowValue FV;
typedef obserwrt::Delta DT;

static int g_failures = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
			g_failures++;                                                              \
		}                                                                                  \
	} while (0)

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

/* IPv4-mapped IPv6 address (RFC 4291) - identical to the ucode test helper. */
std::string v4in6(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	std::string s(10, '\0');
	s.push_back(static_cast<char>(0xff));
	s.push_back(static_cast<char>(0xff));
	s.push_back(static_cast<char>(a));
	s.push_back(static_cast<char>(b));
	s.push_back(static_cast<char>(c));
	s.push_back(static_cast<char>(d));
	return s;
}

/* Big-endian decoders for datagram inspection. */
uint16_t r16(const std::string &s, size_t o)
{
	return static_cast<uint16_t>((static_cast<uint16_t>((uint8_t)s[o]) << 8) |
				     (uint8_t)s[o + 1]);
}

uint32_t r32(const std::string &s, size_t o)
{
	return (static_cast<uint32_t>((uint8_t)s[o]) << 24) |
	       (static_cast<uint32_t>((uint8_t)s[o + 1]) << 16) |
	       (static_cast<uint32_t>((uint8_t)s[o + 2]) << 8) | (uint8_t)s[o + 3];
}

uint64_t r64(const std::string &s, size_t o)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | (uint8_t)s[o + i];
	return v;
}

/* In-memory FlowMap mirroring the map API used by the daemon's lifecycle.
 * Iteration snapshots the current keys (like the libbpf batch walk in the
 * daemon), so deleting a flow mid-pass is safe. reset() before each pass. */
struct MemMap : obserwrt::FlowMap {
	std::map<std::string, std::string> m;
	std::vector<std::string> keys_;
	size_t pos_ = 0;
	bool snapshot_ = false;

	void reset()
	{
		keys_.clear();
		pos_ = 0;
		snapshot_ = false;
	}

	bool next_key(std::string &key) override
	{
		if (!snapshot_) {
			snapshot_ = true;
			for (const auto &kv : m)
				keys_.push_back(kv.first);
		}
		if (pos_ >= keys_.size())
			return false;
		key = keys_[pos_++];
		return true;
	}

	bool get(const std::string &key, std::string &value) override
	{
		const auto it = m.find(key);
		if (it == m.end())
			return false; /* LRU-evicted between iteration and read */
		value = it->second;
		return true;
	}

	bool delete_key(const std::string &key) override
	{
		return m.erase(key) > 0;
	}
};

struct Seen {
	FK k;
	FV v;
	bool expired;
	DT delta;
};

} /* namespace */

/* ---------- 01_ipfix_wire_encoding (pinned ucode test) ---------- */

static void test_ipfix_wire()
{
	obserwrt::IpfixExporter e(1);
	/* Deterministic epochs from the mocked ucode test. */
	e.set_epoch(1615382640ULL, 1613767257000ULL);

	/* IPv4 TCP egress, ifindex 29, src 192.0.2.1 -> 198.51.100.2 */
	FK k1{};
	k1.ifindex = 29;
	k1.direction = obserwrt::EGRESS;
	k1.family = 4;
	k1.protocol = 6;
	std::memcpy(k1.src, v4in6(192, 0, 2, 1).data(), 16);
	std::memcpy(k1.dst, v4in6(198, 51, 100, 2).data(), 16);
	k1.sport = 12345;
	k1.dport = 80;

	FV v1{};
	v1.packets = 10;
	v1.bytes = 12340;
	v1.first_seen = 1700000000000000000ULL;
	v1.last_seen = 1700006000000000000ULL;
	v1.tcp_flags = 0x18;

	/* IPv6 UDP ingress, ifindex 30, 2001:db8::1 -> 2001:db8::2 */
	uint8_t s1[16] = {0};
	uint8_t s2[16] = {0};
	FK k2{};
	k2.ifindex = 30;
	k2.direction = obserwrt::INGRESS;
	k2.family = 6;
	k2.protocol = 17;
	s1[0] = 0x20;
	s1[1] = 0x01;
	s1[2] = 0x0d;
	s1[3] = 0xb8;
	s2[0] = 0x20;
	s2[1] = 0x01;
	s2[2] = 0x0d;
	s2[3] = 0xb8;
	s1[15] = 1;
	s2[15] = 2;
	std::memcpy(k2.src, s1, 16);
	std::memcpy(k2.dst, s2, 16);
	k2.sport = 53;
	k2.dport = 443;

	FV v2{};
	v2.packets = 2;
	v2.bytes = 200;
	v2.first_seen = 1700000000000000000ULL;
	v2.last_seen = 1700003000000000000ULL;
	v2.tcp_flags = 0;

	e.send_templates(1615382640ULL);
	e.emit(k1, v1, nullptr);
	e.emit(k2, v2, nullptr);
	e.flush(1615382640ULL);

	const auto &d = e.captured();
	CHECK_EQ(d.size(), (size_t)3);

	/* [0] templates: len 128, version 10, exportTime, seq 0, domain 1. */
	const std::string &t = d[0];
	CHECK_EQ(t.size(), (size_t)128);
	CHECK_EQ(r16(t, 0), (uint16_t)10);
	CHECK_EQ(r16(t, 2), (uint16_t)128);
	CHECK_EQ(r32(t, 4), (uint32_t)1615382640);
	CHECK_EQ(r32(t, 8), (uint32_t)0);
	CHECK_EQ(r32(t, 12), (uint32_t)1);

	/* set 1: TemplateSet(2) with v4 template tid 256, 12 fields, first (8,4). */
	CHECK_EQ(r16(t, 16), (uint16_t)2);
	CHECK_EQ(r16(t, 18), (uint16_t)56);
	CHECK_EQ(r16(t, 20), (uint16_t)256);
	CHECK_EQ(r16(t, 22), (uint16_t)12);
	CHECK_EQ(r16(t, 24), (uint16_t)8);
	CHECK_EQ(r16(t, 26), (uint16_t)4);
	CHECK_EQ(r16(t, 68), (uint16_t)14); /* last field: egressInterface */
	CHECK_EQ(r16(t, 70), (uint16_t)4);

	/* set 2: v6 template tid 257: set hdr @72, template hdr @76, fields @80. */
	CHECK_EQ(r16(t, 72), (uint16_t)2);
	CHECK_EQ(r16(t, 74), (uint16_t)56);
	CHECK_EQ(r16(t, 76), (uint16_t)257);
	CHECK_EQ(r16(t, 78), (uint16_t)12);
	CHECK_EQ(r16(t, 80), (uint16_t)27); /* sourceIPv6Address */
	CHECK_EQ(r16(t, 82), (uint16_t)16);

	/* [1] v4 data record: len 75, seq 0. */
	const std::string &v4 = d[1];
	CHECK_EQ(v4.size(), (size_t)75);
	CHECK_EQ(r32(v4, 8), (uint32_t)0);	     /* seq */
	CHECK_EQ(r16(v4, 16), (uint16_t)256);	     /* data set id */
	CHECK_EQ(r16(v4, 18), (uint16_t)59);	     /* set length 4+55 */
	CHECK_EQ(r32(v4, 20), (uint32_t)0xc0000201); /* 192.0.2.1 */
	CHECK_EQ(r32(v4, 24), (uint32_t)0xc6336402); /* 198.51.100.2 */
	CHECK_EQ(r16(v4, 28), (uint16_t)12345);
	CHECK_EQ(r16(v4, 30), (uint16_t)80);
	CHECK_EQ((uint8_t)v4[32], (uint8_t)6);
	CHECK_EQ(r64(v4, 33), (uint64_t)10);
	CHECK_EQ(r64(v4, 41), (uint64_t)12340);
	CHECK_EQ(r64(v4, 49), (uint64_t)3313767257000ULL);
	CHECK_EQ(r64(v4, 57), (uint64_t)3313773257000ULL);
	CHECK_EQ(r16(v4, 65), (uint16_t)0x18); /* tcpControlBits */
	CHECK_EQ(r32(v4, 67), (uint32_t)0);    /* ingressInterface */
	CHECK_EQ(r32(v4, 71), (uint32_t)29);   /* egressInterface */

	/* [2] v6 data record: len 99, seq 1, ingress 30. */
	const std::string &v6 = d[2];
	CHECK_EQ(v6.size(), (size_t)99);
	CHECK_EQ(r32(v6, 8), (uint32_t)1);
	CHECK_EQ(r16(v6, 16), (uint16_t)257);
	CHECK_EQ(r16(v6, 18), (uint16_t)83);		 /* 4 + 79 */
	CHECK(std::memcmp(v6.data() + 20, s1, 16) == 0); /* 2001:db8::1 */
	CHECK(std::memcmp(v6.data() + 36, s2, 16) == 0); /* 2001:db8::2 */
	CHECK_EQ(r16(v6, 52), (uint16_t)53);
	CHECK_EQ(r16(v6, 54), (uint16_t)443);
	CHECK_EQ((uint8_t)v6[56], (uint8_t)17);
	CHECK_EQ(r64(v6, 57), (uint64_t)2);
	CHECK_EQ(r64(v6, 65), (uint64_t)200);
	CHECK_EQ(r64(v6, 73), (uint64_t)3313767257000ULL);
	CHECK_EQ(r64(v6, 81), (uint64_t)3313770257000ULL);
	CHECK_EQ(r16(v6, 89), (uint16_t)0);
	CHECK_EQ(r32(v6, 91), (uint32_t)30); /* ingressInterface */
	CHECK_EQ(r32(v6, 95), (uint32_t)0);  /* egressInterface */
}

/* ---------- §5 key/value layouts <...> ---------- */

static void test_key_value_layouts()
{
	FK k{};
	k.ifindex = 29;
	k.direction = obserwrt::EGRESS;
	k.family = 4;
	k.protocol = 6;
	std::memcpy(k.src, v4in6(192, 0, 2, 1).data(), 16);
	std::memcpy(k.dst, v4in6(198, 51, 100, 2).data(), 16);
	k.sport = 12345;
	k.dport = 80;

	const std::string pk = obserwrt::pack_key(k);
	CHECK_EQ(pk.size(), (size_t)46);
	/* ifindex 29 LE, direction 1, family 4, proto 6, reserved 0. */
	const uint8_t lead[] = {0x1d, 0x00, 0x00, 0x00, 0x01, 0x04, 0x06, 0x00};
	CHECK(std::memcmp(pk.data(), lead, sizeof(lead)) == 0);
	/* src starts at byte 8: 10 zero bytes, ff ff, c0 00 02 01. */
	const uint8_t exp_src[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01};
	CHECK(std::memcmp(pk.data() + 8, exp_src, 16) == 0);
	const uint8_t exp_dst[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0xff, 0xff, 0xc6, 0x33, 0x64, 0x02};
	CHECK(std::memcmp(pk.data() + 24, exp_dst, 16) == 0);
	CHECK_EQ((uint8_t)pk[40], (uint8_t)0x39); /* sport 12345 LE */
	CHECK_EQ((uint8_t)pk[41], (uint8_t)0x30);
	CHECK_EQ((uint8_t)pk[42], (uint8_t)0x50); /* dport 80 LE */
	CHECK_EQ((uint8_t)pk[43], (uint8_t)0x00);
	CHECK_EQ((uint8_t)pk[44], (uint8_t)0x00); /* icmp_type */
	CHECK_EQ((uint8_t)pk[45], (uint8_t)0x00); /* icmp_code */

	/* Round-trip parse. */
	const FK k2 = obserwrt::parse_key(pk);
	CHECK_EQ(k2.ifindex, (uint32_t)29);
	CHECK_EQ(k2.direction, (uint8_t)1);
	CHECK_EQ(k2.sport, (uint16_t)12345);

	FV v{};
	v.packets = 10;
	v.bytes = 12340;
	v.first_seen = 1700000000000000000ULL;
	v.last_seen = 1700006000000000000ULL;
	v.tcp_flags = 0x18;

	const std::string pv = obserwrt::pack_value(v);
	CHECK_EQ(pv.size(), (size_t)40);
	CHECK_EQ((uint8_t)pv[0], (uint8_t)0x0a); /* packets LE */
	CHECK_EQ((uint8_t)pv[8], (uint8_t)0x34); /* bytes 12340 = 0x3034 */
	CHECK_EQ((uint8_t)pv[9], (uint8_t)0x30);
	CHECK_EQ((uint8_t)pv[32], (uint8_t)0x18); /* tcp_flags */
	CHECK_EQ((uint8_t)pv[33], (uint8_t)0x00);
	for (int i = 34; i < 40; i++)
		CHECK_EQ((uint8_t)pv[i], (uint8_t)0x00); /* trailing pad */

	const FV v2 = obserwrt::parse_value(pv);
	CHECK_EQ(v2.packets, (uint64_t)10);
	CHECK_EQ(v2.bytes, (uint64_t)12340);
	CHECK_EQ(v2.first_seen, (uint64_t)1700000000000000000ULL);
	CHECK_EQ(v2.last_seen, (uint64_t)1700006000000000000ULL);
	CHECK_EQ(v2.tcp_flags, (uint16_t)0x18);
}

/* ---------- 04_lifecycle/01_delta (pinned ucode test) ---------- */

static std::string tcp_key()
{
	FK k{};
	k.ifindex = 1;
	k.direction = obserwrt::INGRESS;
	k.family = 4;
	k.protocol = 6;
	std::memcpy(k.src, v4in6(192, 0, 2, 1).data(), 16);
	std::memcpy(k.dst, v4in6(198, 51, 100, 2).data(), 16);
	k.sport = 12345;
	k.dport = 443;
	return obserwrt::pack_key(k);
}

static std::string tcp_val(uint64_t pkts, uint64_t bytes, uint64_t last_ns)
{
	FV v{};
	v.packets = pkts;
	v.bytes = bytes;
	v.first_seen = 1;
	v.last_seen = last_ns;
	v.tcp_flags = 0x18;
	return obserwrt::pack_value(v);
}

static void test_lifecycle_delta()
{
	obserwrt::Timeouts to;
	to.tcp = 300;
	obserwrt::Lifecycle life(to);

	const std::string key = tcp_key();
	const uint64_t now_ns = obserwrt::Lifecycle::now_ns();

	MemMap map;
	map.m[key] = tcp_val(5, 500, now_ns);

	std::vector<Seen> seen;
	auto collect = [&](const FK &k, const FV &v, bool expired, const DT &delta) {
		(void)k;
		seen.push_back(Seen{k, v, expired, delta});
	};

	/* pass 1: first export carries the full flow counters, not expired. */
	map.reset();
	seen.clear();
	life.run(map, collect);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK_EQ(seen[0].delta.packets, (uint64_t)5);
	CHECK_EQ(seen[0].delta.bytes, (uint64_t)500);
	CHECK(!seen[0].expired);

	/* bump counters; export is the delta only. */
	map.m[key] = tcp_val(8, 800, now_ns);
	map.reset();
	seen.clear();
	life.run(map, collect);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK_EQ(seen[0].delta.packets, (uint64_t)3);
	CHECK_EQ(seen[0].delta.bytes, (uint64_t)300);

	/* expire: last_seen past tcp_timeout -> expired and deleted. */
	map.m[key] = tcp_val(9, 900, now_ns - 301ULL * 1000000000ULL);
	map.reset();
	seen.clear();
	const obserwrt::Lifecycle::Stats st = life.run(map, collect);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK(seen[0].expired);
	CHECK_EQ(st.expired, (unsigned)1);
	CHECK(map.m.empty());
}

int main()
{
	test_ipfix_wire();
	test_key_value_layouts();
	test_lifecycle_delta();

	if (g_failures != 0) {
		std::fprintf(stderr, "harness: %d failures\n", g_failures);
		return 1;
	}
	std::printf("harness: all golden-vector checks passed\n");
	return 0;
}