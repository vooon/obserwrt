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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "config.hpp"
#include "exporter_ipfix.hpp"
#include "exporter_syslog.hpp"
#include "flow.hpp"
#include "lifecycle.hpp"
#include "prometheus.hpp"

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
uint16_t r16(const std::vector<std::byte> &s, size_t o)
{
	return static_cast<uint16_t>((static_cast<uint16_t>((uint8_t)s[o]) << 8) |
				     (uint8_t)s[o + 1]);
}

uint32_t r32(const std::vector<std::byte> &s, size_t o)
{
	return (static_cast<uint32_t>((uint8_t)s[o]) << 24) |
	       (static_cast<uint32_t>((uint8_t)s[o + 1]) << 16) |
	       (static_cast<uint32_t>((uint8_t)s[o + 2]) << 8) | (uint8_t)s[o + 3];
}

uint64_t r64(const std::vector<std::byte> &s, size_t o)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | (uint8_t)s[o + i];
	return v;
}

uint8_t u8(const std::vector<std::byte> &s, size_t o)
{
	return static_cast<uint8_t>(s[o]);
}

/* In-memory FlowMap mirroring the map API used by the daemon's lifecycle.
 * Iteration snapshots the current keys (like the libbpf walk in the daemon),
 * so deleting a flow mid-pass is safe. reset() before each pass. Keys are the
 * native §5 structs (flow.hpp), byte-compared like the packed map key. */
struct flow_key_less {
	bool operator()(const FK &a, const FK &b) const
	{
		return std::memcmp(&a, &b, sizeof(FK)) < 0;
	}
};

struct MemMap : obserwrt::FlowMap {
	std::map<FK, FV, flow_key_less> m;
	std::vector<FK> keys_;
	size_t pos_ = 0;
	bool snapshot_ = false;

	void reset() override
	{
		keys_.clear();
		pos_ = 0;
		snapshot_ = false;
	}

	bool next_key(FK &key) override
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

	bool get(const FK &key, FV &value) override
	{
		const auto it = m.find(key);
		if (it == m.end())
			return false; /* LRU-evicted between iteration and read */
		value = it->second;
		return true;
	}

	bool delete_key(const FK &key) override
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
	const auto &t = d[0];
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
	/* IE 7/8 are flowStart/EndMilliseconds (152/153), not Seconds (150/151). */
	CHECK_EQ(r16(t, 52), (uint16_t)152);
	CHECK_EQ(r16(t, 56), (uint16_t)153);
	CHECK_EQ(r16(t, 68), (uint16_t)14); /* last field: egressInterface */
	CHECK_EQ(r16(t, 70), (uint16_t)4);

	/* set 2: v6 template tid 257: set hdr @72, template hdr @76, fields @80. */
	CHECK_EQ(r16(t, 72), (uint16_t)2);
	CHECK_EQ(r16(t, 74), (uint16_t)56);
	CHECK_EQ(r16(t, 76), (uint16_t)257);
	CHECK_EQ(r16(t, 78), (uint16_t)12);
	CHECK_EQ(r16(t, 80), (uint16_t)27); /* sourceIPv6Address */
	CHECK_EQ(r16(t, 82), (uint16_t)16);
	CHECK_EQ(r16(t, 108), (uint16_t)152); /* flowStartMilliseconds */
	CHECK_EQ(r16(t, 112), (uint16_t)153); /* flowEndMilliseconds */

	/* [1] v4 data record: len 75, seq 0. */
	const auto &v4 = d[1];
	CHECK_EQ(v4.size(), (size_t)75);
	CHECK_EQ(r32(v4, 8), (uint32_t)0);	     /* seq */
	CHECK_EQ(r16(v4, 16), (uint16_t)256);	     /* data set id */
	CHECK_EQ(r16(v4, 18), (uint16_t)59);	     /* set length 4+55 */
	CHECK_EQ(r32(v4, 20), (uint32_t)0xc0000201); /* 192.0.2.1 */
	CHECK_EQ(r32(v4, 24), (uint32_t)0xc6336402); /* 198.51.100.2 */
	CHECK_EQ(r16(v4, 28), (uint16_t)12345);
	CHECK_EQ(r16(v4, 30), (uint16_t)80);
	CHECK_EQ(u8(v4, 32), (uint8_t)6);
	CHECK_EQ(r64(v4, 33), (uint64_t)10);
	CHECK_EQ(r64(v4, 41), (uint64_t)12340);
	CHECK_EQ(r64(v4, 49), (uint64_t)3313767257000ULL);
	CHECK_EQ(r64(v4, 57), (uint64_t)3313773257000ULL);
	CHECK_EQ(r16(v4, 65), (uint16_t)0x18); /* tcpControlBits */
	CHECK_EQ(r32(v4, 67), (uint32_t)0);    /* ingressInterface */
	CHECK_EQ(r32(v4, 71), (uint32_t)29);   /* egressInterface */

	/* [2] v6 data record: len 99, seq 1, ingress 30. */
	const auto &v6 = d[2];
	CHECK_EQ(v6.size(), (size_t)99);
	CHECK_EQ(r32(v6, 8), (uint32_t)1);
	CHECK_EQ(r16(v6, 16), (uint16_t)257);
	CHECK_EQ(r16(v6, 18), (uint16_t)83);		 /* 4 + 79 */
	CHECK(std::memcmp(v6.data() + 20, s1, 16) == 0); /* 2001:db8::1 */
	CHECK(std::memcmp(v6.data() + 36, s2, 16) == 0); /* 2001:db8::2 */
	CHECK_EQ(r16(v6, 52), (uint16_t)53);
	CHECK_EQ(r16(v6, 54), (uint16_t)443);
	CHECK_EQ(u8(v6, 56), (uint8_t)17);
	CHECK_EQ(r64(v6, 57), (uint64_t)2);
	CHECK_EQ(r64(v6, 65), (uint64_t)200);
	CHECK_EQ(r64(v6, 73), (uint64_t)3313767257000ULL);
	CHECK_EQ(r64(v6, 81), (uint64_t)3313770257000ULL);
	CHECK_EQ(r16(v6, 89), (uint16_t)0);
	CHECK_EQ(r32(v6, 91), (uint32_t)30); /* ingressInterface */
	CHECK_EQ(r32(v6, 95), (uint32_t)0);  /* egressInterface */
}

/* ---------- §5 key/value layouts (pinned by bpf/obserwrt-flow.h) ---------- */

static void test_key_value_layouts()
{
	/* The §5 layouts are native structs shared with the BPF map; sizes and key
	 * offsets are asserted in the shared header. Here we pin the field layout
	 * in bytes (host-endian) so a layout drift is caught as a harness diff. */
	FK k{};
	k.ifindex = 29;
	k.direction = obserwrt::EGRESS;
	k.family = 4;
	k.protocol = 6;
	std::memcpy(k.src, v4in6(192, 0, 2, 1).data(), 16);
	std::memcpy(k.dst, v4in6(198, 51, 100, 2).data(), 16);
	k.sport = 12345;
	k.dport = 80;

	const auto *kp = reinterpret_cast<const uint8_t *>(&k);
	CHECK_EQ(kp[0], (uint8_t)0x1d); /* ifindex 29 LE (host-endian) */
	CHECK_EQ(kp[1], (uint8_t)0x00);
	CHECK_EQ(kp[4], (uint8_t)0x01); /* direction */
	CHECK_EQ(kp[5], (uint8_t)0x04); /* family */
	CHECK_EQ(kp[6], (uint8_t)0x06); /* protocol */
	CHECK_EQ(kp[7], (uint8_t)0x00); /* reserved */
	/* src starts at byte 8: 10 zero bytes, ff ff, c0 00 02 01. */
	const uint8_t exp_src[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01};
	CHECK(std::memcmp(kp + 8, exp_src, 16) == 0);
	const uint8_t exp_dst[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0xff, 0xff, 0xc6, 0x33, 0x64, 0x02};
	CHECK(std::memcmp(kp + 24, exp_dst, 16) == 0);
	CHECK_EQ(kp[40], (uint8_t)0x39); /* sport 12345 LE */
	CHECK_EQ(kp[41], (uint8_t)0x30);
	CHECK_EQ(kp[42], (uint8_t)0x50); /* dport 80 LE */
	CHECK_EQ(kp[43], (uint8_t)0x00);
	CHECK_EQ(kp[44], (uint8_t)0x00); /* icmp_type */
	CHECK_EQ(kp[45], (uint8_t)0x00); /* icmp_code */

	/* Direct member access matches the raw layout. */
	CHECK_EQ(k.ifindex, (uint32_t)29);
	CHECK_EQ(k.direction, (uint8_t)1);
	CHECK_EQ(k.sport, (uint16_t)12345);

	FV v{};
	v.packets = 10;
	v.bytes = 12340;
	v.first_seen = 1700000000000000000ULL;
	v.last_seen = 1700006000000000000ULL;
	v.tcp_flags = 0x18;

	const auto *vp = reinterpret_cast<const uint8_t *>(&v);
	CHECK_EQ(vp[0], (uint8_t)0x0a); /* packets LE */
	CHECK_EQ(vp[8], (uint8_t)0x34); /* bytes 12340 = 0x3034 */
	CHECK_EQ(vp[9], (uint8_t)0x30);
	CHECK_EQ(vp[32], (uint8_t)0x18); /* tcp_flags */
	CHECK_EQ(vp[33], (uint8_t)0x00);
	for (int i = 34; i < 40; i++)
		CHECK_EQ(vp[i], (uint8_t)0x00); /* trailing pad */

	CHECK_EQ(v.packets, (uint64_t)10);
	CHECK_EQ(v.bytes, (uint64_t)12340);
	CHECK_EQ(v.first_seen, (uint64_t)1700000000000000000ULL);
	CHECK_EQ(v.last_seen, (uint64_t)1700006000000000000ULL);
	CHECK_EQ(v.tcp_flags, (uint16_t)0x18);
}

/* ---------- 04_lifecycle/01_delta (pinned ucode test) ---------- */

static FK tcp_key()
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
	return k;
}

static FV tcp_val(uint64_t pkts, uint64_t bytes, uint64_t last_ns)
{
	FV v{};
	v.packets = pkts;
	v.bytes = bytes;
	v.first_seen = 1;
	v.last_seen = last_ns;
	v.tcp_flags = 0x18;
	return v;
}

static void test_lifecycle_delta()
{
	obserwrt::Timeouts to;
	to.tcp = 300;
	obserwrt::Lifecycle life(to);

	const FK key = tcp_key();
	/* Synthetic clock: fixed well above the 301s expiry window so the
	 * "past" last_seen cannot underflow on a freshly-booted host (real
	 * CLOCK_MONOTONIC uptime may be < 301 s on a CI VM, which would make
	 * `now - 301s` wrap to a huge last_seen). */
	const uint64_t now_ns = 1ULL << 40;

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
	life.run(map, collect, now_ns);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK_EQ(seen[0].delta.packets, (uint64_t)5);
	CHECK_EQ(seen[0].delta.bytes, (uint64_t)500);
	CHECK(!seen[0].expired);

	/* bump counters; export is the delta only. */
	map.m[key] = tcp_val(8, 800, now_ns);
	map.reset();
	seen.clear();
	life.run(map, collect, now_ns);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK_EQ(seen[0].delta.packets, (uint64_t)3);
	CHECK_EQ(seen[0].delta.bytes, (uint64_t)300);

	/* expire: last_seen past tcp_timeout -> expired and deleted. */
	map.m[key] = tcp_val(9, 900, now_ns - 301ULL * 1000000000ULL);
	map.reset();
	seen.clear();
	const obserwrt::Lifecycle::Stats st = life.run(map, collect, now_ns);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK(seen[0].expired);
	CHECK_EQ(st.expired, (unsigned)1);
	CHECK(map.m.empty());

	/* Future last_seen (a packet updated the flow after this pass sampled
	 * now): the unsigned age subtraction must not wrap into a false expiry. */
	map.m[key] = tcp_val(7, 700, now_ns + 5000ULL * 1000000000ULL);
	map.reset();
	seen.clear();
	life.run(map, collect, now_ns);
	CHECK_EQ(seen.size(), (size_t)1);
	CHECK(!seen[0].expired);
	CHECK(!map.m.empty());
	CHECK_EQ(seen[0].delta.packets, (uint64_t)7); /* first sighting: cumulative */
	CHECK_EQ(seen[0].delta.bytes, (uint64_t)700);
}

/* ---------- 02_syslog (pinned ucode tests) + config_mini ---------- */

static void test_syslog_export()
{
	/* IPv4 TCP egress ifindex 30 - mirrors 02_syslog/01_local_json. */
	FK k{};
	k.ifindex = 30;
	k.direction = obserwrt::EGRESS;
	k.family = 4;
	k.protocol = 6;
	std::memcpy(k.src, v4in6(192, 0, 2, 10).data(), 16);
	std::memcpy(k.dst, v4in6(198, 51, 100, 20).data(), 16);
	k.sport = 49152;
	k.dport = 443;

	FV v{};
	v.packets = 2;
	v.bytes = 128;
	v.first_seen = 10;
	v.last_seen = 20;
	v.tcp_flags = 2;

	const std::string js = obserwrt::SyslogExporter::encode_json(k, v, true, nullptr, "30");
	CHECK(js.find("\"ifname\":\"30\"") != std::string::npos);
	CHECK(js.find("\"src\":\"192.0.2.10\"") != std::string::npos);
	CHECK(js.find("\"dst\":\"198.51.100.20\"") != std::string::npos);
	CHECK(js.find("\"expired\":true") != std::string::npos);
	CHECK(js.find("\"packets\":2") != std::string::npos);

	/* IPv6 UDP ingress - mirrors 02_syslog/02_remote_logfmt. */
	uint8_t s1[16] = {0};
	uint8_t s2[16] = {0};
	FK k6{};
	k6.ifindex = 30;
	k6.direction = obserwrt::INGRESS;
	k6.family = 6;
	k6.protocol = 17;
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
	std::memcpy(k6.src, s1, 16);
	std::memcpy(k6.dst, s2, 16);
	k6.sport = 53;
	k6.dport = 443;

	FV v6{};
	v6.packets = 1;
	v6.bytes = 64;
	v6.first_seen = 30;
	v6.last_seen = 40;

	const std::string lf =
	    obserwrt::SyslogExporter::encode_logfmt(k6, v6, false, nullptr, "30");
	CHECK(lf.find("ifname=\"30\"") != std::string::npos);
	CHECK(lf.find("src=\"2001:db8::1\"") != std::string::npos);
	CHECK(lf.find("dst=\"2001:db8::2\"") != std::string::npos);
	CHECK(lf.find("expired=0") != std::string::npos);

	/* RFC 5424 envelope. */
	const std::string fr = obserwrt::SyslogExporter::frame(lf, "probe-awg0", 1700000000);
	CHECK(fr.find("<134>1 ") == 0);
	CHECK(fr.find("probe-awg0 obserwrt - - - ") != std::string::npos);
	CHECK(fr.find("Z ") != std::string::npos); /* RFC3339 timestamp */
}

static void test_config_mini()
{
	const std::string text = "[main]\n"
				 "device = awg* br-lan\n"
				 "tcp_timeout = 300\n"
				 "max_flows = 8192\n"
				 "[ipfix]\n"
				 "enabled = true\n"
				 "collector_host = 192.0.2.10\n"
				 "collector_port = 4739\n"
				 "observation_domain = 7\n";

	std::string err;
	const obserwrt::Config c = obserwrt::load_config_string(text, &err);
	CHECK(err.empty());
	CHECK_EQ(c.devices.size(), (size_t)2);
	CHECK(c.devices[0] == "awg*");
	CHECK(c.devices[1] == "br-lan");
	CHECK_EQ(c.timeouts.tcp, (uint64_t)300);
	CHECK_EQ(c.max_flows, (uint32_t)8192);
	CHECK(c.ipfix.enabled);
	CHECK(c.ipfix.collector_host == "192.0.2.10");
	CHECK_EQ(c.ipfix.collector_port, (uint16_t)4739);
	CHECK_EQ(c.ipfix.obs_domain, (uint32_t)7);

	/* enabled but no collector -> fatal config error. */
	const obserwrt::Config bad =
	    obserwrt::load_config_string("[ipfix]\nenabled = true\n", &err);
	CHECK(!err.empty());
}

/* ---------- Prometheus exposition builder ---------- */

static size_t count_occ(const std::string &hay, const std::string &needle)
{
	size_t n = 0;
	size_t pos = 0;
	while ((pos = hay.find(needle, pos)) != std::string::npos) {
		n++;
		pos += needle.size();
	}
	return n;
}

static void test_prometheus()
{
	obserwrt::PromExposition px;
	px.counter("obserwrt_flows_exported_total", "Flow records dispatched to exporters.", "", 4);
	px.counter("obserwrt_flows_exported_total", "Flow records dispatched to exporters.", "", 5);
	px.gauge("obserwrt_build_info", "Build and version information.",
		 obserwrt::PromExposition::labels({{"version", "1.0"}, {"commit", ""}}), 1);
	px.gauge("obserwrt_device_attached", "Attached netdev (1 if attached).",
		 obserwrt::PromExposition::labels({{"ifname", "awg\"x"}}), 1);

	const std::string s = px.str();

	/* # HELP/# TYPE emitted exactly once per family. */
	CHECK_EQ(count_occ(s, "# TYPE obserwrt_flows_exported_total counter\n"), (size_t)1);
	CHECK_EQ(count_occ(s, "# TYPE obserwrt_build_info gauge\n"), (size_t)1);
	CHECK_EQ(count_occ(s, "obserwrt_flows_exported_total 4\n"), (size_t)1);
	CHECK_EQ(count_occ(s, "obserwrt_flows_exported_total 5\n"), (size_t)1);

	/* labels: rendering + escaping of " in values. */
	CHECK(s.find("obserwrt_build_info{version=\"1.0\",commit=\"\"} 1\n") != std::string::npos);
	CHECK(s.find("obserwrt_device_attached{ifname=\"awg\\\"x\"} 1\n") != std::string::npos);

	/* empty label list -> bare sample, no braces. */
	CHECK(s.find("obserwrt_flows_exported_total 4") != std::string::npos);
	CHECK(s.find("obserwrt_flows_exported_total{} 4") == std::string::npos);

	/* header/encounter order preserved. */
	CHECK(s.find("obserwrt_flows_exported_total counter") <
	      s.find("obserwrt_build_info{version"));
}

int main()
{
	test_ipfix_wire();
	test_key_value_layouts();
	test_lifecycle_delta();
	test_syslog_export();
	test_config_mini();
	test_prometheus();

	if (g_failures != 0) {
		std::fprintf(stderr, "harness: %d failures\n", g_failures);
		return 1;
	}
	std::printf("harness: all golden-vector checks passed\n");
	return 0;
}
