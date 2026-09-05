/*
 * obserwrt - native IPFIX e2e emitter (tests/emit_native.cpp)
 *
 * The C++ replacement for scripts/emit-test.uc: drives the C++
 * IpfixExporter over a UdpClient with the same two fixed flows the ucode
 * emitter sent, so scripts/test-ipfix.sh can validate the native exporter
 * against an independent collector (goflow2) end-to-end.
 *
 * Usage: obserwrt-emit [host] [port]   (or COLLECTOR_HOST/COLLECTOR_PORT)
 */

#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "exporter_ipfix.hpp"
#include "flow.hpp"
#include "udp_client.hpp"

namespace
{

uint64_t mono_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
	       static_cast<uint64_t>(ts.tv_nsec / 1000000);
}

/* ::ffff:a.b.c.d */
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

} /* namespace */

int main(int argc, char **argv)
{
	const char *h = argc > 1 ? argv[1] : getenv("COLLECTOR_HOST");
	const char *p = argc > 2 ? argv[2] : getenv("COLLECTOR_PORT");
	const std::string host = h ? h : "127.0.0.1";
	const uint16_t port = static_cast<uint16_t>(p ? std::atoi(p) : 4739);

	obserwrt::UdpClient udp;
	std::string err;
	if (!udp.connect(host, port, "", &err)) {
		std::fprintf(stderr, "emit: connect %s:%u failed: %s\n", host.c_str(), port,
			     err.c_str());
		return 1;
	}

	obserwrt::IpfixExporter ex(1);
	ex.set_sink([&](std::string data) { udp.send(data); });

	const uint32_t start_s = static_cast<uint32_t>(time(nullptr));
	ex.set_epoch(start_s, static_cast<uint64_t>(start_s) * 1000ULL - mono_ms());
	ex.send_templates(start_s);

	/* Let the collector ingest the template before the data records. */
	usleep(200000);

	const uint64_t now_ns = mono_ms() * 1000000ULL;

	/* IPv4 TCP egress (direction 1), ifindex 29, 192.0.2.1 -> 198.51.100.2 */
	obserwrt::FlowKey k1{};
	k1.ifindex = 29;
	k1.direction = obserwrt::EGRESS;
	k1.family = 4;
	k1.protocol = 6;
	std::memcpy(k1.src, v4in6(192, 0, 2, 1).data(), 16);
	std::memcpy(k1.dst, v4in6(198, 51, 100, 2).data(), 16);
	k1.sport = 12345;
	k1.dport = 80;
	obserwrt::FlowValue v1{};
	v1.packets = 10;
	v1.bytes = 12340;
	v1.first_seen = now_ns - 5000000000ULL;
	v1.last_seen = now_ns;
	v1.tcp_flags = 0x18;
	ex.emit(k1, v1, nullptr);

	/* IPv6 UDP ingress, ifindex 30, 2001:db8::1 -> 2001:db8::2 */
	obserwrt::FlowKey k2{};
	k2.ifindex = 30;
	k2.direction = obserwrt::INGRESS;
	k2.family = 6;
	k2.protocol = 17;
	uint8_t s1[16] = {0};
	uint8_t s2[16] = {0};
	s1[0] = s2[0] = 0x20;
	s1[1] = s2[1] = 0x01;
	s1[2] = s2[2] = 0x0d;
	s1[3] = s2[3] = 0xb8;
	s1[15] = 1;
	s2[15] = 2;
	std::memcpy(k2.src, s1, 16);
	std::memcpy(k2.dst, s2, 16);
	k2.sport = 53;
	k2.dport = 443;
	obserwrt::FlowValue v2{};
	v2.packets = 2;
	v2.bytes = 200;
	v2.first_seen = now_ns - 2000000000ULL;
	v2.last_seen = now_ns;
	ex.emit(k2, v2, nullptr);

	ex.flush(start_s);
	std::printf("emit: sent to %s:%u\n", host.c_str(), port);
	return 0;
}