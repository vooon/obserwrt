/*
 * obserwrt - IPFIX exporter (exporter_ipfix.cpp)
 *
 * Wire-identical port of exporter_ipfix.uc. See the header for the design
 * notes. The template/field/sequence/chunking semantics mirror the ucode
 * module byte-for-byte; this class is exercised by the golden-vector harness.
 *
 * Datagrams are built into std::vector<std::byte> with big-endian appenders
 * (one append/memcpy per field) and handed to the owned UdpClient as a span,
 * or captured for tests when not connected.
 */

#include "exporter_ipfix.hpp"

#include <bit>

#include <cstring>

namespace obserwrt
{

namespace
{

constexpr uint16_t VERSION = 10;

/* ---------------------------------------------------------------------------
 * Template fields - IANA IPFIX IEs (RFC 7011), enterprise 0.
 *
 * Both templates carry the same 12-element record; only the address IEs
 * differ: the v4 template (below) keys on the IPv4-mapped ::ffff: prefix and
 * emits the last 4 bytes of src/dst; the v6 template uses the 16-byte
 * sourceIPv6Address / destinationIPv6Address IEs 27/28 instead of 8/12.
 *
 * | IE  | Field                    | Len | Meaning                                |
 * |-----|--------------------------|-----|----------------------------------------|
 * | 8   | sourceIPv4Address        | 4   | source addr (v4: last 4 B of ::ffff:)  |
 * | 12  | destinationIPv4Address   | 4   | dest addr (v4: last 4 B of ::ffff:)    |
 * | 27  | sourceIPv6Address        | 16  | source addr (v6 template)              |
 * | 28  | destinationIPv6Address   | 16  | dest addr (v6 template)                |
 * | 7   | sourceTransportPort      | 2   | TCP/UDP sport; 0 for ICMP/other        |
 * | 11  | destinationTransportPort | 2   | TCP/UDP dport; 0 for ICMP/other        |
 * | 4   | protocolIdentifier       | 1   | IP protocol number (FlowKey.protocol)  |
 * | 2   | packetDeltaCount         | 8   | packets since last export (delta)      |
 * | 1   | octetDeltaCount          | 8   | bytes since last export (delta)        |
 * | 152 | flowStartMilliseconds    | 8   | first packet of flow, UNIX ms          |
 * | 153 | flowEndMilliseconds      | 8   | last packet seen, UNIX ms              |
 * | 6   | tcpControlBits           | 2   | TCP flags, low 8 (OR'd across packets) |
 * | 10  | ingressInterface         | 4   | ifindex on ingress, else 0             |
 * | 14  | egressInterface          | 4   | ifindex on egress, else 0              |
 *
 * fieldStart/End ms = startup offset + flow first_seen/last_seen (monotonic
 * ns), so wall-clock corrections are reflected by offset refresh (set_epoch /
 * set_offset_ms). Lengths are fixed, so a record is the fields below encoded
 * in the same order (see emit()).
 * ---------------------------------------------------------------------------
 */

//! Template for IPv4
const std::vector<std::pair<uint16_t, uint16_t>> FIELDS_V4 = {
    {8, 4},   /* sourceIPv4Address */
    {12, 4},  /* destinationIPv4Address */
    {7, 2},   /* sourceTransportPort */
    {11, 2},  /* destinationTransportPort */
    {4, 1},   /* protocolIdentifier */
    {2, 8},   /* packetDeltaCount */
    {1, 8},   /* octetDeltaCount */
    {152, 8}, /* flowStartMilliseconds */
    {153, 8}, /* flowEndMilliseconds */
    {6, 2},   /* tcpControlBits */
    {10, 4},  /* ingressInterface */
    {14, 4},  /* egressInterface */
};

//! Template for IPv6
const std::vector<std::pair<uint16_t, uint16_t>> FIELDS_V6 = {
    {27, 16}, /* sourceIPv6Address */
    {28, 16}, /* destinationIPv6Address */
    {7, 2},   /* sourceTransportPort */
    {11, 2},  /* destinationTransportPort */
    {4, 1},   /* protocolIdentifier */
    {2, 8},   /* packetDeltaCount */
    {1, 8},   /* octetDeltaCount */
    {152, 8}, /* flowStartMilliseconds */
    {153, 8}, /* flowEndMilliseconds */
    {6, 2},   /* tcpControlBits */
    {10, 4},  /* ingressInterface */
    {14, 4},  /* egressInterface */
};

inline void append_raw(std::vector<std::byte> &b, const void *p, size_t n)
{
	const auto *q = static_cast<const std::byte *>(p);
	b.insert(b.end(), q, q + n);
}

/* Append a host-order integer in network (big-endian) order: byteswap once
 * then append the value's bytes, independent of host endianness. */
template <typename T> inline void append_be(std::vector<std::byte> &b, T v)
{
	if constexpr (std::endian::native == std::endian::big) {
		append_raw(b, &v, sizeof(v));
	} else {
		const T be = std::byteswap(v);
		append_raw(b, &be, sizeof(be));
	}
}

} /* namespace */

IpfixExporter::IpfixExporter(uint32_t obs_domain) : obs_domain_(obs_domain)
{
}

bool IpfixExporter::connect(const std::string &host, uint16_t port, const std::string &source_addr,
			    std::string *err)
{
	return udp_.connect(host, port, source_addr, err);
}

void IpfixExporter::set_epoch(uint32_t export_time_s, uint64_t offset_ms)
{
	offset_ms_ = offset_ms;
	last_template_sent_s_ = export_time_s;
}

void IpfixExporter::set_offset_ms(uint64_t offset_ms)
{
	offset_ms_ = offset_ms;
}

void IpfixExporter::send(std::vector<std::byte> data)
{
	if (udp_.connected())
		udp_.send(data);
	else
		captured_.push_back(std::move(data));
}

std::vector<std::byte>
IpfixExporter::template_set(uint16_t tid, const std::vector<std::pair<uint16_t, uint16_t>> &fields)
{
	std::vector<std::byte> rec;
	rec.reserve(4 + fields.size() * 4);
	append_be(rec, tid);
	append_be(rec, static_cast<uint16_t>(fields.size()));

	for (const auto &f : fields) {
		append_be(rec, f.first);
		append_be(rec, f.second);
	}

	std::vector<std::byte> out;
	out.reserve(4 + rec.size());
	append_be(out, SET_TEMPLATE);
	append_be(out, static_cast<uint16_t>(4 + rec.size()));
	out.insert(out.end(), rec.begin(), rec.end());
	return out;
}

void IpfixExporter::send_templates(uint32_t export_time_s)
{
	std::vector<std::byte> body = template_set(IPV4_TID, FIELDS_V4);
	std::vector<std::byte> v6 = template_set(IPV6_TID, FIELDS_V6);
	body.insert(body.end(), v6.begin(), v6.end());

	std::vector<std::byte> m;
	m.reserve(16 + body.size());
	append_be(m, VERSION);
	append_be(m, static_cast<uint16_t>(16 + body.size()));
	append_be(m, export_time_s);
	append_be(m, seq_);
	append_be(m, obs_domain_);
	m.insert(m.end(), body.begin(), body.end());

	send(std::move(m));
	last_template_sent_s_ = export_time_s;
}

void IpfixExporter::emit_set(uint32_t export_time_s, uint16_t set_id,
			     const std::vector<std::byte> &body, size_t cnt)
{
	std::vector<std::byte> m;
	m.reserve(16 + 4 + body.size());
	append_be(m, VERSION);
	append_be(m, static_cast<uint16_t>(16 + 4 + body.size()));
	append_be(m, export_time_s);
	append_be(m, seq_);
	append_be(m, obs_domain_);
	append_be(m, set_id);
	append_be(m, static_cast<uint16_t>(4 + body.size()));
	m.insert(m.end(), body.begin(), body.end());

	send(std::move(m));
	seq_ += static_cast<uint32_t>(cnt);
}

void IpfixExporter::flush_set(uint32_t export_time_s, uint16_t set_id,
			      std::vector<std::vector<std::byte>> &records)
{
	std::vector<std::byte> body;
	size_t cnt = 0;

	for (const auto &r : records) {
		if (cnt > 0 && 16 + 4 + body.size() + r.size() > MAX_UDP) {
			emit_set(export_time_s, set_id, body, cnt);
			body.clear();
			cnt = 0;
		}
		body.insert(body.end(), r.begin(), r.end());
		cnt++;
	}

	if (cnt > 0)
		emit_set(export_time_s, set_id, body, cnt);
}

void IpfixExporter::emit(const FlowKey &k, const FlowValue &v, const Delta *delta)
{
	const uint64_t dp = delta ? delta->packets : v.packets;
	const uint64_t db = delta ? delta->bytes : v.bytes;

	const uint64_t start_ms = offset_ms_ + v.first_seen / 1000000;
	const uint64_t end_ms = offset_ms_ + v.last_seen / 1000000;

	const uint32_t ingress = (k.direction == INGRESS) ? k.ifindex : 0;
	const uint32_t egress = (k.direction == EGRESS) ? k.ifindex : 0;

	std::vector<std::byte> rec;

	if (k.family == 4) {
		append_raw(rec, k.src + 12, 4);
		append_raw(rec, k.dst + 12, 4);
	} else {
		append_raw(rec, k.src, 16);
		append_raw(rec, k.dst, 16);
	}

	append_be(rec, k.sport);
	append_be(rec, k.dport);
	rec.push_back(static_cast<std::byte>(k.protocol));
	append_be(rec, dp);
	append_be(rec, db);
	append_be(rec, start_ms);
	append_be(rec, end_ms);
	append_be(rec, v.tcp_flags);
	append_be(rec, ingress);
	append_be(rec, egress);

	if (k.family == 4)
		pending4_.push_back(std::move(rec));
	else
		pending6_.push_back(std::move(rec));
}

void IpfixExporter::flush(uint32_t export_time_s)
{
	if (export_time_s - last_template_sent_s_ >= TEMPLATE_INTERVAL_S)
		send_templates(export_time_s);

	flush_set(export_time_s, IPV4_TID, pending4_);
	pending4_.clear();
	flush_set(export_time_s, IPV6_TID, pending6_);
	pending6_.clear();
}

} /* namespace obserwrt */
