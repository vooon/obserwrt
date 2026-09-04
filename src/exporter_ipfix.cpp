/*
 * obserwrt - IPFIX exporter (exporter_ipfix.cpp)
 *
 * Wire-identical port of exporter_ipfix.uc. See the header for the design
 * notes. The template/field/sequence/chunking semantics mirror the ucode
 * module byte-for-byte; this class is exercised by the golden-vector harness
 * against the pinned outputs of the deprecated ucode agent.
 */

#include "exporter_ipfix.hpp"

#include <cstring>

namespace obserwrt
{

namespace
{

constexpr uint32_t VERSION = 10;

/* Template field lists: [ieId, length] - identical to exporter_ipfix.uc. */
const std::vector<std::pair<uint16_t, uint16_t>> FIELDS_V4 = {
    {8, 4},   /* sourceIPv4Address */
    {12, 4},  /* destinationIPv4Address */
    {7, 2},   /* sourceTransportPort */
    {11, 2},  /* destinationTransportPort */
    {4, 1},   /* protocolIdentifier */
    {2, 8},   /* packetDeltaCount */
    {1, 8},   /* octetDeltaCount */
    {150, 8}, /* flowStartMilliseconds */
    {151, 8}, /* flowEndMilliseconds */
    {6, 2},   /* tcpControlBits */
    {10, 4},  /* ingressInterface */
    {14, 4},  /* egressInterface */
};

const std::vector<std::pair<uint16_t, uint16_t>> FIELDS_V6 = {
    {27, 16}, /* sourceIPv6Address */
    {28, 16}, /* destinationIPv6Address */
    {7, 2},   {11, 2}, {4, 1}, {2, 8}, {1, 8}, {150, 8}, {151, 8}, {6, 2}, {10, 4}, {14, 4},
};

} /* namespace */

IpfixExporter::IpfixExporter(uint32_t obs_domain) : obs_domain_(obs_domain)
{
	sink_ = [this](std::string data) { captured_.push_back(std::move(data)); };
}

void IpfixExporter::set_sink(Sink sink)
{
	sink_ = std::move(sink);
}

void IpfixExporter::set_epoch(uint32_t export_time_s, uint64_t offset_ms)
{
	offset_ms_ = offset_ms;
	last_template_sent_s_ = export_time_s;
}

void IpfixExporter::put16be(std::string &b, uint16_t v)
{
	b.push_back(static_cast<char>(v >> 8));
	b.push_back(static_cast<char>(v));
}

void IpfixExporter::put32be(std::string &b, uint32_t v)
{
	b.push_back(static_cast<char>(v >> 24));
	b.push_back(static_cast<char>(v >> 16));
	b.push_back(static_cast<char>(v >> 8));
	b.push_back(static_cast<char>(v));
}

void IpfixExporter::put64be(std::string &b, uint64_t v)
{
	for (int i = 7; i >= 0; i--)
		b.push_back(static_cast<char>(v >> (8 * i)));
}

void IpfixExporter::send(std::string data)
{
	sink_(std::move(data));
}

std::string IpfixExporter::template_set(uint16_t tid,
					const std::vector<std::pair<uint16_t, uint16_t>> &fields)
{
	std::string rec;
	put16be(rec, tid);
	put16be(rec, static_cast<uint16_t>(fields.size()));

	for (const auto &f : fields) {
		put16be(rec, f.first);
		put16be(rec, f.second);
	}

	std::string out;
	put16be(out, SET_TEMPLATE);
	put16be(out, static_cast<uint16_t>(4 + rec.size()));
	out += rec;
	return out;
}

void IpfixExporter::send_templates(uint32_t export_time_s)
{
	std::string body = template_set(IPV4_TID, FIELDS_V4) + template_set(IPV6_TID, FIELDS_V6);

	std::string m;
	m.reserve(16 + body.size());
	put16be(m, VERSION);
	put16be(m, static_cast<uint16_t>(16 + body.size()));
	put32be(m, export_time_s);
	put32be(m, seq_);
	put32be(m, obs_domain_);
	m += body;

	send(std::move(m));
	last_template_sent_s_ = export_time_s;
}

void IpfixExporter::emit_set(uint32_t export_time_s, uint16_t set_id, const std::string &body,
			     size_t cnt)
{
	std::string m;
	m.reserve(16 + 4 + body.size());
	put16be(m, VERSION);
	put16be(m, static_cast<uint16_t>(16 + 4 + body.size()));
	put32be(m, export_time_s);
	put32be(m, seq_);
	put32be(m, obs_domain_);
	put16be(m, set_id);
	put16be(m, static_cast<uint16_t>(4 + body.size()));
	m += body;

	send(std::move(m));
	seq_ += static_cast<uint32_t>(cnt);
}

void IpfixExporter::flush_set(uint32_t export_time_s, uint16_t set_id,
			      std::vector<std::string> &records)
{
	std::string body;
	size_t cnt = 0;

	for (const auto &r : records) {
		if (cnt > 0 && 16 + 4 + body.size() + r.size() > MAX_UDP) {
			emit_set(export_time_s, set_id, body, cnt);
			body.clear();
			cnt = 0;
		}
		body += r;
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

	std::string rec;

	if (k.family == 4) {
		rec.append(reinterpret_cast<const char *>(k.src + 12), 4);
		rec.append(reinterpret_cast<const char *>(k.dst + 12), 4);
	} else {
		rec.append(reinterpret_cast<const char *>(k.src), 16);
		rec.append(reinterpret_cast<const char *>(k.dst), 16);
	}

	put16be(rec, k.sport);
	put16be(rec, k.dport);
	rec.push_back(static_cast<char>(k.protocol & 0xff));
	put64be(rec, dp);
	put64be(rec, db);
	put64be(rec, start_ms);
	put64be(rec, end_ms);
	put16be(rec, v.tcp_flags);
	put32be(rec, ingress);
	put32be(rec, egress);

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