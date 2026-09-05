/*
 * obserwrt - IPFIX exporter (exporter_ipfix.hpp)
 *
 * Wire-identical port of exporter_ipfix.uc (now the C++ agent encodes IPFIX
 * RFC 7011 over UDP with two templates branching on IPv4-mapped ::ffff:
 * sourceIPv4Address/destinationIPv4Address vs IPv6. The exporter owns its
 * transport: a connected UdpClient sends datagrams; when not connected the
 * datagrams accumulate in captured() so tests/harness can inspect the exact
 * wire bytes (there is no injected Sink abstraction).
 *
 * Datagrams are built into std::byte buffers with big-endian appenders (one
 * memcpy per field, no byte-at-a-time push_back).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "flow.hpp"
#include "udp_client.hpp"

namespace obserwrt
{

class IpfixExporter
{
      public:
	explicit IpfixExporter(uint32_t obs_domain = 1);

	/* Owned transport: resolve + open the collector socket. When connected,
	 * emitted datagrams go out; otherwise they accumulate in captured(). */
	bool connect(const std::string &host, uint16_t port, const std::string &source_addr,
		     std::string *err);

	/* Failed sends since the last take (folded into the export error metric
	 * by the daemon). */
	unsigned long take_failures()
	{
		return udp_.take_failures();
	}

	/* Fixed epochs for deterministic wire output (tests). Real deployment sets
	 * offset_ms = epoch_ms - mono_ms at startup and passes live timestamps. */
	void set_epoch(uint32_t export_time_s, uint64_t offset_ms);

	/* Refresh only the realtime<-monotonic anchor (call after the wall clock
	 * is corrected, e.g. NTP, so flow flowStart/End ms follow). Does not touch
	 * the template retransmit timer (unlike set_epoch). */
	void set_offset_ms(uint64_t offset_ms);

	/* Send the two template sets as one datagram (also at init). */
	void send_templates(uint32_t export_time_s);

	/* Buffer one observation; `delta` null means cumulative counters
	 * (identical fallback to exporter_ipfix.uc). */
	void emit(const FlowKey &k, const FlowValue &v, const Delta *delta);

	/* Flush buffered records (retransmitting templates when their interval is
	 * due, matching exporter_ipfix.uc flush()). */
	void flush(uint32_t export_time_s);

	/* Sequence number state (for tests/inspection). */
	uint32_t seq() const
	{
		return seq_;
	}

	/* Datagrams emitted while the exporter was NOT connected (tests). */
	const std::vector<std::vector<std::byte>> &captured() const
	{
		return captured_;
	}

      private:
	static constexpr uint16_t SET_TEMPLATE = 2;
	static constexpr uint16_t IPV4_TID = 256;
	static constexpr uint16_t IPV6_TID = 257;
	static constexpr size_t MAX_UDP = 1200;
	static constexpr uint32_t TEMPLATE_INTERVAL_S = 60;

	uint32_t obs_domain_ = 1;
	uint32_t seq_ = 0;
	uint64_t offset_ms_ = 0;
	uint32_t last_template_sent_s_ = 0;

	UdpClient udp_;
	std::vector<std::vector<std::byte>> captured_;
	std::vector<std::vector<std::byte>> pending4_;
	std::vector<std::vector<std::byte>> pending6_;

	void send(std::vector<std::byte> data);
	void flush_set(uint32_t export_time_s, uint16_t set_id,
		       std::vector<std::vector<std::byte>> &records);
	std::vector<std::byte>
	template_set(uint16_t tid, const std::vector<std::pair<uint16_t, uint16_t>> &fields);
};

} /* namespace obserwrt */