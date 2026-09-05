/*
 * obserwrt - IPFIX exporter (exporter_ipfix.hpp)
 *
 * Wire-identical port of exporter_ipfix.uc. Encodes normalized flow
 * observations as IPFIX (RFC 7011) over UDP with two templates branching on
 * IPv4-mapped ::ffff: (ssourceIPv4Address/destinationIPv4Address) vs IPv6.
 *
 * The exporter is a faithful reimplementation of the ucode module so that the
 * golden-vector harness can compare byte-for-byte against the pinned outputs
 * of the deprecated ucode agent. Datagrams are handed to a Sink (the daemon
 * sends via UDP; the harness captures them).
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "flow.hpp"

namespace obserwrt
{

class IpfixExporter
{
      public:
	using Sink = std::function<void(std::string)>;

	explicit IpfixExporter(uint32_t obs_domain = 1);

	/* Default sink captures datagrams so tests/harness can inspect bytes.
	 * A daemon installs a real socket sink with set_sink(). */
	void set_sink(Sink sink);

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

	const std::vector<std::string> &captured() const
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

	Sink sink_;
	std::vector<std::string> captured_;
	std::vector<std::string> pending4_;
	std::vector<std::string> pending6_;

	static void put16be(std::string &b, uint16_t v);
	static void put32be(std::string &b, uint32_t v);
	static void put64be(std::string &b, uint64_t v);

	void send(std::string data);
	void emit_set(uint32_t export_time_s, uint16_t set_id, const std::string &body, size_t cnt);
	void flush_set(uint32_t export_time_s, uint16_t set_id, std::vector<std::string> &records);
	std::string template_set(uint16_t tid,
				 const std::vector<std::pair<uint16_t, uint16_t>> &fields);
};

} /* namespace obserwrt */
