/*
 * obserwrt - kernel drop reasons (drop_reasons.hpp)
 *
 * The drop tracer stores the RAW kernel `enum skb_drop_reason` value; its
 * numbering differs between kernel versions. This resolves values to names
 * from the running kernel's BTF and maps each name to an IPFIX
 * forwardingStatus (RFC 7270 §4.12: 128 + reason code for "dropped").
 * Normalization lives here, in the agent, not in eBPF (design §7.1).
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace obserwrt
{

/* forwardingStatus for normal (non-drop) flow records: unknown. TC does not
 * know whether a packet is later forwarded, delivered or dropped. */
constexpr uint8_t FWD_STATUS_UNKNOWN = 0;

class DropReasons
{
      public:
	struct Reason {
		std::string name;	   /* e.g. "NETFILTER_DROP" (prefix stripped) */
		uint8_t forwarding_status; /* 128..143 */
	};

	/* Read enum skb_drop_reason from the kernel BTF. False (with `*err`) if
	 * unavailable; lookups then fall back to "reason_<n>" / 128. */
	bool load(std::string *err);

	/* Resolve a raw kernel value. */
	Reason lookup(uint32_t raw) const;

	/* Name (without the SKB_DROP_REASON_ prefix) -> RFC 7270 status. */
	static uint8_t status_for_name(std::string_view name);

	/* For tests: register a raw value -> name. */
	void add(uint32_t raw, std::string name);

      private:
	std::unordered_map<uint32_t, Reason> by_value_;
};

} /* namespace obserwrt */
