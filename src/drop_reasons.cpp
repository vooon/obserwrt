/*
 * obserwrt - kernel drop reasons (drop_reasons.cpp)
 *
 * See drop_reasons.hpp. The name -> RFC 7270 mapping is a best-fit table
 * (docs/design.md §7.1); the raw kernel name is always kept for syslog.
 */

#include "drop_reasons.hpp"

#include <bpf/btf.h>
#include <linux/btf.h>

#include <cerrno>
#include <cstring>

namespace obserwrt
{

namespace
{

constexpr std::string_view PREFIX = "SKB_DROP_REASON_";

/* RFC 7270 forwardingStatus, status "Dropped" (2 << 6) + reason code. */
enum : uint8_t {
	DROP_UNKNOWN = 128,
	DROP_ACL_DROP = 130,
	DROP_UNROUTABLE = 131,
	DROP_ADJACENCY = 132,
	DROP_FRAG_DF = 133,
	DROP_BAD_CHECKSUM = 134,
	DROP_BAD_LENGTH = 135,
	DROP_BAD_HEADER = 136,
	DROP_BAD_TTL = 137,
	DROP_QUEUE = 139, /* "WRED": queue/congestion drops */
	DROP_RPF = 140,
	DROP_BAD_OUT_IF = 142,
};

bool has(std::string_view s, std::string_view part)
{
	return s.find(part) != std::string_view::npos;
}

} /* namespace */

uint8_t DropReasons::status_for_name(std::string_view n)
{
	/* Order matters: the more specific patterns come first. */
	if (has(n, "NETFILTER") || n.starts_with("TC_") || n.starts_with("XDP"))
		return DROP_ACL_DROP;
	if (has(n, "RPFILTER"))
		return DROP_RPF;
	if (has(n, "NOROUTE"))
		return DROP_UNROUTABLE;
	if (has(n, "CSUM"))
		return DROP_BAD_CHECKSUM;
	if (n == "PKT_TOO_BIG")
		return DROP_FRAG_DF;
	if (n == "PKT_TOO_SMALL")
		return DROP_BAD_LENGTH;
	if (has(n, "INHDR") || has(n, "HDR_TRUNC") || has(n, "BAD_EXTHDR") || n == "INVALID_PROTO")
		return DROP_BAD_HEADER;
	if (has(n, "TTL") || has(n, "HOP_LIMIT"))
		return DROP_BAD_TTL;
	if (n.starts_with("NEIGH_"))
		return DROP_ADJACENCY;
	if (n.starts_with("QDISC") || n == "CPU_BACKLOG" || n == "FULL_RING" || n == "QUEUE_PURGE")
		return DROP_QUEUE;
	if (n.starts_with("DEV_"))
		return DROP_BAD_OUT_IF;
	return DROP_UNKNOWN;
}

void DropReasons::add(uint32_t raw, std::string name)
{
	const uint8_t st = status_for_name(name);
	by_value_[raw] = Reason{std::move(name), st};
}

bool DropReasons::load(std::string *err)
{
	struct btf *btf = btf__load_vmlinux_btf();
	if (!btf) {
		if (err)
			*err = std::string("vmlinux BTF: ") + std::strerror(errno);
		return false;
	}
	const int id = btf__find_by_name_kind(btf, "skb_drop_reason", BTF_KIND_ENUM);
	if (id < 0) {
		btf__free(btf);
		if (err)
			*err = "vmlinux BTF: no enum skb_drop_reason";
		return false;
	}
	const struct btf_type *t = btf__type_by_id(btf, static_cast<uint32_t>(id));
	const struct btf_enum *e = btf_enum(t);
	for (int i = 0; i < btf_vlen(t); i++, e++) {
		std::string_view name = btf__name_by_offset(btf, e->name_off);
		if (name.starts_with(PREFIX))
			name.remove_prefix(PREFIX.size());
		add(static_cast<uint32_t>(e->val), std::string(name));
	}
	btf__free(btf);
	return true;
}

DropReasons::Reason DropReasons::lookup(uint32_t raw) const
{
	const auto it = by_value_.find(raw);
	if (it != by_value_.end())
		return it->second;
	return Reason{"reason_" + std::to_string(raw), DROP_UNKNOWN};
}

} /* namespace obserwrt */
