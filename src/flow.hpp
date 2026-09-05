/*
 * obserwrt - flow key/value types (flow.hpp)
 *
 * C++ view of the BPF flow-map key/value layouts (docs/design.md §5). The
 * layout is owned by bpf/obserwrt-flow.h (shared with the eBPF program); the
 * map is written and read on the same machine, so the PODs are interpreted
 * natively - no byte-swapping, no struct-string packing. FlowKey/FlowValue are
 * the raw map key/value; libbpf reads/writes them in place.
 *
 * Direction constants mirror the shared header (OBSERWRT_INGRESS/EGRESS).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "obserwrt-flow.h"

/* FlowKey is packed (no padding), so byte-wise equality is exact. The struct
 * lives in the global namespace (it is a C type), so its operators must too -
 * ADL on unordered_map<FlowKey,...> looks them up there. */
inline bool operator==(const flow_key &a, const flow_key &b)
{
	return std::memcmp(&a, &b, sizeof(flow_key)) == 0;
}

inline bool operator!=(const flow_key &a, const flow_key &b)
{
	return !(a == b);
}

namespace obserwrt
{

/* Direction at the observation point (mirrors the shared BPF header). */
enum : uint8_t {
	INGRESS = OBSERWRT_INGRESS,
	EGRESS = OBSERWRT_EGRESS,
};

using FlowKey = struct flow_key;
using FlowValue = struct flow_val;
/* Sizes asserted once in bpf/obserwrt-flow.h (shared with the eBPF program). */

/* XXH3-based hash of the packed key bytes, implemented in hash.cpp (xxhash is
 * XXH_INLINE_ALL'd there so it instantiates in one TU only). */
uint64_t flow_hash(const uint8_t *data, size_t len);

/* Hash functor for unordered_set/map<FlowKey>; FlowKey is packed (46 B) so the
 * raw bytes are the canonical identity. */
struct FlowKeyHash {
	size_t operator()(const FlowKey &k) const
	{
		return static_cast<size_t>(
		    flow_hash(reinterpret_cast<const uint8_t *>(&k), sizeof(FlowKey)));
	}
};

/* Interval growth handed to exporters by the lifecycle (active-flow delta
 * accounting) - the cumulative counters in FlowValue are NOT re-sent; only
 * the growth since the last export + the explicit value fields are. */
struct Delta {
	uint64_t packets;
	uint64_t bytes;
};

} /* namespace obserwrt */