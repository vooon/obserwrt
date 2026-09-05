/*
 * obserwrt - flow lifecycle (lifecycle.cpp)
 *
 * Port of lifecycle.uc run(): O(map) walk, active-flow delta accounting,
 * per-protocol expiry, tracker pruning. The pass is O(map size) in userspace;
 * flows without new traffic are not re-emitted (their delta is zero anyway).
 */

#include "lifecycle.hpp"

#include <ctime>

namespace obserwrt
{

namespace
{

std::string hexenc(const std::string &b)
{
	static const char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(b.size() * 2);
	for (unsigned char c : b) {
		out.push_back(digits[c >> 4]);
		out.push_back(digits[c & 0x0f]);
	}
	return out;
}

} /* namespace */

uint64_t Lifecycle::now_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

uint64_t Lifecycle::proto_timeout(uint8_t proto) const
{
	switch (proto) {
	case 6: /* TCP */
		return timeouts_.tcp;
	case 17: /* UDP */
		return timeouts_.udp;
	case 1:	 /* ICMP */
	case 58: /* ICMPv6 */
		return timeouts_.icmp;
	default:
		return timeouts_.general;
	}
}

Lifecycle::Stats Lifecycle::run(FlowMap &map, const Exporter &exporter, uint64_t now)
{
	Stats n;
	std::unordered_set<std::string> seen;

	map.reset(); /* re-snapshot current keys (libbpf batch-walk semantics) */

	std::string key;
	std::string raw;

	while (map.next_key(key)) {
		const FlowKey k = parse_key(key);

		/* The key may have been LRU-evicted between iteration and the read. */
		if (!map.get(key, raw))
			continue;

		const FlowValue v = parse_value(raw);
		const std::string fk = hexenc(key);
		/* `now` was sampled before the walk; a packet may have updated
		 * last_seen after that, so v.last_seen can exceed now. Saturate at
		 * zero instead of letting the unsigned subtraction wrap (~584 y). */
		const uint64_t age_ns = now >= v.last_seen ? now - v.last_seen : 0;
		const double age_s = static_cast<double>(age_ns) / 1e9;

		const auto it = last_.find(fk);
		const Last *prev = (it != last_.end()) ? &it->second : nullptr;

		const uint64_t p0 = prev ? prev->packets : 0;
		const uint64_t b0 = prev ? prev->bytes : 0;
		int64_t dp = static_cast<int64_t>(v.packets) - static_cast<int64_t>(p0);
		int64_t db = static_cast<int64_t>(v.bytes) - static_cast<int64_t>(b0);
		if (dp < 0)
			dp = static_cast<int64_t>(v.packets);
		if (db < 0)
			db = static_cast<int64_t>(v.bytes);

		/* Re-export only when something changed since the last pass. A flow
		 * with no new traffic has a zero delta, so emitting it is pure waste. */
		const bool changed = !prev || v.last_seen != prev->last_seen ||
				     v.packets != prev->packets || v.bytes != prev->bytes;

		seen.insert(fk);
		last_[fk] = Last{v.packets, v.bytes, v.last_seen};

		const Delta delta{static_cast<uint64_t>(dp), static_cast<uint64_t>(db)};

		if (age_s > static_cast<double>(proto_timeout(k.protocol))) {
			exporter(k, v, true, delta);
			last_.erase(fk);
			map.delete_key(key);
			n.expired++;
		} else {
			n.active++;
			if (changed)
				exporter(k, v, false, delta);
		}

		n.map++;
	}

	/* Drop tracker entries for flows no longer in the map (LRU-evicted or
	 * expired) so the tracker does not grow without bound. */
	for (auto e = last_.begin(); e != last_.end();) {
		if (!seen.count(e->first))
			e = last_.erase(e);
		else
			++e;
	}

	return n;
}

} /* namespace obserwrt */
