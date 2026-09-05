/*
 * obserwrt - flow lifecycle (lifecycle.hpp)
 *
 * Periodic flow-map walk: hands each flow to an exporter callback with the
 * delta since the last export (active-flow delta accounting, so active
 * re-exports do not double-count), and deletes flows idle longer than their
 * per-protocol timeout. Same semantics as lifecycle.uc (docs/design.md §7).
 *
 * Timestamps in FlowValue come from bpf_ktime_get_ns() (CLOCK_MONOTONIC);
 * now_ns() reads the same clock so ages are directly comparable.
 */

#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "flow.hpp"

namespace obserwrt
{

/* Per-protocol idle timeouts (seconds), configurable via the config file. */
struct Timeouts {
	uint64_t tcp = 300;
	uint64_t udp = 60;
	uint64_t icmp = 30;
	uint64_t general = 10;
};

/* Abstraction over the BPF flow map (libbpf walk lands here). The daemon
 * implements it against libbpf; the harness uses an in-memory map. Keys and
 * values are the native §5 structs (flow.hpp) - the map layout IS the struct. */
class FlowMap
{
      public:
	virtual ~FlowMap() = default;

	/* Called before each pass so a map-backed iterator can re-snapshot the
	 * current keys (like the libbpf walk). No-op for stateless maps. */
	virtual void reset()
	{
	}

	/* Next current key; false when iteration is exhausted. */
	virtual bool next_key(FlowKey &key) = 0;

	/* Read the value for `key`. False = entry vanished between iteration and
	 * read (LRU eviction under map pressure) - skip it. */
	virtual bool get(const FlowKey &key, FlowValue &value) = 0;

	/* Delete the entry for `key` (expiry). */
	virtual bool delete_key(const FlowKey &key) = 0;
};

class Lifecycle
{
      public:
	using Exporter =
	    std::function<void(const FlowKey &, const FlowValue &, bool expired, const Delta &)>;

	struct Stats {
		unsigned active = 0;
		unsigned expired = 0;
		unsigned map = 0;
	};

	explicit Lifecycle(Timeouts timeouts) : timeouts_(timeouts)
	{
	}

	/* One pass; see lifecycle.uc run(). Exporter borrows parsed key/value plus
	 * the delta since the last export (or full counters on first sight).
	 * `now` is injectable for deterministic tests; defaults to the mono clock. */
	Stats run(FlowMap &map, const Exporter &exporter, uint64_t now = now_ns());

	/* Monotonic "now" in nanoseconds - same clock as bpf_ktime_get_ns(). */
	static uint64_t now_ns();

      private:
	Timeouts timeouts_;

	struct Last {
		uint64_t packets;
		uint64_t bytes;
		uint64_t last_seen;
	};

	/* last-exported counters keyed by the flow key (packed struct, hashed for
	 * the unordered map). Pruned each pass so LRU-evicted/expired flows do not
	 * leak state. */
	std::unordered_map<FlowKey, Last, FlowKeyHash> last_;

	uint64_t proto_timeout(uint8_t proto) const;
};

} /* namespace obserwrt */
