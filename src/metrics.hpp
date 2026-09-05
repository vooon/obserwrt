/*
 * obserwrt - Prometheus self-observability (metrics.hpp)
 *
 * Publishes aggregate gauges/counters via the node-exporter textfile collector
 * (no HTTP server; labels per-device, never per-flow). The file is rewritten
 * atomically (temp + rename). Enabled only when the config sets a writable
 * path. Metric NAMES are part of the observable contract (frozen at 1.0.0);
 * see docs/design.md §9.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config.hpp"

namespace obserwrt
{

class Metrics
{
      public:
	/* Enable from config (path + interval). */
	void init(const Config &cfg);

	bool active() const
	{
		return active_;
	}
	uint32_t interval() const
	{
		return interval_s_;
	}

	/* Cheap dispatch counters (per-flow args retained only for symmetry). */
	void observe();
	void record_error();

	/* Gauges from one lifecycle pass + currently attached netdev names. */
	void set_state(unsigned flows_active, unsigned map_entries,
		       const std::vector<std::string> &devices);

	/* Snapshot the BPF-truth counters (exact even under LRU eviction). */
	void set_bpf(unsigned long long packets, unsigned long long bytes,
		     unsigned long long accounted, unsigned long long flows_created);

	/* Real flow-map capacity from bpf_map_info (design §16 v0.3). */
	void set_map_limit(uint32_t limit);

	/* Rewrite the textfile snapshot atomically. Not fatal on failure. */
	void write();

      private:
	bool active_ = false;
	std::string file_;
	uint32_t interval_s_ = 20;

	uint64_t total_flows_ = 0;
	uint64_t total_errors_ = 0;
	unsigned flows_active_ = 0;
	unsigned map_entries_ = 0;
	unsigned long long bpf_packets_ = 0;
	unsigned long long bpf_bytes_ = 0;
	unsigned long long bpf_accounted_ = 0;
	unsigned long long bpf_flows_created_ = 0;
	uint32_t map_limit_ = 0;
	std::vector<std::string> devices_;
};

} /* namespace obserwrt */
