/*
 * obserwrt - libbpf flow-map + TC attach (bpf.hpp)
 *
 * Owns the BPF object lifetime: open, per-incarnation TC attach (tcx), the
 * flow map operations (snapshot iteration, lookup, delete, purge) and the
 * self-observability counters. The map size is applied before load
 * (max_flows), and the real limit is read back via bpf_map_info - design
 * §16 v0.3, no ucode-mod-bpf patch needed.
 */

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "flow.hpp"
#include "lifecycle.hpp"

struct bpf_object;
struct bpf_map;
struct bpf_program;
struct bpf_link;

namespace obserwrt
{

class Bpf
{
      public:
	Bpf() = default;
	~Bpf();
	Bpf(const Bpf &) = delete;
	Bpf &operator=(const Bpf &) = delete;

	/* Open the object, set the SCHED_CLS/TCX program types, size the flow map
	 * (`max_flows` == 0 keeps the baked-in default) and load. */
	bool load(const std::string &object_path, uint32_t max_flows, std::string *err);

	bool loaded() const
	{
		return obj_ != nullptr;
	}

	/* TC ingress+egress attach on a device incarnation (real ifindex), with
	 * the Ethernet or L3 program pair (see link_is_ethernet()). Idempotent;
	 * keeps the tcx links until detach(). */
	bool attach(uint32_t ifindex, bool ethernet, std::string *err);
	void detach(uint32_t ifindex);
	bool attached(uint32_t ifindex) const;

	/* Flow-map element access (native §5 structs - the map layout IS the key/
	 * value POD from bpf/obserwrt-flow.h). snapshot() reads every entry in
	 * one batched walk (see read_flows()). */
	bool snapshot(std::vector<FlowKey> &keys, std::vector<FlowValue> &values) const;
	bool lookup(const FlowKey &key, FlowValue &value) const;
	bool erase(const FlowKey &key) const;
	void purge_ifindex(uint32_t ifindex);

	/* Self-observability. */
	uint32_t map_limit() const;	       /* bpf_map_info.max_entries */
	void bpf_stats(uint64_t out[4]) const; /* packets, bytes, flows_created, parsed */
	/* Per-device/direction packet-class counters (obserwrt_devstats). */
	bool dev_counters(std::vector<DevCounters> &out) const;

	const std::string &last_error() const
	{
		return last_error_;
	}

      private:
	struct Links {
		bpf_link *in = nullptr;
		bpf_link *eg = nullptr;
	};

	bpf_object *obj_ = nullptr;
	bpf_map *flows_ = nullptr;
	bpf_map *stats_ = nullptr;
	bpf_map *devstats_ = nullptr;
	/* [0] = L3 framing, [1] = Ethernet framing */
	bpf_program *prog_ingress_[2] = {};
	bpf_program *prog_egress_[2] = {};
	std::map<uint32_t, Links> atts_; /* ifindex -> live tcx links */
	std::string last_error_;

	/* Delete a device's class counters (both directions). */
	void drop_dev_counters(uint32_t ifindex) const;
};

/* Read the per-CPU device class counters map (fd), summed over CPUs. False
 * on a map error; an empty map is success. Exposed for tests/bpf_run.cpp. */
bool read_dev_counters(int fd, std::vector<DevCounters> &out);

/* Read a whole flow map (fd) with BPF_MAP_LOOKUP_BATCH into parallel
 * key/value vectors. False on a map error; an empty map is success. Exposed
 * for the eBPF test-run (tests/bpf_run.cpp). */
bool read_flows(int fd, std::vector<FlowKey> &keys, std::vector<FlowValue> &values);

/* FlowMap adapter over a loaded Bpf: snapshots keys and values per pass in
 * one batched walk, then serves get() from that snapshot; delete per key so
 * in-pass removal is safe. */
class BpfFlowMap : public FlowMap
{
      public:
	explicit BpfFlowMap(const Bpf *b) : b_(b)
	{
	}

	void reset() override;
	bool next_key(FlowKey &key) override;
	bool get(const FlowKey &key, FlowValue &value) override;
	bool delete_key(const FlowKey &key) override;

      private:
	const Bpf *b_;
	std::vector<FlowKey> keys_;
	std::vector<FlowValue> values_;
	size_t pos_ = 0;
};

} /* namespace obserwrt */