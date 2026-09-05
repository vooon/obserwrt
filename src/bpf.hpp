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

	/* TC ingress+egress attach on a device incarnation (real ifindex).
	 * Idempotent; keeps the tcx links until detach(). */
	bool attach(uint32_t ifindex, std::string *err);
	void detach(uint32_t ifindex);
	bool attached(uint32_t ifindex) const;

	/* Flow-map element access (native §5 structs - the map layout IS the key/
	 * value POD from bpf/obserwrt-flow.h). */
	bool snapshot_keys(std::vector<FlowKey> &out) const;
	bool lookup(const FlowKey &key, FlowValue &value) const;
	bool erase(const FlowKey &key) const;
	void purge_ifindex(uint32_t ifindex);

	/* Self-observability. */
	uint32_t map_limit() const;	       /* bpf_map_info.max_entries */
	void bpf_stats(uint64_t out[4]) const; /* packets, bytes, flows_created, parsed */

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
	bpf_program *prog_ingress_ = nullptr;
	bpf_program *prog_egress_ = nullptr;
	std::map<uint32_t, Links> atts_; /* ifindex -> live tcx links */
	std::string last_error_;
};

/* FlowMap adapter over a loaded Bpf: snapshots the current keys per pass
 * (the libbpf walk semantics the lifecycle/harness MemMap mirror), then
 * get/delete per key so in-pass removal is safe. */
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
	std::vector<FlowKey> snapshot_;
	size_t pos_ = 0;
};

} /* namespace obserwrt */