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
#include <string>
#include <vector>

#include "flow.hpp"
#include "lifecycle.hpp"

struct bpf_object;
struct bpf_map;
struct bpf_program;
struct bpf_link;

namespace obserwrt {

class Bpf {
public:
	Bpf() = default;
	~Bpf();
	Bpf(const Bpf &) = delete;
	Bpf &operator=(const Bpf &) = delete;

	/* Open the object, set the SCHED_CLS/TCX program types, size the flow map
	 * (`max_flows` == 0 keeps the baked-in default) and load. */
	bool load(const std::string &object_path, uint32_t max_flows, std::string *err);

	bool loaded() const { return obj_ != nullptr; }

	/* TC ingress+egress attach on a device incarnation (real ifindex).
	 * Idempotent; keeps the tcx links until detach(). */
	bool attach(uint32_t ifindex, std::string *err);
	void detach(uint32_t ifindex);
	bool attached(uint32_t ifindex) const;

	/* Flow-map element access (raw 46B key / 40B value). */
	bool snapshot_keys(std::vector<std::string> &out) const;
	bool lookup(const std::string &key, std::string &value) const;
	bool erase(const std::string &key) const;
	void purge_ifindex(uint32_t ifindex);

	/* Self-observability. */
	uint32_t map_limit() const;                 /* bpf_map_info.max_entries */
	void bpf_stats(uint64_t out[4]) const;      /* packets, bytes, flows_created, parsed */

	const std::string &last_error() const { return last_error_; }

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
	std::vector<Links> atts_; /* index == ifindex */
	std::string last_error_;
};

/* FlowMap adapter over a loaded Bpf: snapshots the current keys per pass
 * (the libbpf walk semantics the lifecycle/harness MemMap mirror), then
 * get/delete per key so in-pass removal is safe. */
class BpfFlowMap : public FlowMap {
public:
	explicit BpfFlowMap(const Bpf *b) : b_(b) {}

	void reset() override;
	bool next_key(std::string &key) override;
	bool get(const std::string &key, std::string &value) override;
	bool delete_key(const std::string &key) override;

private:
	const Bpf *b_;
	std::vector<std::string> snapshot_;
	size_t pos_ = 0;
};

} /* namespace obserwrt */