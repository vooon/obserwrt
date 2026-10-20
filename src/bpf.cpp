/*
 * obserwrt - libbpf flow-map + TC attach (bpf.cpp)
 *
 * libbpf 1.x lives here only; nothing else in the daemon touches the bpf
 * module. Flow-map keys/values are the raw §5 bytes; each pass snapshots the
 * whole map (keys AND values) with BPF_MAP_LOOKUP_BATCH.
 */

#include "bpf.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <cerrno>
#include <cstring>

namespace obserwrt
{

namespace
{

/* human-readable libbpf failure for diagnostics */
std::string libbpf_msg(const char *what)
{
	char buf[256];
	const int e = errno;
	if (e != 0) {
		std::snprintf(buf, sizeof(buf), "%s: %s", what, std::strerror(e));
		return buf;
	}
	std::snprintf(buf, sizeof(buf), "%s (no errno; see log)", what);
	return buf;
}

} /* namespace */

Bpf::~Bpf()
{
	for (auto &kv : atts_) {
		Links &l = kv.second;
		if (l.in)
			bpf_link__destroy(l.in);
		if (l.eg)
			bpf_link__destroy(l.eg);
	}
	if (drop_link_)
		bpf_link__destroy(drop_link_);
	if (obj_)
		bpf_object__close(obj_);
}

bool Bpf::load(const std::string &path, uint32_t max_flows, bool track_drops, std::string *err,
	       std::string *warn)
{
	if (warn)
		warn->clear();
	if (!open_load(path, max_flows, track_drops, err)) {
		if (!track_drops)
			return false;
		/* The drop tracer is optional: never let it take flow collection
		 * down (e.g. a kernel without BTF for tp_btf). Retry without it. */
		if (warn)
			*warn =
			    "drop tracing disabled: " + (err ? *err : std::string("load failed"));
		if (!open_load(path, max_flows, false, err))
			return false;
		return true;
	}
	if (!track_drops)
		return true;

	drop_link_ = bpf_program__attach(prog_drop_);
	if (!drop_link_) {
		if (warn)
			*warn = "drop tracing disabled: " + libbpf_msg("attach tp_btf/kfree_skb");
		return true;
	}
	drops_active_ = true;
	return true;
}

bool Bpf::open_load(const std::string &path, uint32_t max_flows, bool with_drops, std::string *err)
{
	if (err)
		err->clear();

	obj_ = bpf_object__open_file(path.c_str(), nullptr);
	if (!obj_) {
		if (err)
			*err = libbpf_msg("bpf_object__open_file");
		return false;
	}

	flows_ = bpf_object__find_map_by_name(obj_, "obserwrt_flows");
	stats_ = bpf_object__find_map_by_name(obj_, "obserwrt_stats");
	devstats_ = bpf_object__find_map_by_name(obj_, "obserwrt_devstats");
	attached_ = bpf_object__find_map_by_name(obj_, "obserwrt_attached");
	drops_ = bpf_object__find_map_by_name(obj_, "obserwrt_drops");
	prog_drop_ = bpf_object__find_program_by_name(obj_, "obserwrt_kfree_skb");
	prog_ingress_[0] = bpf_object__find_program_by_name(obj_, "obserwrt_ingress_l3");
	prog_egress_[0] = bpf_object__find_program_by_name(obj_, "obserwrt_egress_l3");
	prog_ingress_[1] = bpf_object__find_program_by_name(obj_, "obserwrt_ingress_eth");
	prog_egress_[1] = bpf_object__find_program_by_name(obj_, "obserwrt_egress_eth");
	if (!flows_ || !stats_ || !devstats_ || !attached_ || !drops_ || !prog_drop_ ||
	    !prog_ingress_[0] || !prog_egress_[0] || !prog_ingress_[1] || !prog_egress_[1]) {
		if (err)
			*err = "obserwrt-bpf.o: missing map/program (flows/stats/devstats/"
			       "attached/drops/{ingress,egress}_{l3,eth}/kfree_skb)";
		bpf_object__close(obj_);
		obj_ = nullptr;
		return false;
	}

	/* Runtime flow-map sizing (design §16 v0.3). Set before load; the map
	 * memory is committed at load time.
	 *   max_flows > 0 -> the configured value;
	 *   max_flows == 0 -> the .o's baked default (FLOW_MAP_ENTRIES), with a
	 *   4096 fallback when the object baked an empty value (a build that
	 *   passed an empty -DFLOW_MAP_ENTRIES=). */
	{
		__u32 entries = max_flows;
		if (entries == 0) {
			entries = bpf_map__max_entries(flows_);
			if (entries == 0)
				entries = 4096;
		}
		bpf_map__set_max_entries(flows_, entries);
	}

	/* libbpf >= 1.6 no longer infers SCHED_CLS from SEC("classifier/x"); the
	 * tcx attach point below comes from the expected attach type. */
	for (int i = 0; i < 2; i++) {
		bpf_program__set_type(prog_ingress_[i], BPF_PROG_TYPE_SCHED_CLS);
		bpf_program__set_type(prog_egress_[i], BPF_PROG_TYPE_SCHED_CLS);
		bpf_program__set_expected_attach_type(prog_ingress_[i], BPF_TCX_INGRESS);
		bpf_program__set_expected_attach_type(prog_egress_[i], BPF_TCX_EGRESS);
	}
	/* The tp_btf drop tracer is loaded only when drop tracking is on. */
	bpf_program__set_autoload(prog_drop_, with_drops);

	if (bpf_object__load(obj_) != 0) {
		if (err)
			*err = libbpf_msg("bpf_object__load");
		bpf_object__close(obj_);
		obj_ = nullptr;
		return false;
	}
	return true;
}

bool Bpf::attach(uint32_t ifindex, bool ethernet, std::string *err)
{
	if (ifindex == 0) {
		if (err)
			*err = "attach: invalid ifindex";
		return false;
	}
	Links &l = atts_[ifindex];
	if (l.in && l.eg)
		return true;

	/* A new attachment starts its class counters from zero (the ifindex may
	 * be a reused one whose old entries were not dropped). */
	if (!l.in && !l.eg)
		drop_dev_counters(ifindex);

	/* Mark the device observed for the drop tracer (harmless when off). */
	const uint8_t one = 1;
	bpf_map__update_elem(attached_, &ifindex, sizeof(ifindex), &one, sizeof(one), BPF_ANY);

	if (!l.in) {
		l.in = bpf_program__attach_tcx(prog_ingress_[ethernet], static_cast<int>(ifindex),
					       nullptr);
		if (!l.in) {
			if (err)
				*err = libbpf_msg("attach_tcx ingress");
			return false;
		}
	}
	if (!l.eg) {
		l.eg = bpf_program__attach_tcx(prog_egress_[ethernet], static_cast<int>(ifindex),
					       nullptr);
		if (!l.eg) {
			bpf_link__destroy(l.in);
			l.in = nullptr;
			if (err)
				*err = libbpf_msg("attach_tcx egress");
			return false;
		}
	}
	return true;
}

void Bpf::detach(uint32_t ifindex)
{
	const auto it = atts_.find(ifindex);
	if (it == atts_.end())
		return;
	Links &l = it->second;
	if (l.in) {
		bpf_link__destroy(l.in);
		l.in = nullptr;
	}
	if (l.eg) {
		bpf_link__destroy(l.eg);
		l.eg = nullptr;
	}
	drop_dev_counters(ifindex);
	if (attached_)
		bpf_map__delete_elem(attached_, &ifindex, sizeof(ifindex), 0);
}

void Bpf::drop_dev_counters(uint32_t ifindex) const
{
	if (!devstats_)
		return;
	for (const uint8_t dir : {static_cast<uint8_t>(INGRESS), static_cast<uint8_t>(EGRESS)}) {
		struct dev_key k = {};
		k.ifindex = ifindex;
		k.direction = dir;
		bpf_map__delete_elem(devstats_, &k, sizeof(k), 0); /* ENOENT is fine */
	}
}

bool read_dev_counters(int fd, std::vector<DevCounters> &out)
{
	out.clear();

	/* PERCPU_HASH: one dev_val per possible CPU, summed here. A plain
	 * get_next_key walk is fine: the map is small and never evicts. */
	const int ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0)
		return false;
	std::vector<struct dev_val> slots(static_cast<size_t>(ncpu));

	struct dev_key cur = {};
	struct dev_key next = {};
	bool first = true;
	while (bpf_map_get_next_key(fd, first ? nullptr : &cur, &next) == 0) {
		first = false;
		cur = next;
		if (bpf_map_lookup_elem(fd, &next, slots.data()) != 0)
			continue; /* deleted between the two calls (detach) */
		DevCounters d = {};
		d.ifindex = next.ifindex;
		d.direction = next.direction;
		for (const struct dev_val &v : slots) {
			for (int c = 0; c < OBSERWRT_CLASS_MAX; c++) {
				d.packets[c] += v.packets[c];
				d.bytes[c] += v.bytes[c];
			}
		}
		out.push_back(d);
	}
	return errno == ENOENT;
}

bool Bpf::dev_counters(std::vector<DevCounters> &out) const
{
	if (!devstats_) {
		out.clear();
		return false;
	}
	return read_dev_counters(bpf_map__fd(devstats_), out);
}

bool Bpf::attached(uint32_t ifindex) const
{
	const auto it = atts_.find(ifindex);
	return it != atts_.end() && it->second.in && it->second.eg;
}

namespace
{

/* Walk a hash map with BPF_MAP_LOOKUP_BATCH (or LOOKUP_AND_DELETE_BATCH when
 * `drain`). The hash-map batch walk advances bucket by bucket (the token is a
 * u32 bucket index), so LRU eviction during the walk cannot restart it the
 * way a vanished get_next_key() cursor does: every key that stays in the map
 * is visited once, and the walk always terminates. */
template <typename K, typename V>
bool batch_read(int fd, std::vector<K> &keys, std::vector<V> &values, bool drain)
{
	keys.clear();
	values.clear();

	std::vector<K> kb(256);
	std::vector<V> vb(kb.size());
	uint32_t in_batch = 0;
	uint32_t out_batch = 0;
	bool first = true;
	LIBBPF_OPTS(bpf_map_batch_opts, opts);

	for (;;) {
		auto count = static_cast<uint32_t>(kb.size());
		void *in = first ? nullptr : &in_batch;
		const int r = drain ? bpf_map_lookup_and_delete_batch(fd, in, &out_batch, kb.data(),
								      vb.data(), &count, &opts)
				    : bpf_map_lookup_batch(fd, in, &out_batch, kb.data(), vb.data(),
							   &count, &opts);
		const int e = r != 0 ? errno : 0;

		if (e == ENOSPC && count == 0) {
			/* One bucket holds more entries than the buffer: grow. */
			kb.resize(kb.size() * 2);
			vb.resize(kb.size());
			continue;
		}
		if (e != 0 && e != ENOENT)
			return false;

		keys.insert(keys.end(), kb.begin(), kb.begin() + count);
		values.insert(values.end(), vb.begin(), vb.begin() + count);

		if (e == ENOENT) /* walked past the last bucket */
			return true;
		in_batch = out_batch;
		first = false;
	}
}

} /* namespace */

bool read_flows(int fd, std::vector<FlowKey> &keys, std::vector<FlowValue> &values)
{
	return batch_read(fd, keys, values, false);
}

bool drain_drops(int fd, std::vector<DropKey> &keys, std::vector<FlowValue> &values)
{
	return batch_read(fd, keys, values, true);
}

bool Bpf::take_drops(std::vector<DropKey> &keys, std::vector<FlowValue> &values) const
{
	if (!drops_active_) {
		keys.clear();
		values.clear();
		return true;
	}
	return drain_drops(bpf_map__fd(drops_), keys, values);
}

bool Bpf::snapshot(std::vector<FlowKey> &keys, std::vector<FlowValue> &values) const
{
	if (!flows_) {
		keys.clear();
		values.clear();
		return false;
	}
	return read_flows(bpf_map__fd(flows_), keys, values);
}

bool Bpf::lookup(const FlowKey &key, FlowValue &value) const
{
	if (!flows_)
		return false;
	if (bpf_map__lookup_elem(flows_, &key, sizeof(FlowKey), &value, sizeof(FlowValue), 0) != 0)
		return false; /* LRU-evicted between iteration and read */
	return true;
}

bool Bpf::erase(const FlowKey &key) const
{
	if (!flows_)
		return false;
	return bpf_map__delete_elem(flows_, &key, sizeof(FlowKey), 0) == 0;
}

void Bpf::purge_ifindex(uint32_t ifindex)
{
	std::vector<FlowKey> keys;
	std::vector<FlowValue> values;
	if (!snapshot(keys, values))
		return;
	for (const FlowKey &k : keys) {
		if (k.ifindex == ifindex)
			erase(k);
	}
}

uint32_t Bpf::map_limit() const
{
	if (!flows_)
		return 0;
	struct bpf_map_info info;
	std::memset(&info, 0, sizeof(info));
	__u32 len = sizeof(info);
	if (bpf_obj_get_info_by_fd(bpf_map__fd(flows_), &info, &len) != 0)
		return 0;
	return info.max_entries;
}

void Bpf::bpf_stats(uint64_t out[STAT_COUNT]) const
{
	/* PERCPU_ARRAY: one u64 slot per possible CPU, summed here. */
	const int ncpu = libbpf_num_possible_cpus();
	std::vector<uint64_t> slots(ncpu > 0 ? static_cast<size_t>(ncpu) : 0);
	for (uint32_t i = 0; i < STAT_COUNT; i++) {
		out[i] = 0;
		if (!stats_ || slots.empty() ||
		    bpf_map__lookup_elem(stats_, &i, sizeof(i), slots.data(),
					 slots.size() * sizeof(uint64_t), 0) != 0)
			continue;
		for (const uint64_t v : slots)
			out[i] += v;
	}
}

/* ---------------- BpfFlowMap ---------------- */

void BpfFlowMap::reset()
{
	keys_.clear();
	values_.clear();
	pos_ = 0;
	if (b_)
		b_->snapshot(keys_, values_);
}

bool BpfFlowMap::next_key(FlowKey &key)
{
	if (pos_ >= keys_.size())
		return false;
	key = keys_[pos_++];
	return true;
}

bool BpfFlowMap::get(const FlowKey &key, FlowValue &value)
{
	/* The usual case: the value of the key just handed out, read in the
	 * same batch. Anything else falls back to a single lookup. */
	if (pos_ > 0 && keys_[pos_ - 1] == key) {
		value = values_[pos_ - 1];
		return true;
	}
	return b_->lookup(key, value);
}

bool BpfFlowMap::delete_key(const FlowKey &key)
{
	return b_->erase(key);
}

} /* namespace obserwrt */