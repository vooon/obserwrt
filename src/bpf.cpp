/*
 * obserwrt - libbpf flow-map + TC attach (bpf.cpp)
 *
 * libbpf 1.x lives here only; nothing else in the daemon touches the bpf
 * module. Flow-map keys/values are the raw §5 bytes; iteration snapshots the
 * current keys per pass (bpf_map__get_next_key), matching the lifecycle's
 * "LRU eviction between iteration and read" semantics.
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
	if (obj_)
		bpf_object__close(obj_);
}

bool Bpf::load(const std::string &path, uint32_t max_flows, std::string *err)
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
	prog_ingress_ = bpf_object__find_program_by_name(obj_, "obserwrt_ingress");
	prog_egress_ = bpf_object__find_program_by_name(obj_, "obserwrt_egress");
	if (!flows_ || !stats_ || !prog_ingress_ || !prog_egress_) {
		if (err)
			*err = "obserwrt-bpf.o: missing map/program (flows/stats/ingress/egress)";
		bpf_object__close(obj_);
		obj_ = nullptr;
		return false;
	}

	/* Runtime flow-map sizing (design §16 v0.3). Set before load; the map
	 * memory is committed at load time. 0 keeps the baked default. */
	if (max_flows)
		bpf_map__set_max_entries(flows_, max_flows);

	/* libbpf >= 1.6 no longer infers SCHED_CLS from SEC("classifier/x"); the
	 * tcx attach point below comes from the expected attach type. */
	bpf_program__set_type(prog_ingress_, BPF_PROG_TYPE_SCHED_CLS);
	bpf_program__set_type(prog_egress_, BPF_PROG_TYPE_SCHED_CLS);
	bpf_program__set_expected_attach_type(prog_ingress_, BPF_TCX_INGRESS);
	bpf_program__set_expected_attach_type(prog_egress_, BPF_TCX_EGRESS);

	if (bpf_object__load(obj_) != 0) {
		if (err)
			*err = libbpf_msg("bpf_object__load");
		bpf_object__close(obj_);
		obj_ = nullptr;
		return false;
	}
	return true;
}

bool Bpf::attach(uint32_t ifindex, std::string *err)
{
	if (ifindex == 0) {
		if (err)
			*err = "attach: invalid ifindex";
		return false;
	}
	Links &l = atts_[ifindex];
	if (l.in && l.eg)
		return true;

	if (!l.in) {
		l.in = bpf_program__attach_tcx(prog_ingress_, static_cast<int>(ifindex), nullptr);
		if (!l.in) {
			if (err)
				*err = libbpf_msg("attach_tcx ingress");
			return false;
		}
	}
	if (!l.eg) {
		l.eg = bpf_program__attach_tcx(prog_egress_, static_cast<int>(ifindex), nullptr);
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
}

bool Bpf::attached(uint32_t ifindex) const
{
	const auto it = atts_.find(ifindex);
	return it != atts_.end() && it->second.in && it->second.eg;
}

bool Bpf::snapshot_keys(std::vector<std::string> &out) const
{
	out.clear();
	if (!flows_)
		return false;

	const size_t ksz = bpf_map__key_size(flows_);
	int fd = bpf_map__fd(flows_);

	std::string prev(ksz, '\0');
	std::string next(ksz, '\0');
	bool first = true;

	for (;;) {
		const void *cur = first ? nullptr : prev.data();
		if (bpf_map_get_next_key(fd, cur, next.data()) != 0) {
			if (errno == ENOENT) /* end of map */
				return true;
			return false;
		}
		out.push_back(next);
		prev.swap(next);
		first = false;
	}
}

bool Bpf::lookup(const std::string &key, std::string &value) const
{
	if (!flows_ || key.size() != bpf_map__key_size(flows_))
		return false;

	const size_t vsz = bpf_map__value_size(flows_);
	std::string raw(vsz, '\0');
	if (bpf_map__lookup_elem(flows_, key.data(), key.size(), raw.data(), raw.size(), 0) != 0)
		return false; /* LRU-evicted between iteration and read */
	value.swap(raw);
	return true;
}

bool Bpf::erase(const std::string &key) const
{
	if (!flows_)
		return false;
	return bpf_map__delete_elem(flows_, key.data(), key.size(), 0) == 0;
}

void Bpf::purge_ifindex(uint32_t ifindex)
{
	std::vector<std::string> keys;
	if (!snapshot_keys(keys))
		return;
	for (const std::string &k : keys) {
		if (parse_key(k).ifindex == ifindex)
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

void Bpf::bpf_stats(uint64_t out[4]) const
{
	for (uint32_t i = 0; i < 4; i++) {
		out[i] = 0;
		if (stats_)
			bpf_map__lookup_elem(stats_, &i, sizeof(i), &out[i], sizeof(out[i]), 0);
	}
}

/* ---------------- BpfFlowMap ---------------- */

void BpfFlowMap::reset()
{
	snapshot_.clear();
	pos_ = 0;
	if (b_)
		b_->snapshot_keys(snapshot_);
}

bool BpfFlowMap::next_key(std::string &key)
{
	if (pos_ >= snapshot_.size())
		return false;
	key = snapshot_[pos_++];
	return true;
}

bool BpfFlowMap::get(const std::string &key, std::string &value)
{
	return b_->lookup(key, value);
}

bool BpfFlowMap::delete_key(const std::string &key)
{
	return b_->erase(key);
}

} /* namespace obserwrt */