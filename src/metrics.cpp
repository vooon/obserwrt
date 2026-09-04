/*
 * obserwrt - Prometheus self-observability (metrics.cpp)
 *
 * Formatting adapted from node-exporter-ucode / the fw4 ucode metrics module
 * (Apache-2.0). The textfile is rewritten via temp-file + atomic rename.
 * obserwrt_build_info carries the compiled build/version info.
 */

#include "metrics.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "prometheus.hpp"
#include "version.hpp"

namespace obserwrt
{

void Metrics::init(const Config &cfg)
{
	file_ = cfg.prometheus_textfile;
	interval_s_ = cfg.prometheus_interval;
	active_ = !file_.empty();
}

void Metrics::observe()
{
	if (active_)
		total_flows_++;
}

void Metrics::record_error()
{
	if (active_)
		total_errors_++;
}

void Metrics::set_state(unsigned flows_active, unsigned map_entries,
			const std::vector<std::string> &devices)
{
	if (!active_)
		return;
	flows_active_ = flows_active;
	map_entries_ = map_entries;
	devices_ = devices;
}

void Metrics::set_bpf(unsigned long long packets, unsigned long long bytes,
		      unsigned long long accounted, unsigned long long flows_created)
{
	if (!active_)
		return;
	bpf_packets_ = packets;
	bpf_bytes_ = bytes;
	bpf_accounted_ = accounted;
	bpf_flows_created_ = flows_created;
}

void Metrics::set_map_limit(uint32_t limit)
{
	if (!active_)
		return;
	map_limit_ = limit;
}

void Metrics::write()
{
	if (!active_)
		return;

	PromExposition px;

	/* Build information: constant gauge, low cardinality. */
	const BuildInfo b = build_info();
	px.gauge("obserwrt_build_info", "Build and version information.",
		 PromExposition::labels({
		     {"version", b.version.data()},
		     {"commit", b.commit.data()},
		     {"os", b.os.data()},
		     {"arch", b.arch.data()},
		 }),
		 1);

	px.counter("obserwrt_flows_exported_total", "Flow records dispatched to exporters.", "",
		   total_flows_);
	px.counter("obserwrt_export_errors_total", "Export/lifecycle failures.", "", total_errors_);
	px.counter("obserwrt_packets_total", "Packets seen at TC (all, incl. non-IP).", "",
		   bpf_packets_);
	px.counter("obserwrt_bytes_total", "Bytes seen at TC (all).", "", bpf_bytes_);
	px.counter("obserwrt_packets_accounted_total", "Packets that entered flow accounting (IP).",
		   "", bpf_accounted_);
	px.counter("obserwrt_flows_created_total", "Flow entries created in the BPF map.", "",
		   bpf_flows_created_);
	px.gauge("obserwrt_flows_active", "Currently live flows.", "", flows_active_);
	px.gauge("obserwrt_bpf_map_entries", "Current flow map entries.", "", map_entries_);
	px.gauge("obserwrt_bpf_map_limit", "Flow map capacity (LRU).", "", map_limit_);
	px.gauge("obserwrt_devices_attached", "Number of attached netdevs.", "",
		 static_cast<uint64_t>(devices_.size()));

	for (const auto &d : devices_)
		px.gauge("obserwrt_device_attached", "Attached netdev (1 if attached).",
			 PromExposition::labels({{"ifname", d.c_str()}}), 1);

	const std::string &out = px.str();

	const std::string tmp = file_ + ".tmp";
	int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		std::fprintf(stderr, "metrics: cannot write %s: %s\n", tmp.c_str(),
			     std::strerror(errno));
		return;
	}

	bool ok = true;
	size_t off = 0;
	while (off < out.size()) {
		ssize_t n = ::write(fd, out.data() + off, out.size() - off);
		if (n < 0) {
			ok = false;
			break;
		}
		off += static_cast<size_t>(n);
	}
	close(fd);
	if (!ok) {
		unlink(tmp.c_str());
		return;
	}

	if (rename(tmp.c_str(), file_.c_str()) != 0) {
		std::fprintf(stderr, "metrics: cannot rename %s: %s\n", tmp.c_str(),
			     std::strerror(errno));
		unlink(tmp.c_str());
	}
}

} /* namespace obserwrt */
