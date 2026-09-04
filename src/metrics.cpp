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

#include "version.hpp"

namespace obserwrt
{

namespace
{

void prom_line(std::string &out, const char *name, const char *labels, const char *value)
{
	out += name;
	out += labels;
	out += ' ';
	out += value;
	out += '\n';
}

} /* namespace */

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

void Metrics::write()
{
	if (!active_)
		return;

	std::string out;

	/* Build information: constant gauge, low cardinality. */
	out += "# HELP obserwrt_build_info Build and version information.\n";
	out += "# TYPE obserwrt_build_info gauge\n";
	{
		const BuildInfo b = build_info();
		std::string labels;
		labels.reserve(96);
		labels += "{version=\"";
		labels.append(b.version);
		labels += "\",commit=\"";
		labels.append(b.commit);
		labels += "\",os=\"";
		labels.append(b.os);
		labels += "\",arch=\"";
		labels.append(b.arch);
		labels += "\"}";
		prom_line(out, "obserwrt_build_info", labels.c_str(), "1");
	}

	out += "# TYPE obserwrt_flows_exported_total counter\n";
	prom_line(out, "obserwrt_flows_exported_total", "", std::to_string(total_flows_).c_str());
	out += "# TYPE obserwrt_export_errors_total counter\n";
	prom_line(out, "obserwrt_export_errors_total", "", std::to_string(total_errors_).c_str());
	out += "# TYPE obserwrt_packets_total counter\n";
	prom_line(out, "obserwrt_packets_total", "", std::to_string(bpf_packets_).c_str());
	out += "# TYPE obserwrt_bytes_total counter\n";
	prom_line(out, "obserwrt_bytes_total", "", std::to_string(bpf_bytes_).c_str());
	out += "# TYPE obserwrt_packets_accounted_total counter\n";
	prom_line(out, "obserwrt_packets_accounted_total", "",
		  std::to_string(bpf_accounted_).c_str());
	out += "# TYPE obserwrt_flows_created_total counter\n";
	prom_line(out, "obserwrt_flows_created_total", "",
		  std::to_string(bpf_flows_created_).c_str());
	out += "# TYPE obserwrt_flows_active gauge\n";
	prom_line(out, "obserwrt_flows_active", "", std::to_string(flows_active_).c_str());
	out += "# TYPE obserwrt_bpf_map_entries gauge\n";
	prom_line(out, "obserwrt_bpf_map_entries", "", std::to_string(map_entries_).c_str());
	out += "# TYPE obserwrt_devices_attached gauge\n";
	prom_line(out, "obserwrt_devices_attached", "", std::to_string(devices_.size()).c_str());
	out += "# TYPE obserwrt_device_attached gauge\n";
	for (const auto &d : devices_) {
		std::string labels;
		labels.reserve(d.size() + 16);
		labels += "{ifname=\"";
		labels.append(d);
		labels += "\"}";
		prom_line(out, "obserwrt_device_attached", labels.c_str(), "1");
	}

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