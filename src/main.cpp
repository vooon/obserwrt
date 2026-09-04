/*
 * obserwrt - daemon entry (main.cpp)
 *
 * Bootstrap: parse CLI, load config, wire exporters + lifecycle, then run the
 * steady-state loop. The epoll/timer event loop and libbpf map access land in
 * the reconciliation/BPF step; the loop currently drives an empty map so the
 * service structure and lifecycle/export plumbing run end-to-end.
 */

#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "cli.hpp"
#include "config.hpp"
#include "exporter_ipfix.hpp"
#include "exporter_syslog.hpp"
#include "lifecycle.hpp"
#include "metrics.hpp"

namespace
{

/* Placeholder map: no flows until the libbpf batch walk lands. */
struct EmptyMap : obserwrt::FlowMap {
	bool next_key(std::string &) override
	{
		return false;
	}
	bool get(const std::string &, std::string &) override
	{
		return false;
	}
	bool delete_key(const std::string &) override
	{
		return false;
	}
};

uint64_t mono_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
	       static_cast<uint64_t>(ts.tv_nsec / 1000000);
}

} /* namespace */

int main(int argc, char **argv)
{
	int exit_code = 0;
	const auto cli = obserwrt::parse_args(argc, argv, &exit_code);
	if (!cli)
		return exit_code;

	const std::string config_path = cli->config_path.empty()
					    ? std::string(obserwrt::Cli::default_config_path())
					    : cli->config_path;

	std::string bpf_object = cli->bpf_object_path;
	if (bpf_object.empty()) {
		const char *env = getenv("BPF_OBJ");
		bpf_object = env ? env : std::string(obserwrt::Cli::default_bpf_object());
	}

	std::string err;
	const obserwrt::Config cfg = obserwrt::load_config(config_path, &err);
	if (!err.empty()) {
		std::fprintf(stderr, "obserwrt: fatal: %s\n", err.c_str());
		return 1;
	}

	obserwrt::Metrics metrics;
	metrics.init(cfg);

	obserwrt::IpfixExporter ipfix(cfg.ipfix.obs_domain);
	obserwrt::SyslogExporter syslog;
	obserwrt::Lifecycle lifecycle(cfg.timeouts);
	EmptyMap map;

	std::string syslog_err;
	const bool syslog_active = syslog.init(cfg.syslog, &syslog_err);
	if (!syslog_err.empty())
		std::fprintf(stderr, "obserwrt: syslog: %s\n", syslog_err.c_str());
	if (cfg.ipfix.enabled)
		openlog("obserwrt", LOG_PID, LOG_DAEMON);

	const uint32_t start_s = static_cast<uint32_t>(time(nullptr));
	/* Monotonic -> epoch offset so exporters can convert flow timestamps
	 * (CLOCK_MONOTONIC ms, same base as bpf_ktime_get_ns). */
	const uint64_t offset_ms = static_cast<uint64_t>(start_s) * 1000ULL - mono_ms();
	ipfix.set_epoch(start_s, offset_ms);
	if (cfg.ipfix.enabled)
		ipfix.send_templates(start_s);

	if (!cfg.ipfix.enabled && !syslog_active)
		std::fprintf(stderr,
			     "obserwrt: no exporters enabled; observations will not be exported\n");

	std::fprintf(
	    stderr,
	    "obserwrt: started (config %s, bpf %s, devices %zu, ipfix %s, syslog %s, metrics %s)\n",
	    config_path.c_str(), bpf_object.c_str(), cfg.devices.size(),
	    cfg.ipfix.enabled ? "on" : "off", syslog_active ? "on" : "off",
	    metrics.active() ? cfg.prometheus_textfile.c_str() : "off");

	unsigned metric_tick = 0;
	const uint32_t lidx = cfg.prometheus_interval > 0 ? cfg.prometheus_interval : 20;
	metrics.write();

	for (;;) {
		/* Steady-state pass; BPF map walk + device reconciliation follow. */
		const uint32_t now_s = static_cast<uint32_t>(time(nullptr));
		const obserwrt::Lifecycle::Stats n =
		    lifecycle.run(map, [&](const obserwrt::FlowKey &k, const obserwrt::FlowValue &v,
					   bool expired, const obserwrt::Delta &delta) {
			    metrics.observe();
			    if (cfg.ipfix.enabled)
				    ipfix.emit(k, v, &delta);
			    if (syslog_active)
				    syslog.emit(k, v, expired, &delta);
		    });

		if (cfg.ipfix.enabled)
			ipfix.flush(now_s);

		metrics.set_state(n.active, n.map, cfg.devices);

		if (++metric_tick >= lidx) {
			metric_tick = 0;
			metrics.write();
		}

		sleep(1);
	}
}
