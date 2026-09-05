/*
 * obserwrt - daemon entry (main.cpp)
 *
 * Bootstrap: CLI -> config -> exporters -> eBPF load -> reconcile, then an
 * epoll loop over the rtnetlink socket + timerfds (5s lifecycle, metrics
 * interval). Device events attach/detach the TC programs (real ifindex) and
 * purge the device's flows on removal; the lifecycle walks the flow map and
 * hands deltas to the exporters.
 */

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <fnmatch.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "bpf.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "exporter_ipfix.hpp"
#include "exporter_syslog.hpp"
#include "lifecycle.hpp"
#include "metrics.hpp"
#include "reconcile.hpp"
#include "udp_client.hpp"

#include "log.hpp"

namespace
{

constexpr int LIFECYCLE_S = 5;

uint64_t mono_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
	       static_cast<uint64_t>(ts.tv_nsec / 1000000);
}

/* fnmatch against the configured device patterns. */
bool match_device(const std::string &name, const std::vector<std::string> &pats)
{
	for (const std::string &p : pats) {
		if (fnmatch(p.c_str(), name.c_str(), 0) == 0)
			return true;
	}
	return false;
}

int make_timer(uint32_t interval_s, std::string *err)
{
	struct itimerspec ts;
	std::memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_sec = interval_s;
	ts.it_interval.tv_sec = interval_s;
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (fd < 0 || timerfd_settime(fd, 0, &ts, nullptr) != 0) {
		if (err)
			*err = "timerfd: " + std::string(std::strerror(errno));
		return -1;
	}
	return fd;
}

void drain_timer(int fd)
{
	uint64_t exp;
	/* timerfd read() carries warn_unused_result under _FORTIFY_SOURCE; the
	 * value itself is irrelevant - we only need the fd drained. */
	const ssize_t n = read(fd, &exp, sizeof(exp));
	(void)n;
}

} /* namespace */

int main(int argc, char **argv)
{
	int exit_code = 0;
	const auto cli = obserwrt::parse_args(argc, argv, &exit_code);
	if (!cli)
		return exit_code;

	/* Diagnostics go to syslog(3) (logd/journald) regardless of how procd
	 * wires the fds - that is why they are visible in logread on OpenWrt. */
	openlog("obserwrt", LOG_PID, LOG_DAEMON);

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
		DAEMON_LOG(LOG_ERR, "fatal: %s", err.c_str());
		return 1;
	}
	obserwrt::g_log_level = cfg.log_level;

	obserwrt::Metrics metrics;
	metrics.init(cfg);
	metrics.set_map_limit(0); /* filled from bpf_map_info below */

	obserwrt::IpfixExporter ipfix(cfg.ipfix.obs_domain);
	obserwrt::SyslogExporter syslog;
	std::string syslog_err;
	const bool syslog_active = syslog.init(cfg.syslog, &syslog_err);
	if (!syslog_err.empty())
		DAEMON_LOG(LOG_WARNING, "syslog: %s", syslog_err.c_str());

	obserwrt::UdpClient ipfix_udp;
	if (cfg.ipfix.enabled) {
		if (!ipfix_udp.connect(cfg.ipfix.collector_host, cfg.ipfix.collector_port,
				       cfg.ipfix.source_address, &err)) {
			DAEMON_LOG(LOG_ERR, "fatal: %s", err.c_str());
			return 1;
		}
		ipfix.set_sink([&](const std::string &data) {
			if (!ipfix_udp.send(data))
				metrics.record_error(); /* obserwrt_export_errors_total */
		});
	}

	const uint32_t start_s = static_cast<uint32_t>(time(nullptr));
	const uint64_t offset_ms = static_cast<uint64_t>(start_s) * 1000ULL - mono_ms();
	ipfix.set_epoch(start_s, offset_ms);
	if (cfg.ipfix.enabled)
		ipfix.send_templates(start_s);

	obserwrt::Bpf bpf;
	if (!bpf.load(bpf_object, cfg.max_flows, &err)) {
		DAEMON_LOG(LOG_ERR, "fatal: bpf: %s", err.c_str());
		return 1;
	}
	metrics.set_map_limit(bpf.map_limit());

	obserwrt::BpfFlowMap flowmap(&bpf);
	obserwrt::Lifecycle lifecycle(cfg.timeouts);

	obserwrt::Reconcile rec;
	if (!rec.open(&err)) {
		DAEMON_LOG(LOG_ERR, "fatal: %s", err.c_str());
		return 1;
	}

	/* ifindex -> netdev name for the syslog exporter's ifname field. */
	std::map<uint32_t, std::string> name_by_index;
	std::vector<std::string> attached_names;

	auto refresh_names = [&] {
		attached_names.clear();
		for (const auto &kv : name_by_index)
			attached_names.push_back(kv.second);
	};
	syslog.set_ifnames([&](uint32_t idx) -> std::string {
		const auto it = name_by_index.find(idx);
		return it != name_by_index.end() ? it->second : std::to_string(idx);
	});

	/* Attach/detach on rtnetlink link events (design §6; rtnetlink replaces
	 * netifd): up|newlink -> attach with the current real ifindex, down|gone
	 * -> detach + purge the device's flows. An ifindex already attached is
	 * reconciled by its CURRENT state and name first: a rename to a
	 * non-matching name detaches, a matching->matching rename refreshes the
	 * stored name. */
	auto on_link = [&](const obserwrt::LinkEvent &ev) {
		const bool attached = bpf.attached(ev.ifindex);
		const bool wanted = ev.present && ev.up && match_device(ev.ifname, cfg.devices);

		if (attached) {
			if (!wanted) {
				DAEMON_LOG(LOG_NOTICE, "detached %s (ifindex %u)",
					   ev.ifname.c_str(), ev.ifindex);
				bpf.detach(ev.ifindex);
				bpf.purge_ifindex(ev.ifindex);
				name_by_index.erase(ev.ifindex);
			} else if (name_by_index[ev.ifindex] != ev.ifname) {
				name_by_index[ev.ifindex] = ev.ifname;
				DAEMON_LOG(LOG_NOTICE, "renamed %s (ifindex %u)", ev.ifname.c_str(),
					   ev.ifindex);
			}
		} else if (wanted) {
			if (bpf.attach(ev.ifindex, &err)) {
				name_by_index[ev.ifindex] = ev.ifname;
				DAEMON_LOG(LOG_NOTICE, "attached %s (ifindex %u)",
					   ev.ifname.c_str(), ev.ifindex);
			} else
				DAEMON_LOG(LOG_WARNING, "attach %s: %s", ev.ifname.c_str(),
					   err.c_str());
		}
		refresh_names();
	};

	if (!rec.dump(on_link, &err)) {
		/* Reconciliation has no periodic rescan: a failed initial dump leaves
		 * already-up devices unattached until an unrelated link event, so
		 * fail hard and let procd/systemd restart into a clean reconcile. */
		DAEMON_LOG(LOG_ERR, "fatal: reconcile dump: %s", err.c_str());
		return 1;
	}

	if (!cfg.ipfix.enabled && !syslog_active)
		DAEMON_LOG(LOG_WARNING, "no exporters enabled; observations will not be exported");

	DAEMON_LOG(LOG_INFO,
		   "started (config %s, bpf %s, devices %zu, ipfix %s, syslog %s, metrics %s)",
		   config_path.c_str(), bpf_object.c_str(), cfg.devices.size(),
		   cfg.ipfix.enabled ? "on" : "off", syslog_active ? "on" : "off",
		   metrics.active() ? cfg.prometheus_textfile.c_str() : "off");

	const uint32_t metric_s = cfg.prometheus_interval > 0 ? cfg.prometheus_interval : 20;
	int ep = epoll_create1(EPOLL_CLOEXEC);
	int t_life = make_timer(LIFECYCLE_S, &err);
	int t_meter = make_timer(metric_s, &err);
	if (ep < 0 || t_life < 0 || t_meter < 0) {
		DAEMON_LOG(LOG_ERR, "fatal: %s", err.c_str());
		return 1;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = rec.fd();
	epoll_ctl(ep, EPOLL_CTL_ADD, rec.fd(), &ev);
	ev.data.fd = t_life;
	epoll_ctl(ep, EPOLL_CTL_ADD, t_life, &ev);
	ev.data.fd = t_meter;
	epoll_ctl(ep, EPOLL_CTL_ADD, t_meter, &ev);

	metrics.write();

	struct epoll_event events[8];
	for (;;) {
		int n = epoll_wait(ep, events, 8, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			DAEMON_LOG(LOG_ERR, "epoll: %s", std::strerror(errno));
			return 1;
		}

		for (int i = 0; i < n; i++) {
			const int f = events[i].data.fd;

			if (f == rec.fd()) {
				char buf[65536];
				bool resync = false;
				for (;;) {
					ssize_t r = recv(rec.fd(), buf, sizeof(buf), 0);
					if (r == 0)
						break;
					if (r < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						/* ENOBUFS and friends lose link notifications; a
						 * missed down/up/rename leaves TC + names stale, so
						 * resync from a fresh dump. */
						DAEMON_LOG(LOG_WARNING, "netlink recv: %s",
							   std::strerror(errno));
						resync = true;
						break;
					}
					rec.dispatch(buf, static_cast<size_t>(r), on_link);
				}
				if (resync) {
					std::string derr;
					rec.dump(on_link, &derr);
				}
			} else if (f == t_life) {
				drain_timer(t_life);
				const uint32_t now_s = static_cast<uint32_t>(time(nullptr));
				/* Refresh the realtime<-monotonic anchor each pass: if the
				 * wall clock was corrected after startup (NTP), flow
				 * flowStart/End ms keep up instead of staying pinned to
				 * the boot-time offset (design §8.1 timestamps). */
				ipfix.set_offset_ms(static_cast<uint64_t>(now_s) * 1000ULL -
						    mono_ms());
				uint64_t stat[4];
				bpf.bpf_stats(stat);
				const obserwrt::Lifecycle::Stats st = lifecycle.run(
				    flowmap,
				    [&](const obserwrt::FlowKey &k, const obserwrt::FlowValue &v,
					bool expired, const obserwrt::Delta &delta) {
					    metrics.observe();
					    if (cfg.ipfix.enabled)
						    ipfix.emit(k, v, &delta);
					    if (syslog_active)
						    syslog.emit(k, v, expired, &delta);
				    });
				if (cfg.ipfix.enabled)
					ipfix.flush(now_s);
				DAEMON_LOG(LOG_DEBUG, "pass active=%u expired=%u map=%u", st.active,
					   st.expired, st.map);
				metrics.set_state(st.active, st.map, attached_names);
				metrics.set_bpf(stat[0], stat[1], stat[3], stat[2]);
			} else if (f == t_meter) {
				drain_timer(t_meter);
				metrics.write();
			}
		}
	}
}