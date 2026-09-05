/*
 * obserwrt - configuration facade (config.hpp)
 *
 * Single Config struct reads by two backend implementations:
 *   - config_uci.cpp (OpenWrt, OBSEWRRT_USE_LIBUCI): /etc/config/obserwrt
 *   - config_mini.cpp (plain Linux): vendored inifile-cpp, /etc/obserwrt.conf
 * The rest of the daemon only sees the Config struct.
 */

#pragma once

#include <syslog.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "lifecycle.hpp"

namespace obserwrt
{

/* Map a config log_level string to a syslog priority; unknown -> def. */
inline int log_level_from_string(std::string_view s, int def)
{
	if (s == "debug")
		return LOG_DEBUG;
	if (s == "info")
		return LOG_INFO;
	if (s == "notice")
		return LOG_NOTICE;
	if (s == "warning" || s == "warn")
		return LOG_WARNING;
	if (s == "error" || s == "err")
		return LOG_ERR;
	return def;
}

struct Config {
	std::vector<std::string> devices;
	Timeouts timeouts;

	/* Daemon diagnostic verbosity (syslog priority; debug shows the per-pass
	 * lifecycle line). */
	int log_level = LOG_NOTICE;

	/* Flow-map LRU capacity; 0 = baked-in default of the loaded BPF object. */
	uint32_t max_flows = 0;

	/* Self-observability (Prometheus textfile collector). Empty disables. */
	std::string prometheus_textfile;
	uint32_t prometheus_interval = 20;

	struct Ipfix {
		bool enabled = false;
		std::string collector_host;
		uint16_t collector_port = 4739;
		std::string source_address;
		uint32_t obs_domain = 1;
	} ipfix;

	struct Syslog {
		bool enabled = false;
		std::string syslog_host; /* empty = process-local syslog(3) */
		uint16_t syslog_port = 514;
		std::string protocol = "udp";
		std::string format = "json"; /* json | logfmt */
		std::string hostname;	     /* RFC 5424 HOSTNAME; empty = router hostname */
		std::string source_address;
	} syslog;
};

/* Read the config at `path`. Missing file -> defaults (zero matching devices,
 * no exporters). A fatal parse/config error fills `*error` (empty otherwise);
 * the config parser's exceptions never escape this boundary (daemon builds
 * use -fno-exceptions). */
Config load_config(const std::string &path, std::string *error);

/* Parse the option-set from an in-memory string (tests); same error contract. */
Config load_config_string(const std::string &text, std::string *error);

} /* namespace obserwrt */
