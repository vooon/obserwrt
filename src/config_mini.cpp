/*
 * obserwrt - configuration backend for plain Linux (config_mini.cpp)
 *
 * Uses vendored inifile-cpp (vendor/inifile.hpp, MIT). The library is
 * exception-based, so this TU is compiled with -fexceptions; parse errors are
 * caught at the load boundary and surfaced as std::runtime_error. A missing
 * path yields defaults (matches "startup with zero matching devices is a
 * successful READY state").
 *
 * Format (see linux/obserwrt.conf), mirroring the UCI option set:
 *   [main]   device = <space-separated globs>, *_timeout, max_flows,
 *            prometheus_textfile, prometheus_interval
 *   [ipfix]  enabled, collector_host, collector_port, observation_domain,
 *            source_address
 *   [syslog] enabled, syslog_host, syslog_port, protocol, format, hostname,
 *            source_address
 */

#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.hpp"

/* Vendored inifile-cpp (vendor/inifile.hpp, MIT); the vendor dir is a system
 * include so neither the compiler nor clang-tidy treats it as project code. */
#include <inifile.hpp>

namespace obserwrt
{

namespace
{

bool parse_bool(ini::IniFile &ini, const char *sec, const char *key, bool fallback)
{
	const auto v = ini[sec][key].as<std::string_view>();
	if (v == "1" || v == "on" || v == "true" || v == "yes" || v == "enabled")
		return true;
	if (v == "0" || v == "off" || v == "false" || v == "no" || v == "disabled")
		return false;
	return fallback;
}

std::string_view field(ini::IniFile &ini, const char *sec, const char *key)
{
	return ini[sec][key].as<std::string_view>();
}

/* Non-negative integer option in [0, hi]. Missing -> def; present but
 * invalid -> throw (fatal config error). */
uint64_t parse_uint(ini::IniFile &ini, const char *sec, const char *key, uint64_t def, uint64_t hi,
		    const std::string &label)
{
	const std::string_view s = field(ini, sec, key);
	if (s.empty())
		return def;

	uint64_t v = 0;
	for (char c : s) {
		if (c < '0' || c > '9') {
			std::string msg(label);
			msg += ": invalid value: ";
			msg += s;
			throw std::runtime_error(msg);
		}
		v = v * 10 + static_cast<uint64_t>(c - '0');
		if (v > hi)
			throw std::runtime_error(label + ": out of range");
	}
	return v;
}

/* Space-separated list value (device globs). */
std::vector<std::string> parse_list(ini::IniFile &ini, const char *sec, const char *key)
{
	std::vector<std::string> out;
	std::istringstream ss(std::string(field(ini, sec, key)));
	std::string tok;
	while (ss >> tok)
		out.push_back(tok);
	return out;
}

Config parse(ini::IniFile &ini)
{
	Config cfg;

	cfg.devices = parse_list(ini, "main", "device");
	cfg.timeouts.tcp = parse_uint(ini, "main", "tcp_timeout", 300, 86400, "tcp_timeout");
	cfg.timeouts.udp = parse_uint(ini, "main", "udp_timeout", 60, 86400, "udp_timeout");
	cfg.timeouts.icmp = parse_uint(ini, "main", "icmp_timeout", 30, 86400, "icmp_timeout");
	cfg.timeouts.general =
	    parse_uint(ini, "main", "general_timeout", 10, 86400, "general_timeout");
	cfg.max_flows =
	    static_cast<uint32_t>(parse_uint(ini, "main", "max_flows", 0, 1ULL << 30, "max_flows"));
	cfg.prometheus_textfile = std::string(field(ini, "main", "prometheus_textfile"));
	cfg.prometheus_interval = static_cast<uint32_t>(
	    parse_uint(ini, "main", "prometheus_interval", 20, 86400, "prometheus_interval"));

	cfg.ipfix.enabled = parse_bool(ini, "ipfix", "enabled", false);
	cfg.ipfix.collector_host = std::string(field(ini, "ipfix", "collector_host"));
	cfg.ipfix.collector_port = static_cast<uint16_t>(
	    parse_uint(ini, "ipfix", "collector_port", 4739, 65535, "collector_port"));
	cfg.ipfix.source_address = std::string(field(ini, "ipfix", "source_address"));
	cfg.ipfix.obs_domain = static_cast<uint32_t>(
	    parse_uint(ini, "ipfix", "observation_domain", 1, 4294967295ULL, "observation_domain"));

	cfg.syslog.enabled = parse_bool(ini, "syslog", "enabled", false);
	cfg.syslog.syslog_host = std::string(field(ini, "syslog", "syslog_host"));
	cfg.syslog.syslog_port = static_cast<uint16_t>(
	    parse_uint(ini, "syslog", "syslog_port", 514, 65535, "syslog_port"));
	/* Keep the struct defaults when an option is absent (empty string). */
	{
		const std::string_view p = field(ini, "syslog", "protocol");
		cfg.syslog.protocol = p.empty() ? "udp" : std::string(p);
	}
	{
		const std::string_view f = field(ini, "syslog", "format");
		cfg.syslog.format = f.empty() ? "json" : std::string(f);
	}
	cfg.syslog.hostname = std::string(field(ini, "syslog", "hostname"));
	cfg.syslog.source_address = std::string(field(ini, "syslog", "source_address"));

	if (cfg.ipfix.enabled && cfg.ipfix.collector_host.empty())
		throw std::runtime_error("ipfix: enabled but no collector_host configured");

	return cfg;
}

} /* namespace */

Config load_config_string(const std::string &text, std::string *error)
{
	if (error)
		error->clear();
	try {
		ini::IniFile ini;
		std::istringstream is(text);
		ini.decode(is);
		return parse(ini);
	} catch (const std::exception &e) {
		if (error)
			*error = e.what();
		return Config{};
	}
}

Config load_config(const std::string &path, std::string *error)
{
	if (error)
		error->clear();
	if (path.empty())
		return Config{};

	try {
		ini::IniFile ini;
		/* Missing/unreadable file decodes to an empty ini -> defaults. */
		ini.load(path);
		return parse(ini);
	} catch (const std::exception &e) {
		if (error)
			*error = e.what();
		return Config{};
	}
}

} /* namespace obserwrt */