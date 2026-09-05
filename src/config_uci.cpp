/*
 * obserwrt - configuration backend for OpenWrt (config_uci.cpp)
 *
 * Reads the "obserwrt" UCI package (/etc/config/obserwrt) via libuci into the
 * Config facade. No exceptions (matches the -fno-exceptions build); failures
 * surface through the out `error` parameter, and a missing package yields
 * defaults (startup with zero matching devices is a successful READY state).
 *
 * `load_config(path)`: an absolute `path` is loaded directly as a UCI file
 * (supports -c overrides and tests); an empty path reads the "obserwrt"
 * package from the default config dir.
 */

#include <uci.h>

#include <unistd.h>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <string>
#include <system_error>
#include <vector>

#include "config.hpp"

namespace obserwrt
{

namespace
{

/* libuci error -> short label (uci.h exposes no strerror) + a fatal flag.
 * NOTFOUND (missing package/file) is the READY-defaults case, not an error. */
const char *uci_err_label(int rc, bool &fatal)
{
	switch (rc) {
	case UCI_ERR_NOTFOUND:
		fatal = false; /* absent config -> defaults */
		return "not found";
	case UCI_ERR_MEM:
		fatal = true;
		return "out of memory";
	case UCI_ERR_INVAL:
		fatal = true;
		return "invalid argument";
	case UCI_ERR_IO:
		fatal = true;
		return "I/O error";
	case UCI_ERR_PARSE:
		fatal = true;
		return "parse error";
	case UCI_ERR_DUPLICATE:
		fatal = true;
		return "duplicate";
	default:
		fatal = true;
		return "unknown error";
	}
}

bool bool_option(const char *v, bool fallback)
{
	if (!v)
		return fallback;
	if (strcmp(v, "1") == 0 || strcmp(v, "on") == 0 || strcmp(v, "true") == 0 ||
	    strcmp(v, "yes") == 0 || strcmp(v, "enabled") == 0)
		return true;
	if (strcmp(v, "0") == 0 || strcmp(v, "off") == 0 || strcmp(v, "false") == 0 ||
	    strcmp(v, "no") == 0 || strcmp(v, "disabled") == 0)
		return false;
	return fallback;
}

const char *option(uci_context *ctx, uci_section *s, const char *k)
{
	return uci_lookup_option_string(ctx, s, k);
}

/* Non-negative integer option in [0, hi]; missing -> def. On a present-but-
 * invalid value fills `*err` (fatal config error) and leaves out = def. */
bool parse_uint(uci_context *ctx, uci_section *s, const char *k, uint64_t def, uint64_t hi,
		const std::string &label, uint64_t &out, std::string *err)
{
	out = def;
	const char *v = option(ctx, s, k);
	if (!v || !*v)
		return true;

	uint64_t r = 0;
	const char *last = v + std::strlen(v);
	const auto [ptr, ec] = std::from_chars(v, last, r);
	if (ec != std::errc() || ptr != last) {
		if (err)
			*err = label + ": invalid value: " + v;
		return false;
	}
	if (r > hi) {
		if (err)
			*err = label + ": out of range";
		return false;
	}
	out = r;
	return true;
}

/* `list device` entries (and a single-string fallback). */
void parse_devices(uci_section *s, Config &cfg)
{
	struct uci_element *e;
	uci_foreach_element(&s->options, e)
	{
		struct uci_option *o = uci_to_option(e);
		if (strcmp(o->e.name, "device") != 0)
			continue;
		if (o->type == UCI_TYPE_LIST) {
			struct uci_element *el;
			uci_foreach_element(&o->v.list, el) cfg.devices.push_back(el->name);
		} else if (o->type == UCI_TYPE_STRING && o->v.string) {
			cfg.devices.push_back(o->v.string);
		}
	}
}

void fill(struct uci_context *ctx, const std::string &target, Config &cfg, std::string *err)
{
	struct uci_package *pkg = nullptr;
	/* uci_load loads a file when `target` contains '/' (path), else a package
	 * from the config dir. A missing package/file is the READY-defaults case
	 * (startup with zero configured devices is success); parse, I/O and
	 * permission failures are surfaced as fatal config errors so a broken
	 * config doesn't silently start the daemon with defaults. */
	int rc = uci_load(ctx, target.c_str(), &pkg);
	if (rc != UCI_OK) {
		bool fatal = true;
		uci_err_label(rc, fatal);
		if (fatal && err) {
			*err = std::string("config: uci_load ") + target + ": " +
			       uci_err_label(rc, fatal);
		}
		return;
	}

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e)
	{
		struct uci_section *s = uci_to_section(e);
		if (!s->type)
			continue;

		if (strcmp(s->type, "obserwrt") == 0) {
			parse_devices(s, cfg);
			parse_uint(ctx, s, "tcp_timeout", 300, 86400, "tcp_timeout",
				   cfg.timeouts.tcp, err);
			parse_uint(ctx, s, "udp_timeout", 60, 86400, "udp_timeout",
				   cfg.timeouts.udp, err);
			parse_uint(ctx, s, "icmp_timeout", 30, 86400, "icmp_timeout",
				   cfg.timeouts.icmp, err);
			parse_uint(ctx, s, "general_timeout", 10, 86400, "general_timeout",
				   cfg.timeouts.general, err);
			uint64_t flows = 0;
			if (parse_uint(ctx, s, "max_flows", 0, 1ULL << 30, "max_flows", flows, err))
				cfg.max_flows = static_cast<uint32_t>(flows);
			const char *ll = option(ctx, s, "log_level");
			cfg.log_level = log_level_from_string(ll ? ll : "", LOG_NOTICE);
			const char *tf = option(ctx, s, "prometheus_textfile");
			if (tf)
				cfg.prometheus_textfile = tf;
			uint64_t pi = 0;
			if (parse_uint(ctx, s, "prometheus_interval", 20, 86400,
				       "prometheus_interval", pi, err))
				cfg.prometheus_interval = static_cast<uint32_t>(pi);
		} else if (strcmp(s->type, "exporter_ipfix") == 0) {
			cfg.ipfix.enabled = bool_option(option(ctx, s, "enabled"), false);
			const char *h = option(ctx, s, "collector_host");
			cfg.ipfix.collector_host = h ? h : "";
			uint64_t p = 0;
			if (parse_uint(ctx, s, "collector_port", 4739, 65535, "collector_port", p,
				       err))
				cfg.ipfix.collector_port = static_cast<uint16_t>(p);
			uint64_t d = 0;
			if (parse_uint(ctx, s, "observation_domain", 1, 4294967295ULL,
				       "observation_domain", d, err))
				cfg.ipfix.obs_domain = static_cast<uint32_t>(d);
			const char *sa = option(ctx, s, "source_address");
			cfg.ipfix.source_address = sa ? sa : "";
		} else if (strcmp(s->type, "exporter_syslog") == 0) {
			cfg.syslog.enabled = bool_option(option(ctx, s, "enabled"), false);
			const char *sh = option(ctx, s, "syslog_host");
			cfg.syslog.syslog_host = sh ? sh : "";
			uint64_t p = 0;
			if (parse_uint(ctx, s, "syslog_port", 514, 65535, "syslog_port", p, err))
				cfg.syslog.syslog_port = static_cast<uint16_t>(p);
			const char *proto = option(ctx, s, "protocol");
			cfg.syslog.protocol = proto ? proto : "udp";
			const char *f = option(ctx, s, "format");
			cfg.syslog.format = f ? f : "json";
			const char *host = option(ctx, s, "hostname");
			cfg.syslog.hostname = host ? host : "";
			const char *sa = option(ctx, s, "source_address");
			cfg.syslog.source_address = sa ? sa : "";
		}
	}

	if (cfg.ipfix.enabled && cfg.ipfix.collector_host.empty()) {
		if (err)
			*err = "ipfix: enabled but no collector_host configured";
	}
}

} /* namespace */

Config load_config(const std::string &path, std::string *err)
{
	if (err)
		err->clear();

	uci_context *ctx = uci_alloc_context();
	if (!ctx) {
		if (err)
			*err = "uci_alloc_context failed";
		return Config{};
	}

	Config cfg;
	fill(ctx, path.empty() ? "obserwrt" : path, cfg, err);
	uci_free_context(ctx);
	return cfg;
}

Config load_config_string(const std::string &text, std::string *err)
{
	if (err)
		err->clear();

	char tmpl[] = "/tmp/obserwrt-uci-XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) {
		if (err)
			*err = "mkstemp failed";
		return Config{};
	}

	size_t off = 0;
	while (off < text.size()) {
		ssize_t n = write(fd, text.data() + off, text.size() - off);
		if (n <= 0)
			break;
		off += static_cast<size_t>(n);
	}
	close(fd);

	Config cfg = load_config(tmpl, err);
	unlink(tmpl);
	return cfg;
}

} /* namespace obserwrt */
