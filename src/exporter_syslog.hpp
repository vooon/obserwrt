/*
 * obserwrt - syslog flow exporter (exporter_syslog.hpp)
 *
 * Port of exporter_syslog.uc: normalized observation as JSON or logfmt.
 * Empty syslog_host -> process-local syslog(3) (logd/journald); a non-empty
 * host -> one connected UDP socket for the daemon lifetime, RFC 5424 framing
 * with `obserwrt` as the application name (docs/design.md §8.2).
 *
 * Encoding primitives are static so the golden-vector harness can pin them
 * against the ucode exporter's expected output.
 */

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <ctime>
#include <functional>
#include <string>

#include "config.hpp"
#include "flow.hpp"

namespace obserwrt
{

class SyslogExporter
{
      public:
	using SendFn = std::function<void(const std::string &)>;
	using IfnameFn = std::function<std::string(uint32_t)>;

	SyslogExporter() = default;

	/* Test sink / socket override. */
	void set_sink(SendFn sink)
	{
		sink_ = std::move(sink);
	}

	/* ifindex -> netdev name (reconcile provides the map); default = the
	 * numeric ifindex, matching the ucode exporter's ifname() fallback. */
	void set_ifnames(IfnameFn fn)
	{
		ifnames_ = std::move(fn);
	}

	/* Enable from the exporter_syslog config section. Returns true when the
	 * exporter becomes active. */
	bool init(const Config::Syslog &cfg, std::string *error);

	bool active() const
	{
		return enabled_;
	}

	/* Emit one observation (delta supplied by the lifecycle; fallback to
	 * cumulative counters when null - identical to exporter_ipfix). */
	void emit(const FlowKey &k, const FlowValue &v, bool expired, const Delta *delta);

	/* ---- encoding primitives (harness-pinned) ---- */

	static std::string encode_json(const FlowKey &k, const FlowValue &v, bool expired,
				       const Delta *delta, const std::string &ifname);
	static std::string encode_logfmt(const FlowKey &k, const FlowValue &v, bool expired,
					 const Delta *delta, const std::string &ifname);
	static std::string encode(const FlowKey &k, const FlowValue &v, bool expired,
				  const Delta *delta, const std::string &ifname,
				  const std::string &format);

	/* RFC 5424 envelope: <134>1 TIMESTAMP HOSTNAME obserwrt - - - MSG. */
	static std::string frame(const std::string &message, const std::string &hostname,
				 std::time_t now);

      private:
	bool enabled_ = false;
	bool local_ = false;
	std::string format_ = "json";
	std::string host_ = ""; /* RFC 5424 HOSTNAME */
	SendFn sink_;
	IfnameFn ifnames_;

	int fd_ = -1;
	sockaddr_in addr_ = {};

	std::string deliver(const std::string &message);
	bool connect_remote(const std::string &host, uint16_t port, const std::string &source_addr,
			    std::string *error);
};

} /* namespace obserwrt */