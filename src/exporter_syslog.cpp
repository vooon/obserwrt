/*
 * obserwrt - syslog flow exporter (exporter_syslog.cpp)
 *
 * Port of exporter_syslog.uc (docs/design.md §8.2). Field order, JSON key
 * order, the logfmt layout and the RFC 5424 envelope mirror the ucode module
 * so collectors that already parse obserwrt's syslog output keep working.
 */

#include "exporter_syslog.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace obserwrt
{

namespace
{

/* One normalized observation, matching exporter_syslog.uc flow_record(). */
struct SyslogRecord {
	uint32_t ifindex;
	std::string ifname;
	std::string direction;
	uint8_t family;
	uint8_t protocol;
	uint8_t icmp_type;
	uint8_t icmp_code;
	std::string src;
	std::string dst;
	uint16_t sport;
	uint16_t dport;
	uint64_t packets;
	uint64_t bytes;
	uint64_t first_seen_ns;
	uint64_t last_seen_ns;
	uint16_t tcp_flags;
	bool expired;
};

/* Convert the 16-byte address field to text: dotted quad for family 4
 * (last 4 bytes of the ::ffff: mapping), else inet_ntop IPv6. */
std::string addr_text(const uint8_t *a, uint8_t family)
{
	if (family == 4) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
		return buf;
	}
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, a, buf, sizeof(buf));
	return buf;
}

/* JSON string escaping (ucode %J semantics for strings). */
void json_escape(std::string &out, const char *s, size_t n)
{
	out.push_back('"');
	for (size_t i = 0; i < n; i++) {
		switch (s[i]) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		default:
			out.push_back(s[i]);
		}
	}
	out.push_back('"');
}

SyslogRecord make_record(const FlowKey &k, const FlowValue &v, bool expired, const Delta *delta,
			 const std::string &ifname)
{
	SyslogRecord r;
	r.ifindex = k.ifindex;
	r.ifname = ifname;
	r.direction = (k.direction == INGRESS) ? "ingress" : "egress";
	r.family = k.family;
	r.protocol = k.protocol;
	r.icmp_type = k.icmp_type;
	r.icmp_code = k.icmp_code;
	r.src = addr_text(k.src, k.family);
	r.dst = addr_text(k.dst, k.family);
	r.sport = k.sport;
	r.dport = k.dport;
	r.packets = delta ? delta->packets : v.packets;
	r.bytes = delta ? delta->bytes : v.bytes;
	r.first_seen_ns = v.first_seen;
	r.last_seen_ns = v.last_seen;
	r.tcp_flags = v.tcp_flags;
	r.expired = expired;
	return r;
}

std::string fmt_u64(uint64_t v)
{
	char buf[32];
	std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
	return buf;
}

/* RFC 3339 UTC (RFC 5424 TIMESTAMP), identical layout to util.uc. */
void iso_timestamp(std::time_t t, char (&out)[24])
{
	struct tm tm;
	gmtime_r(&t, &tm);
	std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Router/machine hostname (RFC 5424 HOSTNAME fallback); '' if unreadable. */
std::string sys_hostname()
{
	const char *name = "/proc/sys/kernel/hostname";
	FILE *f = std::fopen(name, "r");
	if (!f)
		return "";
	char buf[129];
	size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
	std::fclose(f);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	buf[n] = '\0';
	return std::string(buf, n);
}

} /* namespace */

bool SyslogExporter::connect_remote(const std::string &host, uint16_t port,
				    const std::string &source_addr, std::string *error)
{
	char portbuf[8];
	std::snprintf(portbuf, sizeof(portbuf), "%u", port);

	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo *res = nullptr;
	if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || !res) {
		if (error) {
			*error = "syslog: cannot resolve " + host;
		}
		if (res)
			freeaddrinfo(res);
		return false;
	}

	fd_ = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd_ < 0) {
		if (error)
			*error = "syslog: socket create failed";
		freeaddrinfo(res);
		return false;
	}

	if (!source_addr.empty()) {
		struct sockaddr_in src;
		std::memset(&src, 0, sizeof(src));
		src.sin_family = AF_INET;
		src.sin_addr.s_addr = inet_addr(source_addr.c_str());
		if (src.sin_addr.s_addr == INADDR_NONE ||
		    bind(fd_, (struct sockaddr *)&src, sizeof(src)) < 0) {
			if (error)
				*error = "syslog: bind source " + source_addr + " failed";
		}
	}

	std::memcpy(&addr_, res->ai_addr, sizeof(addr_));
	freeaddrinfo(res);
	return true;
}

bool SyslogExporter::init(const Config::Syslog &cfg, std::string *error)
{
	if (error)
		error->clear();

	if (!cfg.enabled) {
		enabled_ = false;
		return false;
	}

	format_ = cfg.format;
	if (format_ != "json" && format_ != "logfmt") {
		if (error)
			*error = "syslog: unsupported format " + format_;
		return false;
	}

	if (cfg.protocol != "udp") {
		if (error)
			*error = "syslog: unsupported protocol " + cfg.protocol;
		return false;
	}

	host_ = cfg.hostname.empty() ? sys_hostname() : cfg.hostname;

	if (cfg.syslog_host.empty()) {
		local_ = true;
		enabled_ = true;
		return true;
	}

	local_ = false;
	enabled_ = connect_remote(cfg.syslog_host, cfg.syslog_port, cfg.source_address, error);
	return enabled_;
}

std::string SyslogExporter::encode_json(const FlowKey &k, const FlowValue &v, bool expired,
					const Delta *delta, const std::string &ifname)
{
	const SyslogRecord r = make_record(k, v, expired, delta, ifname);
	std::string out;
	out.reserve(320);
	out += "{\"ifindex\":";
	out += fmt_u64(r.ifindex);
	out += ",\"ifname\":";
	json_escape(out, r.ifname.data(), r.ifname.size());
	out += ",\"direction\":";
	json_escape(out, r.direction.data(), r.direction.size());
	out += ",\"family\":";
	out += std::to_string(r.family);
	out += ",\"protocol\":";
	out += std::to_string(r.protocol);
	out += ",\"icmp_type\":";
	out += std::to_string(r.icmp_type);
	out += ",\"icmp_code\":";
	out += std::to_string(r.icmp_code);
	out += ",\"src\":";
	json_escape(out, r.src.data(), r.src.size());
	out += ",\"dst\":";
	json_escape(out, r.dst.data(), r.dst.size());
	out += ",\"sport\":";
	out += fmt_u64(r.sport);
	out += ",\"dport\":";
	out += fmt_u64(r.dport);
	out += ",\"packets\":";
	out += fmt_u64(r.packets);
	out += ",\"bytes\":";
	out += fmt_u64(r.bytes);
	out += ",\"first_seen_ns\":";
	out += fmt_u64(r.first_seen_ns);
	out += ",\"last_seen_ns\":";
	out += fmt_u64(r.last_seen_ns);
	out += ",\"tcp_flags\":";
	out += fmt_u64(r.tcp_flags);
	out += ",\"expired\":";
	out += r.expired ? "true" : "false";
	out += "}";
	return out;
}

std::string SyslogExporter::encode_logfmt(const FlowKey &k, const FlowValue &v, bool expired,
					  const Delta *delta, const std::string &ifname)
{
	const SyslogRecord r = make_record(k, v, expired, delta, ifname);
	std::string out;
	out.reserve(320);
	out += "ifindex=";
	out += fmt_u64(r.ifindex);
	out += " ifname=";
	json_escape(out, r.ifname.data(), r.ifname.size());
	out += " direction=";
	out += r.direction;
	out += " family=";
	out += std::to_string(r.family);
	out += " protocol=";
	out += std::to_string(r.protocol);
	out += " icmp_type=";
	out += std::to_string(r.icmp_type);
	out += " icmp_code=";
	out += std::to_string(r.icmp_code);
	out += " src=";
	json_escape(out, r.src.data(), r.src.size());
	out += " dst=";
	json_escape(out, r.dst.data(), r.dst.size());
	out += " sport=";
	out += fmt_u64(r.sport);
	out += " dport=";
	out += fmt_u64(r.dport);
	out += " packets=";
	out += fmt_u64(r.packets);
	out += " bytes=";
	out += fmt_u64(r.bytes);
	out += " first_seen_ns=";
	out += fmt_u64(r.first_seen_ns);
	out += " last_seen_ns=";
	out += fmt_u64(r.last_seen_ns);
	out += " tcp_flags=";
	out += fmt_u64(r.tcp_flags);
	out += " expired=";
	out += r.expired ? "1" : "0";
	return out;
}

std::string SyslogExporter::encode(const FlowKey &k, const FlowValue &v, bool expired,
				   const Delta *delta, const std::string &ifname,
				   const std::string &format)
{
	if (format == "json")
		return encode_json(k, v, expired, delta, ifname);
	return encode_logfmt(k, v, expired, delta, ifname);
}

std::string SyslogExporter::frame(const std::string &message, const std::string &hostname,
				  std::time_t now)
{
	char ts[24];
	iso_timestamp(now, ts);
	std::string out;
	out.reserve(message.size() + 40);
	out += "<134>1 ";
	out += ts;
	out += " ";
	out += hostname;
	out += " obserwrt - - - ";
	out += message;
	return out;
}

std::string SyslogExporter::deliver(const std::string &message)
{
	if (sink_)
		sink_(message);
	return message;
}

void SyslogExporter::emit(const FlowKey &k, const FlowValue &v, bool expired, const Delta *delta)
{
	if (!enabled_)
		return;

	const std::string ifname = ifnames_ ? ifnames_(k.ifindex) : std::to_string(k.ifindex);
	const std::string payload = encode(k, v, expired, delta, ifname, format_);

	if (local_) {
		::syslog(LOG_INFO | LOG_DAEMON, "%s", payload.c_str());
		return;
	}

	const std::string framed = frame(payload, host_, time(nullptr));
	if (sink_) {
		sink_(framed);
		return;
	}
	if (fd_ >= 0) {
		sendto(fd_, framed.data(), framed.size(), 0, (struct sockaddr *)&addr_,
		       sizeof(addr_));
	}
}

} /* namespace obserwrt */
