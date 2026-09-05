/*
 * obserwrt - structured daemon diagnostics (logfmt.hpp)
 *
 * A miniature logfmt logger replacing printf-style DAEMON_LOG format strings
 * with key=value fields, so syslog/journald lines stay grep-able and
 * parseable. No dependency is worth it for this (spdlog/quill need exceptions
 * and their own sinks; fmt is a full formatter; nlohmann/json is already
 * heavy) - one header, exceptions-free, gated by the existing
 * main.log_level.
 *
 * Values are logfmt-escaped: a value is double-quoted (with \\, \", \n, \r
 * escaping) when empty or containing whitespace / quotes / backslashes /
 * '='; numbers and bools are rendered bare (true/false).
 *
 * Usage (builds the line only when the priority is enabled, then syslog()s it
 * once on scope exit):
 *
 *	SLOG(LOG_NOTICE)("event", "attach")("ifname", ev.ifname)("ifindex", ev.ifindex);
 *	SLOG(LOG_DEBUG)("event", "pass")("active", st.active)("expired", st.expired);
 */

#pragma once

#include <syslog.h>

#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>

#include "log.hpp"

namespace obserwrt
{

class Log
{
      public:
	/* Only builds/flushes when `prio` passes the configured level. */
	explicit Log(int prio) : prio_(prio), ok_(prio <= g_log_level)
	{
	}

	~Log()
	{
		if (ok_ && !buf_.empty())
			::syslog(prio_, "%s", buf_.c_str());
	}

	Log(const Log &) = delete;
	Log &operator=(const Log &) = delete;

	/* Append one key=value field; returns *this for chaining. */
	template <typename V> Log &operator()(std::string_view key, const V &value)
	{
		if (ok_) {
			if (!buf_.empty())
				buf_ += ' ';
			buf_ += key;
			buf_ += '=';
			append_value(value);
		}
		return *this;
	}

	/* SLOG for-loop family: run one pass, then this makes enabled() false so
	 * the loop ends (the destructor still flushes the built line). */
	void finish()
	{
		done_ = true;
	}

	bool enabled() const
	{
		return ok_ && !done_;
	}

      private:
	int prio_;
	bool ok_;
	bool done_ = false;
	std::string buf_;

	static void append_escaped(std::string &out, std::string_view v)
	{
		bool needq = v.empty();
		for (char c : v) {
			if (c == ' ' || c == '\t' || c == '"' || c == '\\' || c == '=' ||
			    c == '\n' || c == '\r') {
				needq = true;
				break;
			}
		}
		if (!needq) {
			out += v;
			return;
		}
		out += '"';
		for (char c : v) {
			switch (c) {
			case '"':
				out += "\\\"";
				break;
			case '\\':
				out += "\\\\";
				break;
			case '\n':
				out += "\\n";
				break;
			case '\r':
				out += "\\r";
				break;
			default:
				out += c;
			}
		}
		out += '"';
	}

	template <typename V> void append_value(const V &value)
	{
		using U = std::remove_cvref_t<V>;
		if constexpr (std::same_as<U, bool>) {
			buf_ += value ? "true" : "false";
		} else if constexpr (std::integral<U> || std::floating_point<U>) {
			buf_ += std::to_string(value);
		} else if constexpr (std::convertible_to<V, std::string_view> ||
				     std::convertible_to<V, const char *>) {
			append_escaped(buf_, std::string_view(value));
		} else {
			static_assert(!sizeof(U), "unsupported structured-log value type");
		}
	}
};

} /* namespace obserwrt */

/* Iterate exactly once when the priority is enabled; `"msg", ...` starts the
 * line as the traditional logfmt `msg="..."` first field, then `("k", v)`
 * appends the rest; the destructor syslog()s the line. Backslashes stay
 * flush with the code (no alignment spaces) to keep -Wbackslash-newline quiet.
 *
 *	SLOG(LOG_NOTICE, "device attached")("ifname", "awg0")("ifindex", 17);
 */
// clang-format off
#define SLOG(prio, msg)\
	for (obserwrt::Log obserwrt_log{prio}; obserwrt_log.enabled(); obserwrt_log.finish())\
		obserwrt_log("msg", msg)
// clang-format on
