/*
 * obserwrt - daemon diagnostics (log.hpp)
 *
 * Gate syslog(3) diagnostics by the configured log level (main.log_level).
 * A macro (not a function) so syslog gets the caller's real varargs - no
 * va_list indirection to trip clang-analyzer's valist check. ::syslog always
 * refers to the C function, immune to local `syslog` variables. Deliberately
 * not setlogmask(): that would also suppress the syslog exporter's local-mode
 * LOG_INFO flow records.
 */

#pragma once

#include <syslog.h>

namespace obserwrt
{

/* Daemon diagnostic verbosity, initialized from main.log_level. Inline +
 * constant-initialized so there is no separate TU and no dynamic init
 * (clang-analyzer/bugprone-clean). */
inline int g_log_level = LOG_NOTICE;

#define DAEMON_LOG(prio, ...)                                                                      \
	do {                                                                                       \
		if ((prio) > obserwrt::g_log_level)                                                \
			break;                                                                     \
		::syslog((prio), __VA_ARGS__);                                                     \
	} while (0)

} /* namespace obserwrt */