/*
 * obserwrt - daemon diagnostics (log.hpp)
 *
 * Daemon diagnostic verbosity gate for syslog(3), shared by the structured
 * logfmt logger (logfmt.hpp). Deliberately not setlogmask(): that would also
 * suppress the syslog exporter's local-mode LOG_INFO flow records.
 */

#pragma once

#include <syslog.h>

namespace obserwrt
{

/* Daemon diagnostic verbosity, initialized from main.log_level. Inline +
 * constant-initialized so there is no separate TU and no dynamic init
 * (clang-analyzer/bugprone-clean). */
inline int g_log_level = LOG_NOTICE;

} /* namespace obserwrt */