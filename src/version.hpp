/*
 * obserwrt - build/version info (version.hpp)
 *
 * Version, commit, os and arch are injected by the build system
 * (-DOBSERWRT_*); never hardcoded here. Both the CLI --version output and the
 * obserwrt_build_info Prometheus metric read the same constexpr values so they
 * can never drift.
 */

#pragma once

#include <string_view>

#ifdef OBSERWRT_VERSION
#define OBSERWRT_VERSION_STR OBSERWRT_VERSION
#else
#define OBSERWRT_VERSION_STR "unknown"
#endif

#ifdef OBSERWRT_COMMIT
#define OBSERWRT_COMMIT_STR OBSERWRT_COMMIT
#else
#define OBSERWRT_COMMIT_STR ""
#endif

#ifdef OBSERWRT_OS
#define OBSERWRT_OS_STR OBSERWRT_OS
#else
#define OBSERWRT_OS_STR "unknown"
#endif

#ifdef OBSERWRT_ARCH
#define OBSERWRT_ARCH_STR OBSERWRT_ARCH
#else
#define OBSERWRT_ARCH_STR "unknown"
#endif

namespace obserwrt
{

struct BuildInfo {
	std::string_view version = OBSERWRT_VERSION_STR;
	std::string_view commit = OBSERWRT_COMMIT_STR;
	std::string_view os = OBSERWRT_OS_STR;
	std::string_view arch = OBSERWRT_ARCH_STR;
};

inline constexpr BuildInfo build_info()
{
	return {};
}

} /* namespace obserwrt */
