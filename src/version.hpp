/*
 * obserwrt - build/version info (version.hpp)
 *
 * Version, commit, os and arch are injected by the build system
 * (-DOBSEWRRT_*); never hardcoded here. Both the CLI --version output and the
 * obserwrt_build_info Prometheus metric read the same constexpr values so they
 * can never drift.
 */

#pragma once

#include <string_view>

#ifdef OBSEWRRT_VERSION
#define OBSEWRRT_VERSION_STR OBSEWRRT_VERSION
#else
#define OBSEWRRT_VERSION_STR "unknown"
#endif

#ifdef OBSEWRRT_COMMIT
#define OBSEWRRT_COMMIT_STR OBSEWRRT_COMMIT
#else
#define OBSEWRRT_COMMIT_STR ""
#endif

#ifdef OBSEWRRT_OS
#define OBSEWRRT_OS_STR OBSEWRRT_OS
#else
#define OBSEWRRT_OS_STR "unknown"
#endif

#ifdef OBSEWRRT_ARCH
#define OBSEWRRT_ARCH_STR OBSEWRRT_ARCH
#else
#define OBSEWRRT_ARCH_STR "unknown"
#endif

namespace obserwrt
{

struct BuildInfo {
	std::string_view version = OBSEWRRT_VERSION_STR;
	std::string_view commit = OBSEWRRT_COMMIT_STR;
	std::string_view os = OBSEWRRT_OS_STR;
	std::string_view arch = OBSEWRRT_ARCH_STR;
};

inline constexpr BuildInfo build_info()
{
	return {};
}

} /* namespace obserwrt */
