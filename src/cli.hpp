/*
 * obserwrt - command-line parsing (cli.hpp)
 *
 * Minimal getopt_long-based CLI. --version/--help never touch config or BPF,
 * so they work even with a broken config or missing object. Options are
 * parsed before any daemon initialization in main().
 */

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace obserwrt
{

struct Cli {
	bool help = false;
	bool version = false;
	std::string config_path;     /* empty = compiled-default per target */
	std::string bpf_object_path; /* empty = $BPF_OBJ or compiled default */

	/* Compile-time default config/object paths (per-target, see CMake). */
	static std::string_view default_config_path();
	static std::string_view default_bpf_object();
};

/* Parse argv. Returns nullopt when the caller should exit immediately
 * (help/version printed, or a usage error) with `*exit_code` set. */
std::optional<Cli> parse_args(int argc, char **argv, int *exit_code);

/* Print --help usage to stdout. */
void print_usage(FILE *out);

/* Print --version line to stdout. */
void print_version();

} /* namespace obserwrt */
