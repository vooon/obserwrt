/*
 * obserwrt - command-line parsing (cli.cpp)
 *
 * Minimal getopt_long handling: -h/--help, -V/--version (exit 0),
 * -c/--config PATH, -o/--bpf-object PATH. Unknown option or a missing
 * argument prints usage to stderr and exits 1.
 */

#include "cli.hpp"

#include <getopt.h>

#include <cstdio>
#include <cstdlib>

#include "version.hpp"

#ifdef OBSEWRRT_DEFAULT_CONFIG
#define CLIDEF_CONFIG OBSEWRRT_DEFAULT_CONFIG
#else
#define CLIDEF_CONFIG ""
#endif

#ifdef OBSEWRRT_DEFAULT_BPF_OBJ
#define CLIDEF_BPF OBSEWRRT_DEFAULT_BPF_OBJ
#else
#define CLIDEF_BPF ""
#endif

namespace obserwrt
{

std::string_view Cli::default_config_path()
{
	return CLIDEF_CONFIG;
}

std::string_view Cli::default_bpf_object()
{
	return CLIDEF_BPF;
}

void print_version()
{
	std::printf("obserwrt %.*s (commit %.*s, %.*s/%.*s)\n", (int)build_info().version.size(),
		    build_info().version.data(), (int)build_info().commit.size(),
		    build_info().commit.data(), (int)build_info().os.size(), build_info().os.data(),
		    (int)build_info().arch.size(), build_info().arch.data());
}

void print_usage(FILE *out)
{
	std::fprintf(out,
		     "Usage: obserwrt [options]\n"
		     "\n"
		     "Lightweight eBPF network observability agent.\n"
		     "\n"
		     "Options:\n"
		     "  -h, --help           Show this usage and exit\n"
		     "  -V, --version        Show build/version info and exit\n"
		     "  -c, --config PATH    Config file to read (default: %.*s)\n"
		     "  -o, --bpf-object PATH\n"
		     "                       Path to obserwrt-bpf.o (default: $BPF_OBJ or %.*s)\n",
		     (int)Cli::default_config_path().size(), Cli::default_config_path().data(),
		     (int)Cli::default_bpf_object().size(), Cli::default_bpf_object().data());
}

std::optional<Cli> parse_args(int argc, char **argv, int *exit_code)
{
	const struct option opts[] = {
	    {"help", no_argument, nullptr, 'h'},
	    {"version", no_argument, nullptr, 'V'},
	    {"config", required_argument, nullptr, 'c'},
	    {"bpf-object", required_argument, nullptr, 'o'},
	    {nullptr, 0, nullptr, 0},
	};

	Cli cli;
	int c;

	while ((c = getopt_long(argc, argv, "hVc:o:", opts, nullptr)) != -1) {
		switch (c) {
		case 'h':
			cli.help = true;
			break;
		case 'V':
			cli.version = true;
			break;
		case 'c':
			cli.config_path = optarg;
			break;
		case 'o':
			cli.bpf_object_path = optarg;
			break;
		default:
			print_usage(stderr);
			*exit_code = 1;
			return std::nullopt;
		}
	}

	if (cli.help) {
		print_usage(stdout);
		*exit_code = 0;
		return std::nullopt;
	}

	if (cli.version) {
		print_version();
		*exit_code = 0;
		return std::nullopt;
	}

	return cli;
}

} /* namespace obserwrt */