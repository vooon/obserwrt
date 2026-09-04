/*
 * obserwrt - Prometheus text exposition builder (prometheus.cpp)
 */

#include "prometheus.hpp"

#include <algorithm>

namespace obserwrt
{

void PromExposition::sample(const char *name, const char *type, const char *help,
			    const std::string &labels, uint64_t value)
{
	if (std::find(declared_.begin(), declared_.end(), name) == declared_.end()) {
		out_ += "# HELP ";
		out_ += name;
		out_ += ' ';
		out_ += help;
		out_ += '\n';
		out_ += "# TYPE ";
		out_ += name;
		out_ += ' ';
		out_ += type;
		out_ += '\n';
		declared_.push_back(name);
	}

	out_ += name;
	out_ += labels; /* starts with '{' or is empty */
	out_ += ' ';
	out_ += std::to_string(value);
	out_ += '\n';
}

std::string PromExposition::labels(std::initializer_list<std::pair<const char *, const char *>> kv)
{
	if (kv.size() == 0)
		return {};

	std::string out;
	out.reserve(32);
	out += '{';
	bool first = true;
	for (const auto &p : kv) {
		if (!first)
			out += ',';
		first = false;
		out += p.first;
		out += "=\"";
		for (const char *c = p.second; *c; c++) {
			switch (*c) {
			case '\\':
				out += "\\\\";
				break;
			case '"':
				out += "\\\"";
				break;
			case '\n':
				out += "\\n";
				break;
			default:
				out += *c;
			}
		}
		out += '"';
	}
	out += '}';
	return out;
}

} /* namespace obserwrt */