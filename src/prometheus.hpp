/*
 * obserwrt - Prometheus text exposition builder (prometheus.hpp)
 *
 * Tiny pure string builder for the node-exporter textfile format (no fs
 * access, so it is unit-testable). Handles the per-family # HELP/# TYPE
 * headers (emitted once on first sample, in encounter order) and label
 * rendering with escaping. Values are integers - every obserwrt metric is.
 *
 * Sample layout:  name{labels} value\n  (no trailing space/{} when unlabeled).
 */

#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace obserwrt
{

class PromExposition
{
      public:
	/* Emit one sample; the # HELP/# TYPE header for `name` is written once,
	 * before the first sample of that family. */
	void sample(const char *name, const char *type, const char *help, const std::string &labels,
		    uint64_t value);
	void counter(const char *name, const char *help, const std::string &labels, uint64_t v)
	{
		sample(name, "counter", help, labels, v);
	}
	void gauge(const char *name, const char *help, const std::string &labels, uint64_t v)
	{
		sample(name, "gauge", help, labels, v);
	}

	/* Render {k="v",...} with JSON-style escaping of \ " and newline in the
	 * values. Empty list -> "" (unlabeled sample). */
	static std::string labels(std::initializer_list<std::pair<const char *, const char *>> kv);

	const std::string &str() const
	{
		return out_;
	}
	void clear()
	{
		out_.clear();
		declared_.clear();
	}

      private:
	std::string out_;
	std::vector<std::string> declared_; /* families with headers emitted */
};

} /* namespace obserwrt */