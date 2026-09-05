/*
 * obserwrt - flow key hashing (hash.cpp)
 *
 * Single TU that instantiates the vendored xxhash (XXH_INLINE_ALL). flow.hpp
 * only declares flow_hash(); keeping xxhash out of every includer keeps
 * compile cost and warnings contained to this file (vendor is a system
 * include, so xherent clang/macOS pedantic warnings are suppressed here).
 */

#define XXH_INLINE_ALL
#include <xxhash/xxhash.h>

#include <cstddef>
#include <cstdint>

#include "flow.hpp"

namespace obserwrt
{

uint64_t flow_hash(const uint8_t *data, size_t len)
{
	return XXH3_64bits(data, len);
}

} /* namespace obserwrt */