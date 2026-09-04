/*
 * obserwrt - flow key/value wire formats (flow.hpp)
 *
 * Single point of ownership for the BPF flow-map key/value layouts
 * (docs/design.md §5). POD structs mirror the packed C layout written by
 * obserwrt-bpf.c; endian helpers pack/unpack the scheduler formats.
 *
 * The BPF map is written and read on the same machine, so counters and ports
 * are interpreted native-endian (the '<' prefix in the ucode struct module).
 * Address bytes are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d) for IPv4.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace obserwrt
{

/* Direction at the observation point (mirrors the BPF enum). */
enum : uint8_t {
	INGRESS = 0,
	EGRESS = 1,
};

/* Flow key (46 bytes, packed, native endian) - docs/design.md §5.1.
 * struct.pack format (little-endian): "<LBBBx16s16sHHBB".
 */
struct __attribute__((packed)) FlowKey {
	uint32_t ifindex;
	uint8_t direction;
	uint8_t family;
	uint8_t protocol;
	uint8_t reserved;
	uint8_t src[16];
	uint8_t dst[16];
	uint16_t sport;
	uint16_t dport;
	uint8_t icmp_type;
	uint8_t icmp_code;
};
static_assert(sizeof(FlowKey) == 46, "FlowKey must be 46 bytes");

/* Flow value (40 bytes, native endian) - docs/design.md §5.2.
 * struct.pack format (little-endian): "<QQQQH6x". NOT packed: the 8-byte
 * counters are naturally aligned in-kernel (atomic increments), and the
 * trailing alignment padding is exactly the "<QQQQH6x" 6 pad bytes that make
 * sizeof() == 40.
 */
struct FlowValue {
	uint64_t packets;
	uint64_t bytes;
	uint64_t first_seen;
	uint64_t last_seen;
	uint16_t tcp_flags;
};
static_assert(sizeof(FlowValue) == 40, "FlowValue must be 40 bytes");

/* Interval growth handed to exporters by the lifecycle (active-flow delta
 * accounting) - the cumulative counters in FlowValue are NOT re-sent; only
 * the growth since the last export + the explicit value fields are. */
struct Delta {
	uint64_t packets;
	uint64_t bytes;
};

/* Little-endian load helpers for the packed map structs (native endian is the
 * BPF map's own byte order; these make the field reads explicit). */
inline uint16_t le16(const void *p)
{
	uint16_t v;
	std::memcpy(&v, p, sizeof(v));
	return v;
}

inline uint32_t le32(const void *p)
{
	uint32_t v;
	std::memcpy(&v, p, sizeof(v));
	return v;
}

inline uint64_t le64(const void *p)
{
	uint64_t v;
	std::memcpy(&v, p, sizeof(v));
	return v;
}

/* Parse a raw map key (bytes) - decode via the packed struct. The 46-byte raw
 * blob and sizeof(FlowKey) are identical, so a memcpy is the whole parse. */
inline FlowKey parse_key(const std::string &raw)
{
	FlowKey k;
	std::memcpy(&k, raw.data(), raw.size() < sizeof(k) ? raw.size() : sizeof(k));
	return k;
}

inline FlowKey parse_key(const void *raw)
{
	FlowKey k;
	std::memcpy(&k, raw, sizeof(k));
	return k;
}

inline FlowValue parse_value(const std::string &raw)
{
	FlowValue v;
	std::memcpy(&v, raw.data(), raw.size() < sizeof(v) ? raw.size() : sizeof(v));
	return v;
}

inline FlowValue parse_value(const void *raw)
{
	FlowValue v;
	std::memcpy(&v, raw, sizeof(v));
	return v;
}

/* Pack helpers: native-endian append into the wire struct for a key/value
 * byte buffer (the inverse of parse_*). Used by tests and the syslog/hex
 * tracker path. */
inline void append_le16(std::string &b, uint16_t v)
{
	uint8_t c[2];
	std::memcpy(c, &v, 2);
	b.append(reinterpret_cast<char *>(c), 2);
}

inline void append_le32(std::string &b, uint32_t v)
{
	uint8_t c[4];
	std::memcpy(c, &v, 4);
	b.append(reinterpret_cast<char *>(c), 4);
}

inline void append_le64(std::string &b, uint64_t v)
{
	uint8_t c[8];
	std::memcpy(c, &v, 8);
	b.append(reinterpret_cast<char *>(c), 8);
}

inline std::string pack_key(const FlowKey &k)
{
	std::string out;
	out.reserve(sizeof(k));
	append_le32(out, k.ifindex);
	out.push_back(static_cast<char>(k.direction));
	out.push_back(static_cast<char>(k.family));
	out.push_back(static_cast<char>(k.protocol));
	out.push_back(static_cast<char>(k.reserved));
	out.append(reinterpret_cast<const char *>(k.src), 16);
	out.append(reinterpret_cast<const char *>(k.dst), 16);
	append_le16(out, k.sport);
	append_le16(out, k.dport);
	out.push_back(static_cast<char>(k.icmp_type));
	out.push_back(static_cast<char>(k.icmp_code));
	return out;
}

inline std::string pack_value(const FlowValue &v)
{
	std::string out;
	out.reserve(sizeof(v));
	append_le64(out, v.packets);
	append_le64(out, v.bytes);
	append_le64(out, v.first_seen);
	append_le64(out, v.last_seen);
	append_le16(out, v.tcp_flags);
	out.append(6, '\0'); /* trailing pad */
	return out;
}

} /* namespace obserwrt */
