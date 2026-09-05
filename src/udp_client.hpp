/*
 * obserwrt - remote UDP endpoint (udp_client.hpp)
 *
 * The one place that turns a collector host:port into a sendable UDP socket.
 * Exporters own a UdpClient (one per remote exporter) - there is no injected
 * transport abstraction; tests capture datagrams inside the exporter instead.
 * Dual-stack: AF_UNSPEC resolution, a socket of the resolved family, optional
 * source bind matched to that family, sockaddr_storage for sendto. Failed
 * sends are counted so the daemon can fold them into
 * obserwrt_export_errors_total via take_failures().
 */

#pragma once

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace obserwrt
{

class UdpClient
{
      public:
	UdpClient() = default;
	~UdpClient();
	UdpClient(const UdpClient &) = delete;
	UdpClient &operator=(const UdpClient &) = delete;

	/* Resolve host:port (IPv4 or IPv6) and open a DGRAM socket; a non-empty
	 * `source_addr` pins the local source in the collector's family. */
	bool connect(const std::string &host, uint16_t port, const std::string &source_addr,
		     std::string *err);

	bool connected() const
	{
		return fd_ >= 0;
	}

	/* Send one datagram; false on failure (errno preserved), counted so the
	 * caller can fold it into the export error metric later. */
	bool send(std::span<const std::byte> data);

	/* Failed sends since the last take (for exporter metrics). */
	unsigned long take_failures()
	{
		unsigned long n = failures_;
		failures_ = 0;
		return n;
	}

      private:
	int fd_ = -1;
	struct sockaddr_storage to_ = {};
	socklen_t tolen_ = 0;
	unsigned long failures_ = 0;

	bool bind_source(int family, const std::string &s, std::string &err);
};

} /* namespace obserwrt */