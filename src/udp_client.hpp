/*
 * obserwrt - remote UDP endpoint (udp_client.hpp)
 *
 * The one place that turns a collector host:port into a sendable UDP socket.
 * Dual-stack: AF_UNSPEC resolution, a socket of the resolved family, optional
 * source bind matched to that family, sockaddr_storage for sendto. Used by
 * both the IPFIX exporter (daemon sink) and the remote syslog exporter, so
 * the resolve/create/bind/send logic lives in exactly one place.
 */

#pragma once

#include <sys/socket.h>

#include <cstdint>
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

	void send(const std::string &data) const;

      private:
	int fd_ = -1;
	struct sockaddr_storage to_ = {};
	socklen_t tolen_ = 0;

	bool bind_source(int family, const std::string &s, std::string &err);
};

} /* namespace obserwrt */