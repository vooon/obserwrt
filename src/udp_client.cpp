/*
 * obserwrt - remote UDP endpoint (udp_client.cpp)
 */

#include "udp_client.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace obserwrt
{

UdpClient::~UdpClient()
{
	if (fd_ >= 0)
		close(fd_);
}

bool UdpClient::bind_source(int family, const std::string &s, std::string &err)
{
	if (family == AF_INET) {
		struct sockaddr_in src;
		std::memset(&src, 0, sizeof(src));
		src.sin_family = AF_INET;
		if (inet_pton(AF_INET, s.c_str(), &src.sin_addr) != 1 ||
		    bind(fd_, (struct sockaddr *)&src, sizeof(src)) < 0) {
			err = s + ": " + std::strerror(errno);
			return false;
		}
		return true;
	}
	if (family == AF_INET6) {
		struct sockaddr_in6 src6;
		std::memset(&src6, 0, sizeof(src6));
		src6.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, s.c_str(), &src6.sin6_addr) != 1 ||
		    bind(fd_, (struct sockaddr *)&src6, sizeof(src6)) < 0) {
			err = s + ": " + std::strerror(errno);
			return false;
		}
		return true;
	}
	err = "unsupported family";
	return false;
}

bool UdpClient::connect(const std::string &host, uint16_t port, const std::string &source_addr,
			std::string *err)
{
	if (err)
		err->clear();

	char portbuf[8];
	std::snprintf(portbuf, sizeof(portbuf), "%u", port);

	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* dual-stack: IPv4 or IPv6 collector */
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo *res = nullptr;
	if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || !res) {
		if (err)
			*err = host + ": cannot resolve";
		if (res)
			freeaddrinfo(res);
		return false;
	}

	/* Try each candidate until a socket with the optional source bound comes
	 * up; the source must be in the candidate's family. */
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			continue;

		int old = fd_;
		fd_ = s;
		if (!source_addr.empty()) {
			std::string berr;
			if (!bind_source(ai->ai_family, source_addr, berr)) {
				close(s);
				fd_ = old;
				continue;
			}
		}

		std::memcpy(&to_, ai->ai_addr, ai->ai_addrlen);
		tolen_ = ai->ai_addrlen;
		freeaddrinfo(res);
		return true;
	}

	freeaddrinfo(res);
	if (err) {
		*err = source_addr.empty() ? host + ": no usable address"
					   : "bind source " + source_addr + " failed";
	}
	return false;
}

void UdpClient::send(const std::string &data) const
{
	if (fd_ >= 0)
		sendto(fd_, data.data(), data.size(), 0, (struct sockaddr *)&to_, tolen_);
}

} /* namespace obserwrt */