/*
 * obserwrt - device reconciliation via rtnetlink (reconcile.cpp)
 *
 * NETLINK_ROUTE, RTMGRP_LINK: RTM_GETLINK dump at startup, then live
 * RTM_NEWLINK/RTM_DELLINK. Only the IFLA_IFNAME + ifi_index/ifi_flags are
 * read; netifd's notion of "active/present" reduces to IFF_UP here (see the
 * header comment in reconcile.hpp).
 */

#include "reconcile.hpp"

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "log.hpp"

namespace obserwrt
{

namespace
{

/* Parse one link message into a LinkEvent. */
void parse_link(const struct nlmsghdr *nlh, LinkEvent &ev)
{
	const struct ifinfomsg *ifi = (const struct ifinfomsg *)NLMSG_DATA(nlh);
	ev.ifindex = static_cast<uint32_t>(ifi->ifi_index);
	ev.up = (ifi->ifi_flags & IFF_UP) != 0;
	ev.present = (nlh->nlmsg_type == RTM_NEWLINK);

	const struct rtattr *rta =
	    (const struct rtattr *)((const char *)ifi + NLMSG_ALIGN(sizeof(*ifi)));
	size_t len = NLMSG_PAYLOAD(nlh, sizeof(*ifi));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type == IFLA_IFNAME && RTA_PAYLOAD(rta) > 0)
			ev.ifname.assign((const char *)RTA_DATA(rta), RTA_PAYLOAD(rta) - 1);
		rta = RTA_NEXT(rta, len);
	}
}

} /* namespace */

Reconcile::~Reconcile()
{
	if (fd_ >= 0)
		close(fd_);
}

bool Reconcile::open(std::string *err)
{
	if (fd_ >= 0)
		return true;

	fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (fd_ < 0) {
		if (err)
			*err = std::string("reconcile: netlink socket: ") + std::strerror(errno);
		return false;
	}

	int grp = RTMGRP_LINK;
	DAEMON_LOG(LOG_DEBUG, "netlink fd=%d subscribing RTMGRP_LINK", fd_);

	struct sockaddr_nl sa;
	std::memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	/* Multicast link notifications must arrive in the BIND sockaddr:
	 * netlink_bind() mirrors nl_groups into the socket groups, REPLACING any
	 * setsockopt(NETLINK_ADD_MEMBERSHIP) made beforehand. Binding with
	 * nl_groups=0 silently drops every live RTM_NEWLINK/RTM_DELLINK after
	 * the (unicast) startup dump - the netifd 'ip monitor' pattern. */
	sa.nl_groups = grp;
	if (bind(fd_, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		if (err)
			*err = std::string("reconcile: netlink bind: ") + std::strerror(errno);
		close(fd_);
		fd_ = -1;
		return false;
	}
	return true;
}

bool Reconcile::dump(const Callback &cb, std::string *err)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(sizeof(struct ifinfomsg)));
	if (!nlh) {
		if (err)
			*err = "reconcile: dump alloc failed";
		return false;
	}
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++seq_;

	struct sockaddr_nl sa;
	std::memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd_, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (err)
			*err = std::string("reconcile: dump request: ") + std::strerror(errno);
		free(nlh);
		return false;
	}
	free(nlh);

	/* Collect dump replies (may span multiple datagrams). */
	char buf[65536];
	for (;;) {
		ssize_t n = recv(fd_, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue;
			if (err)
				*err = std::string("reconcile: dump recv: ") + std::strerror(errno);
			return false;
		}

		struct nlmsghdr *h;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)n);
		     h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_type == NLMSG_DONE)
				return true;
			if (h->nlmsg_type == NLMSG_ERROR)
				return false;
			LinkEvent ev;
			parse_link(h, ev);
			if (!ev.ifname.empty())
				cb(ev);
		}
	}
}

void Reconcile::dispatch(const void *data, size_t len, const Callback &cb)
{
	const char *cur = (const char *)data;
	size_t left = len;
	while (left >= sizeof(struct nlmsghdr) && NLMSG_OK((const struct nlmsghdr *)cur, left)) {
		const struct nlmsghdr *h = (const struct nlmsghdr *)cur;
		if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK) {
			LinkEvent ev;
			parse_link(h, ev);
			DAEMON_LOG(LOG_DEBUG, "link event %s ifindex=%u up=%d present=%d",
				   ev.ifname.c_str(), ev.ifindex, ev.up ? 1 : 0,
				   ev.present ? 1 : 0);
			if (!ev.ifname.empty())
				cb(ev);
		}
		size_t step = NLMSG_ALIGN(h->nlmsg_len);
		cur += step;
		left -= step;
	}
}

} /* namespace obserwrt */