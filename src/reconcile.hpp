/*
 * obserwrt - device reconciliation via rtnetlink (reconcile.hpp)
 *
 * Plain-Linux device lifecycle: an initial RTM_GETLINK dump plus live
 * RTM_NEWLINK/RTM_DELLINK events, replacing the ucode agent's netifd/ubus
 * machinery (design §6.2). Works identically on OpenWrt and any Linux host -
 * netifd is just a manager; the kernel rtnetlink events are the same source
 * of truth. The daemon maps events onto attach/detach + purge.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace obserwrt
{

struct LinkEvent {
	uint32_t ifindex = 0;
	std::string ifname;
	uint16_t type = 0;    /* ifi_type (ARPHRD_*) */
	bool present = false; /* true=NEWLINK, false=DELLINK */
	bool up = false;      /* IFF_UP (admin up) */
};

/* Whether TC sees a link-layer (Ethernet) header in front of IP on a device
 * of this ARPHRD type; false for L3 devices (WireGuard/AWG, ip6gre/FOU, tun,
 * PPP), whose skb data starts at the IP header. */
bool link_is_ethernet(uint16_t arphrd);

class Reconcile
{
      public:
	using Callback = std::function<void(const LinkEvent &)>;

	Reconcile() = default;
	~Reconcile();
	Reconcile(const Reconcile &) = delete;
	Reconcile &operator=(const Reconcile &) = delete;

	/* Open the NETLINK_ROUTE socket and subscribe to link events. */
	bool open(std::string *err);

	/* Pollable fd for the event loop. */
	int fd() const
	{
		return fd_;
	}

	/* One-shot enumeration of current links ("startup snapshot"); fires
	 * `cb` for every existing link. */
	bool dump(const Callback &cb, std::string *err);

	/* Parse a received netlink buffer and fire `cb` for each link event. */
	void dispatch(const void *data, size_t len, const Callback &cb);

      private:
	int fd_ = -1;
	uint32_t seq_ = 0;
};

} /* namespace obserwrt */