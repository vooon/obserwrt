include $(TOPDIR)/rules.mk

PKG_NAME:=obserwrt
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/obserwrt-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=bpf-headers

PKG_LICENSE:=ISC
PKG_MAINTAINER:=vooon <vovan@users.noreply.github.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/obserwrt-bpf.c)
endef

define Package/obserwrt
  SECTION:=utils
  CATEGORY:=Network
  SUBMENU:=obserwrt
  TITLE:=eBPF network observability agent
  URL:=https://github.com/vooon/obserwrt
  DEPENDS:=+ucode +ucode-mod-bpf +ucode-mod-ubus +ucode-mod-struct +libbpf $(BPF_DEPENDS)
endef

define Package/obserwrt/description
  Lightweight eBPF network observability for OpenWrt. Observes traffic on
  selected Linux netdevs via TC ingress/egress, tracks flows, and exports them
  to IPFIX (Akvorado) and a debug exporter. See docs/design.md.
endef

define Package/obserwrt/conffiles
/etc/config/obserwrt
endef

define Package/obserwrt/install
	$(INSTALL_DIR) \
		$(1)/usr/lib/obserwrt \
		$(1)/usr/libexec/obserwrt \
		$(1)/etc/config \
		$(1)/etc/init.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/obserwrt-bpf.o $(1)/usr/lib/obserwrt/
	$(INSTALL_BIN) ./files/usr/libexec/obserwrt/obserwrt.uc $(1)/usr/libexec/obserwrt/
	$(INSTALL_DATA) ./files/etc/config/obserwrt $(1)/etc/config/
	$(INSTALL_BIN) ./files/etc/init.d/obserwrt $(1)/etc/init.d/
endef

$(eval $(call BuildPackage,obserwrt))