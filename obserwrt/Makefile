include $(TOPDIR)/rules.mk

PKG_NAME:=obserwrt
PKG_VERSION:=0.1.3
PKG_RELEASE:=3

PKG_BUILD_DIR:=$(BUILD_DIR)/obserwrt-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=bpf-headers

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Vladimir Ermakov <vooon341@gmail.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

# Flow-map size is a per-image build-time Kconfig (no runtime override exposed by
# ucode-mod-bpf). Passed to the BPF compile as -DFLOW_MAP_ENTRIES.
FLOW_MAP_ENTRIES:=$(call qstrip,$(CONFIG_OBSERWRT_FLOW_MAP_ENTRIES))
FLOW_MAP_ENTRIES:=$(if $(FLOW_MAP_ENTRIES),$(FLOW_MAP_ENTRIES),4096)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/obserwrt-bpf.c,-DFLOW_MAP_ENTRIES=$(FLOW_MAP_ENTRIES))
endef

define Package/obserwrt/config
	if PACKAGE_obserwrt

		config OBSERWRT_FLOW_MAP_ENTRIES
			int "Max flow map entries"
			default 4096

	endif
endef

define Package/obserwrt
  SECTION:=utils
  CATEGORY:=Network
  SUBMENU:=obserwrt
  TITLE:=eBPF network observability agent
  URL:=https://github.com/vooon/obserwrt
  DEPENDS:=+ucode +ucode-mod-bpf +ucode-mod-ubus +ucode-mod-struct +ucode-mod-log +ucode-mod-fs +ucode-mod-uloop +ucode-mod-socket +libbpf $(BPF_DEPENDS)
endef

define Package/obserwrt/description
  Lightweight eBPF network observability for OpenWrt. Observes traffic on
  selected Linux netdevs via TC ingress/egress, tracks flows, and exports them
  to IPFIX (Akvorado) and a syslog exporter. See docs/design.md.
endef

define Package/obserwrt/conffiles
/etc/config/obserwrt
endef

define Package/obserwrt/install
	$(INSTALL_DIR) \
		$(1)/lib/bpf \
		$(1)/usr/share/ucode/obserwrt \
		$(1)/etc/config \
		$(1)/etc/init.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/obserwrt-bpf.o $(1)/lib/bpf/
	$(INSTALL_DATA) \
		./files/usr/share/ucode/obserwrt/obserwrt.uc \
		./files/usr/share/ucode/obserwrt/flow.uc \
		./files/usr/share/ucode/obserwrt/util.uc \
		./files/usr/share/ucode/obserwrt/reconcile.uc \
		./files/usr/share/ucode/obserwrt/lifecycle.uc \
		./files/usr/share/ucode/obserwrt/metrics.uc \
		./files/usr/share/ucode/obserwrt/exporter_ipfix.uc \
		./files/usr/share/ucode/obserwrt/exporter_syslog.uc \
		$(1)/usr/share/ucode/obserwrt/
	$(INSTALL_DATA) ./files/etc/config/obserwrt $(1)/etc/config/
	$(INSTALL_BIN) ./files/etc/init.d/obserwrt $(1)/etc/init.d/
endef

$(eval $(call BuildPackage,obserwrt))
