include $(TOPDIR)/rules.mk

PKG_NAME:=obserwrt
PKG_VERSION:=0.2.6
PKG_RELEASE:=106

PKG_BUILD_DIR:=$(BUILD_DIR)/obserwrt-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=bpf-headers
CMAKE_INSTALL:=1
CMAKE_BINARY_SUBDIR:=build-cmake

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Vladimir Ermakov <vooon341@gmail.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(INCLUDE_DIR)/bpf.mk

# Root CMakeLists.txt + C++ sources live repo-root (feed root); the eBPF
# source lives in the package dir (obserwrt/src/obserwrt-bpf.c). Assemble
# both into the package build dir; the BPF object is built on-device-from-
# source via bpf.mk (never checked in) - see Build/Compile below.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ../CMakeLists.txt $(PKG_BUILD_DIR)/
	$(CP) -r ../src $(PKG_BUILD_DIR)/
	$(CP) -r ../vendor $(PKG_BUILD_DIR)/
	$(CP) ./src/obserwrt-bpf.c $(PKG_BUILD_DIR)/obserwrt-bpf.c
endef

# Optimization follows the image (CONFIG_TARGET_OPTIMIZATION is already in
# $(TARGET_CXXFLAGS)); null out CMake's own -O2 Release default so the image
# flags stay authoritative (the Linux/CMake build keeps its -O2 .deb default).
CMAKE_OPTIONS += \
	-DOBSEWRRT_USE_LIBUCI=ON \
	-DOBSEWRRT_OS=openwrt \
	-DOBSEWRRT_ARCH=$(ARCH) \
	-DOBSEWRRT_VERSION=$(PKG_VERSION) \
	-DOBSEWRRT_BUILD_TESTS=OFF \
	-DCMAKE_CXX_FLAGS_RELEASE=""

# The daemon is built by CMake (Build/Compile/Default); the eBPF object is
# compiled from source by bpf.mk's CompileBPF. No FLOW_MAP_ENTRIES define is
# passed: obserwrt-bpf.c defaults to 4096, and the daemon's runtime
# `max_flows` overrides it at load (max_flows=0 stays the 4k baked default).
define Build/Compile
	$(call Build/Compile/Default)
	$(call CompileBPF,$(PKG_BUILD_DIR)/obserwrt-bpf.c)
endef

define Package/obserwrt
  SECTION:=utils
  CATEGORY:=Network
  SUBMENU:=obserwrt
  TITLE:=eBPF network observability agent
  URL:=https://github.com/vooon/obserwrt
  DEPENDS:=+libbpf +libuci +libstdcpp \
	   $(BPF_DEPENDS) \
	   +@KERNEL_DEBUG_INFO +@KERNEL_DEBUG_INFO_BTF +@KERNEL_BPF_EVENTS +@KERNEL_NET_NS \
	   +kmod-ipsec
endef

define Package/obserwrt/description
  Lightweight eBPF network observability for OpenWrt and plain Linux.
  Observes traffic on selected Linux netdevs via TC ingress/egress, tracks
  flows, and exports them to IPFIX (Akvorado) and a syslog exporter.
  See docs/design.md.
endef

define Package/obserwrt/conffiles
/etc/config/obserwrt
endef

define Package/obserwrt/install
	$(INSTALL_DIR) \
		$(1)/usr/bin \
		$(1)/lib/bpf \
		$(1)/etc/config \
		$(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/obserwrt $(1)/usr/bin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/obserwrt-bpf.o $(1)/lib/bpf/
	$(INSTALL_BIN) ./files/obserwrt.init $(1)/etc/init.d/obserwrt
	$(INSTALL_DATA) ./files/obserwrt.conf $(1)/etc/config/obserwrt
endef

$(eval $(call BuildPackage,obserwrt))
