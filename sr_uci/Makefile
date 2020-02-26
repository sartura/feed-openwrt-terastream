include $(TOPDIR)/rules.mk

PKG_NAME:=sr_uci
PKG_RELEASE:=3
PKG_VERSION:=1.0.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/sr_uci.git
PKG_SOURCE_VERSION:=526a0b5bcee19a50166996972c9d9031842f2bea
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Luka Paulic <luka.paulic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/sr-uci
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=sr_uci library
  DEPENDS:= +libsysrepo-v1.x.x +libuci +libubus +libubox +libblobmsg-json
endef

define Package/sr-uci/description
	Sysrepo to uci library
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libsr_uci.so $(1)/usr/lib/

	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sr_uci.h $(1)/usr/include
endef

define Package/sr-uci/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libsr_uci.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,sr-uci))
