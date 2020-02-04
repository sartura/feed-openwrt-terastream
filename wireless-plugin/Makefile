include $(TOPDIR)/rules.mk

PKG_NAME:=wireless-plugin
PKG_RELEASE:=3
PKG_VERSION:=1.0.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/wireless-plugin.git
PKG_SOURCE_VERSION:=d983f97393544060952168fc928b51b9b701c5a5
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Luka Paulic <luka.paulic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/wireless-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=wireless plugin
  DEPENDS:= +libsysrepo-v1.x.x +libuci +sysrepoctl-v1.x.x +libubus +libubox +libblobmsg-json
endef

define Package/wireless-plugin/description
	Sysrepo wireless plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE

define Package/wireless-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-wireless.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-wireless@2017-08-08.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/wireless.default $(1)/etc/uci-defaults/99_wireless
endef

$(eval $(call BuildPackage,wireless-plugin))
