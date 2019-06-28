include $(TOPDIR)/rules.mk

PKG_NAME:=generic-ubus-plugin
PKG_RELEASE:=2019-06-27
PKG_VERSION:=0.1.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/generic-ubus-plugin
PKG_SOURCE_VERSION:=904a7b63f29e45cb23aa2c2890ed375a7552c472
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Luka Paulic <luka.paulic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/generic-ubus-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=generic ubus plugin
  DEPENDS:= +sysrepo +sysrepoctl +libubus +libubox +libblobmsg-json +generic-ubus-yang-modules
endef

define Package/generic-ubus-plugin/description
	Sysrepo generic ubus plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE \

define Package/generic-ubus-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-generic-ubus.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-generic-ubus@2019-06-12.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/generic-ubus.default $(1)/etc/uci-defaults/99_generic_ubus
endef

$(eval $(call BuildPackage,generic-ubus-plugin))
