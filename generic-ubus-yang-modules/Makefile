include $(TOPDIR)/rules.mk

PKG_NAME:=generic-ubus-yang-modules
PKG_RELEASE:=2019-06-27
PKG_VERSION:=0.1.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/generic-ubus-yang-modules
PKG_SOURCE_VERSION:=5135ac5efa2f695d0a5948a160b646bacd0776f7
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
  TITLE:=generic ubus yang modules
  DEPENDS:= +sysrepo +sysrepoctl
endef

define Package/wireless-plugin/description
	Sysrepo ubus specific YANG modules used by the generic ubus plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE \

define Package/wireless-plugin/install

	# TODO: all yangs need to be copyed to the /etc/sysrepo/yang
	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-router-wireless@2019-06-24.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-router-system@2019-06-24.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-sip@2019-06-24.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-system@2019-06-24.yang $(1)/etc/sysrepo/yang/

	# TODO: then installed
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/generic-ubus-yang-modules.default $(1)/etc/uci-defaults/99_generic_ubus_yang_modules
endef

$(eval $(call BuildPackage,generic-ubus-yang-modules))
