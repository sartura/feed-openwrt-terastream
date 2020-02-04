include $(TOPDIR)/rules.mk

PKG_NAME:=generic-ubus-yang-modules
PKG_RELEASE:=2
PKG_VERSION:=1.0.0

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

define Package/generic-ubus-yang-modules
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=generic ubus yang modules
  DEPENDS:= +libsysrepo-v1.x.x +sysrepoctl-v1.x.x
endef

define Package/generic-ubus-yang-modules/description
		Sysrepo ubus specific YANG modules used by the generic ubus plugin
endef

define Build/Compile
		true
endef

define Package/generic-ubus-yang-modules/install

		$(INSTALL_DIR) $(1)/etc/sysrepo/yang
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-router-wireless@2019-06-24.yang $(1)/etc/sysrepo/yang/
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-router-system@2019-06-24.yang $(1)/etc/sysrepo/yang/
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-sip@2019-06-24.yang $(1)/etc/sysrepo/yang/
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/generic-ubus-system@2019-06-24.yang $(1)/etc/sysrepo/yang/

		$(INSTALL_DIR) $(1)/etc/uci-defaults
		$(INSTALL_BIN) ./files/generic-ubus-yang-modules.default $(1)/etc/uci-defaults/99_generic_ubus_yang_modules
endef

$(eval $(call BuildPackage,generic-ubus-yang-modules))

