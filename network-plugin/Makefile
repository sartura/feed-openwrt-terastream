include $(TOPDIR)/rules.mk

PKG_NAME:=network-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/network-plugin.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/network-plugin/config
  source "$(SOURCE)/Config.in"
endef

define Package/network-plugin
  SECTION:=terastream
  CATEGORY:=terastream
  TITLE:=network plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libblobmsg-json +libjson-c
endef

define Package/network-plugin/description
	Midland
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=FALSE

ifeq ($(CONFIG_PLUGIN),y)
CMAKE_OPTIONS:= \
	-DPLUGIN:BOLL=TRUE
else
CMAKE_OPTIONS:= \
	-DPLUGIN:BOLL=FALSE
endif

define Package/network-plugin/install

ifeq ($(CONFIG_PLUGIN),y)
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-terastream.so $(1)/usr/lib/sysrepo/plugins/
else
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysrepo-plugin-dt-terastream $(1)/usr/bin/
endif

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/iana-if-type@2014-05-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/ietf-interfaces@2014-05-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/ietf-ip@2014-06-16.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-provisioning@2017-08-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-wireless@2017-08-08.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/terastream.default $(1)/etc/uci-defaults/99_terasream
endef

$(eval $(call BuildPackage,network-plugin))
