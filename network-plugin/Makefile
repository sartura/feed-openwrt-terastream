include $(TOPDIR)/rules.mk

PKG_NAME:=network-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1.4

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/network-plugin.git
PKG_SOURCE_VERSION:=79dfb4763bc9e6b48b154cf3010169621831dd04
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)


PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/network-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=network plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libblobmsg-json +libjson-c +sr-uci
endef

define Package/network-plugin/description
	Sysrepo network plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE

define Package/network-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-network.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/iana-if-type@2014-05-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/ietf-interfaces@2014-05-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/ietf-ip@2014-06-16.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-interfaces-opto@2017-09-27.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/terastream.default $(1)/etc/uci-defaults/99_network
endef

$(eval $(call BuildPackage,network-plugin))
