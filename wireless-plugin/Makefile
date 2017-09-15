include $(TOPDIR)/rules.mk

PKG_NAME:=wireless-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/wireless-plugin.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/wireless-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=wireless plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl
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
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/iana-if-type@2014-05-08.yang $(1)/etc/sysrepo/yang/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-wireless@2017-08-08.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/wireless.default $(1)/etc/uci-defaults/99_wireless
endef

$(eval $(call BuildPackage,wireless-plugin))
