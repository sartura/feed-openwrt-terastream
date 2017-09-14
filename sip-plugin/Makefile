include $(TOPDIR)/rules.mk

PKG_NAME:=sip-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/sip-plugin.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/sip-plugin/config
  source "$(SOURCE)/Config.in"
endef

define Package/sip-plugin
  SECTION:=terastream
  CATEGORY:=terastream
  TITLE:=sip plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libubox +libblobmsg-json +voice-client
endef

define Package/sip-plugin/description
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

define Package/sip-plugin/install

ifeq ($(CONFIG_PLUGIN),y)
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-sip.so $(1)/usr/lib/sysrepo/plugins/
else
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysrepo-plugin-dt-sip $(1)/usr/bin/
endif

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/sip@2017-08-09.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/sip.default $(1)/etc/uci-defaults/99_sip

	$(INSTALL_DIR) $(1)/etc/sysrepo/scripts/sip
	$(INSTALL_BIN) ./files/secret.sh $(1)/etc/sysrepo/scripts/sip
endef

$(eval $(call BuildPackage,sip-plugin))
