include $(TOPDIR)/rules.mk

PKG_NAME:=sip-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1.5

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/sip-plugin.git
PKG_SOURCE_VERSION:=d2b746bde8507303ab4f7af2700728b2771d5c65
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/sip-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=sip plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libubox +libblobmsg-json +voice-client
endef

define Package/sip-plugin/description
	Sysrepo sip plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE

define Package/sip-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-sip.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-sip@2017-08-09.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/sip.default $(1)/etc/uci-defaults/99_sip

	$(INSTALL_DIR) $(1)/etc/sysrepo/scripts/sip
	$(INSTALL_BIN) ./files/secret.sh $(1)/etc/sysrepo/scripts/sip
endef

$(eval $(call BuildPackage,sip-plugin))
