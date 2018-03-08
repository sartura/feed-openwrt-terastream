include $(TOPDIR)/rules.mk

PKG_NAME:=test-plugin
PKG_RELEASE:=2018-02-20
PKG_VERSION:=0.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/test-plugin.git
PKG_SOURCE_VERSION:=5afa2355df72ea7e4caeced24da97fc22ca954b7
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/test-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=test plugin
  DEPENDS:= +sysrepo +sysrepoctl
endef

define Package/test-plugin/description
	Sysrepo plugin for end to end tests.
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Release \
	-DPLUGIN:BOLL=TRUE

define Package/test-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysrepo-plugin-dt-test.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/test-plugin@2018-02-20.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/test.default $(1)/etc/uci-defaults/99_test
endef

$(eval $(call BuildPackage,test-plugin))
