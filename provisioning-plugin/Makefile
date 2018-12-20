include $(TOPDIR)/rules.mk

PKG_NAME:=provisioning-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1.5

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/provisioning-plugin.git
PKG_SOURCE_VERSION:=41fac1d252ff3cfa7df44424c7e8fedd111a9a0b
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)


PKG_MAINTAINER:=Petar Paradzik <petar.paradzik@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/provisioning-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=provisioning plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libubox +libblobmsg-json +sr-uci
endef

define Package/provisioning-plugin/description
	Sysrepo provisioning plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Debug \
	-DPLUGIN:BOLL=TRUE

define Package/provisioning-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/sysrepo-plugin-dt-provisioning.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-provisioning@2018-05-14.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/provisioning.default $(1)/etc/uci-defaults/99_provisioning
endef

$(eval $(call BuildPackage,provisioning-plugin))
