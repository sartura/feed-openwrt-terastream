include $(TOPDIR)/rules.mk

PKG_NAME:=dhcp-plugin
PKG_RELEASE:=2017-07-31
PKG_VERSION:=0.1.1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/dhcp.git
PKG_SOURCE_VERSION:=42c7489e884163d8c380925e0affc5e37d22547f
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/dhcp-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=dhcp plugin
  DEPENDS:= +sysrepo +libuci +sysrepoctl +libubus +libubox +libblobmsg-json
endef

define Package/dhcp-plugin/description
	Sysrepo DHCP plugin
endef

CMAKE_OPTIONS:= \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_BUILD_TYPE=Release \
	-DPLUGIN:BOLL=TRUE

define Package/dhcp-plugin/install
	$(INSTALL_DIR) $(1)/usr/lib/sysrepo/plugins/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/sysrepo-plugin-dt-dhcp.so $(1)/usr/lib/sysrepo/plugins/

	$(INSTALL_DIR) $(1)/etc/sysrepo/yang
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/yang/terastream-dhcp@2017-12-07.yang $(1)/etc/sysrepo/yang/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/dhcp.default $(1)/etc/uci-defaults/99_dhcp
endef

$(eval $(call BuildPackage,dhcp-plugin))
