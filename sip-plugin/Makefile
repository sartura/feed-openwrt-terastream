include $(TOPDIR)/rules.mk

PKG_NAME:=sip-plugin
PKG_RELEASE:=3
PKG_VERSION:=1.0.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sartura/sip-plugin.git
PKG_SOURCE_VERSION:=7d8df926bc4f21df6f5622fa1c6d7a209e9dec81
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)

PKG_BUILD_ROOT:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DIR:=$(PKG_BUILD_ROOT)

PKG_MAINTAINER:=Luka Paulic <luka.paulic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/sip-plugin
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=sip plugin
  DEPENDS:= +libsysrepo-v1.x.x +libuci +sysrepoctl-v1.x.x +libubus +libubox +libblobmsg-json +voice-client
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
