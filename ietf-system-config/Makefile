include $(TOPDIR)/rules.mk

PKG_NAME:=ietf-system-config
PKG_RELEASE:=2018-10-03
PKG_VERSION:=0.0.1

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

include $(INCLUDE_DIR)/package.mk

define Package/ietf-system-config
  SECTION:=Terastream
  CATEGORY:=Terastream
  TITLE:=ietf-system configuration data
  DEPENDS:= +netopeer2-server +sysrepoctl +sysrepocfg
endef

define Package/ietf-system-config/description
	Startup configuration for ietf-system YANG model.
endef

define Build/Compile
endef

define Package/ietf-system-config/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ietf-system-config.default $(1)/etc/uci-defaults/99_ietf-system-config

	$(INSTALL_DIR) $(1)/usr/share/terastream
	$(INSTALL_DATA) ./files/ietf-system-config.xml $(1)/usr/share/terastream/ietf-system-config.xml
endef

$(eval $(call BuildPackage,ietf-system-config))
