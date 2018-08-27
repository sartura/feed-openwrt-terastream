include $(TOPDIR)/rules.mk

PKG_NAME:=mB4
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/mB4-$(PKG_VERSION)
PKG_SOURCE:=mB4-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/mb4
PKG_HASH:=f6cf06e8ed80a3dff86f676d154f322a57150690276aaa3fce2f50bcac1e0cea

PKG_MAINTAINER:=Mislav Novakovic <mislav.novakovic@sartura.hr>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/mB4
  SECTION:=Terastream
  CATEGORY:=Terastream
  URL:=https://sourceforge.net/projects/mb4/
  TITLE:=mB4
endef

define Package/mB4/description
	France Telecom/Orange Labs Beijing has developed the “mB4 function” that conveys the contents
	of IGMP Report messages sent by the IPv4 multicast receiver into the equivalent MLD Report
	messages which are forwarded by the CPE towards the MLD Querier located upstream in the IPv6
	multicast network for further processing.
endef

define Package/mB4/install
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mB4 $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/my-plugin $(1)/etc/init.d/my-plugin

	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./files/multi_forward.conf $(1)/etc
endef

$(eval $(call BuildPackage,mB4))
