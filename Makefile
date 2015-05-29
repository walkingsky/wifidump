#
# a demo tool for dump wifi device
# by walkingsky  tangxn_1@163.com
#

include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=wifidump
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk

define Package/wifidump
  SECTION:=net
  CATEGORY:=Utilities
  SUBMENU:=walkingsky
  TITLE:=wifidump
  DEPENDS:=+libpcap +libsqlite3
endef

define Package/wifidump/description
	a demo tool for dump wifi device
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) CFLAGS="$(TARGET_CFLAGS) -I$(LINUX_DIR)/include"
endef

define Package/wifidump/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wifidump $(1)/usr/bin/
endef

$(eval $(call BuildPackage,wifidump))
