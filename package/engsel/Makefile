# SPDX-License-Identifier: GPL-2.0-or-later
#
# OpenWrt Package Makefile untuk engsel (me-cli-sunset port C)
# INI BUKAN GNU Makefile biasa! Ini adalah OpenWrt Package Makefile.
# Letakkan di: package/engsel/Makefile (dalam OpenWrt SDK)
#

include $(TOPDIR)/rules.mk

PKG_NAME:=engsel
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/engsel
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=engsel - XL Axiata CLI client (C port)
  URL:=https://github.com/youruser/me-cli-sunset-c
  MAINTAINER:=Rofiq
  DEPENDS:=+libcurl +libopenssl +libpthread
endef

define Package/engsel/description
  CLI client untuk XL Axiata (me-cli-sunset porting ke C).
  Jalankan dengan mengetik "engsel" di terminal.
  Data konfigurasi disimpan di /etc/engsel/
endef

# Salin seluruh isi folder src/ (src/, include/, Makefile) ke build dir
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -lssl -lcrypto -lcurl -lm -lpthread"
endef

define Package/engsel/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/engsel $(1)/usr/bin/engsel

	$(INSTALL_DIR) $(1)/etc/engsel
	$(INSTALL_DATA) ./files/etc/engsel/.env $(1)/etc/engsel/.env
	$(INSTALL_DATA) ./files/etc/engsel/refresh-tokens.json $(1)/etc/engsel/refresh-tokens.json
	$(INSTALL_DATA) ./files/etc/engsel/bookmark.json $(1)/etc/engsel/bookmark.json

	$(INSTALL_DIR) $(1)/etc/engsel/hot_data
	$(INSTALL_DATA) ./files/etc/engsel/hot_data/hot.json $(1)/etc/engsel/hot_data/hot.json

	$(INSTALL_DIR) $(1)/etc/engsel/decoy_data
	$(INSTALL_DATA) ./files/etc/engsel/decoy_data/decoy-prabayar-balance.json $(1)/etc/engsel/decoy_data/decoy-prabayar-balance.json
	$(INSTALL_DATA) ./files/etc/engsel/decoy_data/decoy-prio-balance.json $(1)/etc/engsel/decoy_data/decoy-prio-balance.json
	$(INSTALL_DATA) ./files/etc/engsel/decoy_data/decoy-priohybrid-balance.json $(1)/etc/engsel/decoy_data/decoy-priohybrid-balance.json
endef

# File-file ini akan dipreservasi saat upgrade (tidak ditimpa opkg/apk)
define Package/engsel/conffiles
/etc/engsel/.env
/etc/engsel/refresh-tokens.json
/etc/engsel/bookmark.json
endef

$(eval $(call BuildPackage,engsel))
