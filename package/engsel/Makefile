# SPDX-License-Identifier: GPL-2.0-or-later
#
# OpenWrt Package Makefile untuk engsel (me-cli-sunset port C)
# Letakkan di: package/engsel/Makefile (dalam OpenWrt SDK)
#

include $(TOPDIR)/rules.mk

PKG_NAME:=engsel
# --- PENTING: Versi harus sesuai format APK (hanya angka & titik) ---
PKG_VERSION:=1.0.0
# --- PENTING: Pastikan format PKG_RELEASE adalah angka, tidak ada simbol lain ---
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/moonspacelite/me-cli-sunset-c.git
# --- PENTING: Gunakan commit hash spesifik, bukan HEAD, untuk konsistensi ---
PKG_SOURCE_VERSION:=b44c4753eac1269668c7771fce4966cdeff70f5a452d75d4f69e1e74e73adfbc # Contoh: a1b2c3d4...
# --- PENTING: Isi dengan hash SHA256 yang valid, jangan 'skip' atau kosong ---
PKG_MIRROR_HASH:=53591c1ac087cc8e7a664973b2103b57d33ea9f4

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

# --- PENTING: Override Build/Prepare untuk sumber lokal ---
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

# File-file ini akan dipreservasi saat upgrade (tidak ditimpa apk)
define Package/engsel/conffiles
/etc/engsel/.env
/etc/engsel/refresh-tokens.json
/etc/engsel/bookmark.json
endef

$(eval $(call BuildPackage,engsel))
