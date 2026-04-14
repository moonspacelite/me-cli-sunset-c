# SPDX-License-Identifier: GPL-2.0-or-later
include $(TOPDIR)/rules.mk

PKG_NAME:=engsel
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/moonspacelite/me-cli-sunset-c.git
# Gunakan commit hash terbaru yang sudah Anda push
PKG_SOURCE_VERSION:=7b6b423f212de41bbf6e5076ea3c39ca52c3ad7d
# Hash yang didapat dari log sebelumnya
PKG_MIRROR_HASH:=453432e349dc7ec394f36e2a1b13059f1ae11cd91957192fa48ca5acf5392a85

# Biarkan sistem OpenWrt mengekstrak tarball ke subdirektori ini
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.zst
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)

include $(INCLUDE_DIR)/package.mk

define Package/engsel
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=engsel - XL Axiata CLI client (C port)
  URL:=https://github.com/moonspacelite/me-cli-sunset-c
  MAINTAINER:=Rofiq
  DEPENDS:=+libcurl +libopenssl +libpthread
endef

define Package/engsel/description
  CLI client untuk XL Axiata (me-cli-sunset porting ke C).
  Jalankan dengan mengetik "engsel" di terminal.
  Data konfigurasi disimpan di /etc/engsel/
endef

# Tidak perlu Build/Prepare, source otomatis di-extract

define Build/Compile
	# Asumsi Makefile untuk kompilasi C ada di subdirektori src/
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -lssl -lcrypto -lcurl -lm -lpthread"
endef

define Package/engsel/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/engsel $(1)/usr/bin/engsel

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

define Package/engsel/conffiles
/etc/engsel/.env
/etc/engsel/refresh-tokens.json
/etc/engsel/bookmark.json
endef

$(eval $(call BuildPackage,engsel))
