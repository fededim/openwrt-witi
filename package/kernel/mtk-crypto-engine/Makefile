#
# Copyright (C) 2015
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mtk-crypto-engine
PKG_VERSION:=4.3.2.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

PKG_MAINTAINER:=Gino pino <gino@pino.org>
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define KernelPackage/mtk-crypto-engine
	SUBMENU:=Cryptographic API modules
	TITLE:=Mediatek IPSec HW Crypto Engine
	FILES:=$(PKG_BUILD_DIR)/mtk-crypto-eng.ko
	AUTOLOAD:=$(call AutoLoad,30,mtk_aes,1)
	DEPENDS:=+kmod-random-core +kmod-crypto-manager +kmod-crypto-cbc +kmod-crypto-ecb +kmod-crypto-rng
endef

define KernelPackage/mtk-crypto-engine/description
	Mediatek HW Ipsec Acceleration Engine
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	M="$(PKG_BUILD_DIR)" \
        LINUXINCLUDE="-I${CURDIR}/src/include -I$(LINUX_DIR)/include -include linux/kconfig.h -I$(LINUX_DIR)/arch/$(LINUX_KARCH)/include -I$(LINUX_DIR)/arch/$(LINUX_KARCH)/include/generated -I$(TOOLCHAIN_DIR)/include" \
	EXTRA_CFLAGS="-DCONFIG_RALINK_MT7621 -DRT_EIP93_DRIVER -DRT_EIP93_DRIVER_DEBUG -DRT_EIP93_DRIVER_DEBUG_H -DMTK_CRYPTO_DRIVER -DHWPAL_TRACE_DEVICE_FIND -DVDRIVER_INTERRUPTS"# for latest openwrt add also option  -Wno-error=date-time for witi remove


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
	
define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	CONFIG_CRYPTO_DEV_MTK_CRYPTO=m \
	modules
endef

#define Package/mtk-crypto-engine/install
#        $(INSTALL_DIR) $(1)/usr/sbin
#        $(INSTALL_BIN) $(PKG_BUILD_DIR)/px5g $(1)/usr/sbin/px5g
#endef

$(eval $(call KernelPackage,mtk-crypto-engine))
