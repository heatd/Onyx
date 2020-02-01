include drivers/build-helper.config

$(eval $(call INCLUDE_IF_ENABLED,CONFIG_AHCI,ahci))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_ATA,ata))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_BGA,bga))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_E1000,e1000))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_IGD,igd))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_QXL,qxl))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_RTL8139,rtl8139))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_SVGA,svga))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_USB,usb))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_VIRTIO,virtio))

include drivers/mmio_utils/Makefile
include drivers/pci/Makefile
include drivers/ps2/Makefile
include drivers/rtc/Makefile
