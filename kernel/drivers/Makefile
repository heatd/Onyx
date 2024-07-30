include drivers/build-helper.config

$(eval $(call INCLUDE_IF_ENABLED,CONFIG_AHCI,ahci))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_ATA,ata))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_BGA,bga))
#$(eval $(call INCLUDE_IF_ENABLED,CONFIG_IGD,igd))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_QXL,qxl))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_SVGA,svga))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_USB,usb))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_VIRTIO,virtio))
$(eval $(call INCLUDE_IF_ENABLED,CONFIG_NVME,nvme))


include drivers/mmio_utils/Makefile
include drivers/serial/Makefile
include drivers/net/Makefile
include drivers/firmware/Makefile
include drivers/rtc/Makefile
include drivers/acpi/Makefile
include drivers/pci/Makefile
include drivers/ps2/Makefile
