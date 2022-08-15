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

ifeq ($(CONFIG_X86), y)

ifeq ($(CONFIG_X86_PLATFORM), pc)

include drivers/pci/Makefile
include drivers/ps2/Makefile
include drivers/rtc/Makefile

endif
endif

ifeq ($(CONFIG_RISCV), y)

include drivers/pci/Makefile

endif

ifeq ($(CONFIG_ARM64), y)

include drivers/pci/Makefile

endif
