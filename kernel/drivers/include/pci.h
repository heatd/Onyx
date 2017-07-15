/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PCI_H
#define _KERNEL_PCI_H

#include <stdint.h>

#include <kernel/portio.h>
#include <kernel/spinlock.h>
#include <kernel/compiler.h>
#include <kernel/dev.h>

#define PCI_CONFIGURATION_SPACE_SIZE	256
#define PCI_BAR0 0x10
#define PCI_BARx(index) (PCI_BAR0 + 0x4 * index)
#define PCI_INTN 0x3C
#define PCI_COMMAND 0x4
#define PCI_REG_STATUS			0x6
#define PCI_REG_CAPABILTIES_POINTER	0x34
#define CLASS_MASS_STORAGE_CONTROLLER 0x1
#define CLASS_NETWORK_CONTROLLER 0x2
#define CLASS_DISPLAY_CONTROLLER 0x3
#define CLASS_MULTIMEDIA_CONTROLLER 0x4
#define CLASS_MEMORY_CONTROLLER 0x5
#define CLASS_BRIDGE_DEVICE 0x6
#define CLASS_COMMUNICATIONS_CONTROLLER 0x7
#define CLASS_BASE_SYSTEM_PERIPHERALS 0x8
#define CLASS_INPUT_DEVICES 0x9
#define CLASS_DOCKING_STATIONS 0xA
#define CLASS_PROCESSORS 0xB
#define CLASS_SERIAL_BUS_CONTROLLER 0xC
#define CLASS_WIRELESS_CONTROLLER 0xD
#define CLASS_INTELIGENT_CONTROLLER 0xE
#define CLASS_SATELLITE_CONTROLLER 0xF
#define CLASS_ENCRYPTION_DECRYPTION_CONTROLLER 0x10
#define CLASS_DATA_AND_SIGNAL_CONTROLLER 0x11

#define PCI_COMMAND_IOSPACE			(1)
#define PCI_COMMAND_MEMORY_SPACE		(2)
#define PCI_COMMAND_BUS_MASTER			(1 << 2)
#define PCI_COMMAND_SPECIAL_CYCLES		(1 << 3)
#define PCI_COMMAND_MEMORY_WRITE_AND_INV	(1 << 4)
#define PCI_COMMAND_VGA_PALETTE_SNOOP		(1 << 5)
#define PCI_COMMAND_PARITY_ERROR_RESPONSE	(1 << 6)
#define PCI_COMMAND_SERR_ENABLE			(1 << 8)
#define PCI_COMMAND_FAST_BACK2BACK		(1 << 9)
#define PCI_COMMAND_INTR_DISABLE		(1 << 10)

#define PCI_STATUS_INT_STATUS			(1 << 3)
#define PCI_STATUS_CAP_LIST_SUPPORTED		(1 << 4)
#define PCI_STATUS_66MHZ			(1 << 5)
#define PCI_STATUS_FAST_BACK2BACK		(1 << 7)
#define PCI_STATUS_MASTER_DATA_PARITY_ERROR	(1 << 8)
#define PCI_STATUS_DEVSEL_TIMING		((1 << 9) | (1 << 10))
#define PCI_STATUS_SIGNALED_TARGET_ABORT	(1 << 11)
#define PCI_STATUS_RECEIVED_TARGET_ABORT	(1 << 12)
#define PCI_STATUS_RECEIVED_MASTER_ABORT	(1 << 13)
#define PCI_STATUS_SIGNALED_SYSTEM_ERROR	(1 << 14)
#define PCI_STATUS_DETECTED_PARITY_ERROR	(1 << 15)

#define PCI_CAP_ID_RESERVED				(0)
#define PCI_CAP_ID_POWER_MANAGEMENT_INTERFACE		(1)
#define PCI_CAP_ID_AGP					(2)
#define PCI_CAP_ID_VPD					(3)
#define PCI_CAP_ID_SLOT_IDENT				(4)
#define PCI_CAP_ID_MSI					(5)
#define PCI_CAP_ID_COMPACTPCI_HOT_SWAP			(6)
#define PCI_CAP_ID_PCI_X				(7)
#define PCI_CAP_ID_HYPER_TRANSPORT			(8)
#define PCI_CAP_ID_VENDOR				(9)
#define PCI_CAP_ID_DEBUG_PORT				(0xA)
#define PCI_CAP_ID_COMPACTPCI_CENTRAL_RSRC_CNTRL	(0xB)
#define PCI_CAP_ID_PCI_HOTPLUG				(0xC)
#define PCI_CAP_ID_BRIDGE_SUBSYS_VENDOR			(0xD)
#define PCI_CAP_ID_AGPX8				(0xE)
#define PCI_CAP_ID_SECURE_DEVICE			(0xF)
#define PCI_CAP_ID_PCI_EXPRESS				(0x10)
#define PCI_CAP_ID_MSI_X				(0x11)

#define PCI_DRIVER_GENERIC 0
#define PCI_DRIVER_SPECIFIC 1
struct pci_device
{
	struct device dev;
	uint16_t deviceID, vendorID;
	uint8_t bus, device, function;
	uint8_t pciClass, subClass, progIF;
	struct pci_device* next __align_cache;
};
typedef struct
{
	uint32_t address;
	_Bool isPrefetchable;
	_Bool isIO;
	size_t size;
} pcibar_t;

void pci_init();
uint16_t __pci_config_read_word (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
uint32_t __pci_config_read_dword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void __pci_write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t data);
void __pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data);
void __pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data);
void __pci_write_qword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint64_t data);
void pci_check_devices();
const char* pci_identify_common_vendors(uint16_t vendorID);
const char* pci_identify_device_type(uint16_t headerType);
const char* pci_identify_device_function(uint8_t pciClass, uint8_t subClass, uint8_t progIF);
pcibar_t* pci_get_bar(struct pci_device *dev, uint8_t barindex);
uint16_t pci_get_intn(uint8_t slot, uint8_t device, uint8_t function);
struct pci_device *get_pcidev_from_vendor_device(uint16_t deviceid, uint16_t vendorid);
struct pci_device *get_pcidev(uint8_t bus, uint8_t device, uint8_t function);
struct pci_device *get_pcidev_from_classes(uint8_t class, uint8_t subclass, uint8_t progif);
void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch);
void pci_initialize_drivers();
void pci_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size);
uint64_t pci_read(struct pci_device *dev, uint16_t off, size_t size);
void pci_enable_busmastering(struct pci_device *dev);
off_t pci_find_capability(struct pci_device *dev, uint8_t cap);
int pci_enable_msi(struct pci_device *dev);
typedef void (*pci_callback_t)(struct pci_device *dev);
typedef struct
{
	uint16_t deviceID, vendorID;
	uint8_t pciClass, subClass, progIF;
	uint8_t driver_type;
	pci_callback_t cb;
} pci_driver_t;

#endif
