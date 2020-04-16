/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PCI_H
#define _KERNEL_PCI_H

#include <stdint.h>
#include <stdbool.h>

#include <pci/pcie.h>

#include <onyx/portio.h>
#include <onyx/spinlock.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/irq.h>

#define PCI_CONFIGURATION_SPACE_SIZE		256

#define PCI_BAR0 				0x10
#define PCI_BARx(index) 			(PCI_BAR0 + 0x4 * index)

#define PCI_NR_BARS						6

#define PCI_REGISTER_VENDOR_ID			0x0
#define PCI_REGISTER_DEVICE_ID			0x2
#define PCI_REGISTER_COMMAND 			0x4
#define PCI_REGISTER_STATUS			0x6
#define PCI_REGISTER_HEADER			0xe
#define PCI_REGISTER_REVISION_ID		0x8
#define PCI_REGISTER_PROGIF			0x9
#define PCI_REGISTER_SUBCLASS			0xa
#define PCI_REGISTER_CLASS			0xb
#define PCI_REGISTER_SUBSYSTEM_VID		0x2c
#define PCI_REGISTER_SUBSYSTEM_ID		0x2e
#define PCI_REGISTER_CAPABILTIES_POINTER	0x34
#define PCI_REGISTER_INTN 			0x3c

#define PCI_TYPE_MASK				0x7f
#define PCI_TYPE_REGULAR			0
#define PCI_TYPE_BRIDGE				1
#define PCI_TYPE_CARDBUS			2

#define CLASS_MASS_STORAGE_CONTROLLER 		1
#define CLASS_NETWORK_CONTROLLER 		2
#define CLASS_DISPLAY_CONTROLLER 		3
#define CLASS_MULTIMEDIA_CONTROLLER 		4
#define CLASS_MEMORY_CONTROLLER 		5
#define CLASS_BRIDGE_DEVICE 			6
#define CLASS_COMMUNICATIONS_CONTROLLER 	7
#define CLASS_BASE_SYSTEM_PERIPHERALS 		8
#define CLASS_INPUT_DEVICES 			9
#define CLASS_DOCKING_STATIONS 			10
#define CLASS_PROCESSORS 			11
#define CLASS_SERIAL_BUS_CONTROLLER 		12
#define CLASS_WIRELESS_CONTROLLER 		13
#define CLASS_INTELIGENT_CONTROLLER 		14
#define CLASS_SATELLITE_CONTROLLER 		15
#define CLASS_ENCRYPTION_DECRYPTION_CONTROLLER 	16
#define CLASS_DATA_AND_SIGNAL_CONTROLLER 	17

#define PCI_COMMAND_IOSPACE			(1 << 0)
#define PCI_COMMAND_MEMORY_SPACE		(1 << 1)
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

#define PCI_CAP_ID_RESERVED							(0)
#define PCI_CAP_ID_POWER_MANAGEMENT_INTERFACE		(1)
#define PCI_CAP_ID_AGP								(2)
#define PCI_CAP_ID_VPD								(3)
#define PCI_CAP_ID_SLOT_IDENT						(4)
#define PCI_CAP_ID_MSI								(5)
#define PCI_CAP_ID_COMPACTPCI_HOT_SWAP				(6)
#define PCI_CAP_ID_PCI_X							(7)
#define PCI_CAP_ID_HYPER_TRANSPORT					(8)
#define PCI_CAP_ID_VENDOR							(9)
#define PCI_CAP_ID_DEBUG_PORT						(0xA)
#define PCI_CAP_ID_COMPACTPCI_CENTRAL_RSRC_CNTRL	(0xB)
#define PCI_CAP_ID_PCI_HOTPLUG						(0xC)
#define PCI_CAP_ID_BRIDGE_SUBSYS_VENDOR				(0xD)
#define PCI_CAP_ID_AGPX8							(0xE)
#define PCI_CAP_ID_SECURE_DEVICE					(0xF)
#define PCI_CAP_ID_PCI_EXPRESS						(0x10)
#define PCI_CAP_ID_MSI_X							(0x11)
#define PCI_CAP_ID_AF								(0x13)

#define PCI_DRIVER_GENERIC 0
#define PCI_DRIVER_SPECIFIC 1

#define PCI_PMC_D1_SUPPORT	(1 << 9)
#define PCI_PMC_D2_SUPPORT	(1 << 10)

#define PCI_POWER_STATE_D0	(1 << 0)
#define PCI_POWER_STATE_D1	(1 << 1)
#define PCI_POWER_STATE_D2	(1 << 2)
#define PCI_POWER_STATE_D3	(1 << 3)

struct pci_irq
{
	bool level;
	bool active_high;
	uint32_t gsi;
};

struct pci_device_address
{
	uint16_t segment;
	uint8_t bus;
	uint8_t device;
	uint8_t function;
};

struct pci_device
{
	struct device dev;
	uint16_t deviceID, vendorID;
	uint8_t bus, device, function;
	uint8_t pciClass, subClass, progIF;
	int type;
	bool has_power_management;
	uint8_t pm_cap_off;
	/* Given by PCI, we just cache it here */
	int supported_power_states;
	int current_power_state;
	uint16_t segment;
	uint64_t (*read)(struct pci_device *dev, uint16_t offset, size_t size);
	void (*write)(struct pci_device *dev, uint64_t val, uint16_t offset, size_t size);
	struct pci_device *next __align_cache;
	struct pci_irq pin_to_gsi[4];
	void *driver_data;
};

struct pci_bar
{
	uint64_t address;
	bool is_iorange;
	bool may_prefetch;
	size_t size;
};

#define PCI_ID_BY_CLASS		0
#define PCI_ID_BY_ID		1

#define PCI_ANY_ID	0xff

struct pci_id
{
	uint16_t device_id;
	uint16_t vendor_id;
	uint8_t pci_class;
	uint8_t subclass;
	uint8_t progif;
	void *driver_data;
};

#define PCI_ID_DEVICE(vendor, dev, drv_data) \
.device_id = dev, .vendor_id = vendor, .pci_class = PCI_ANY_ID, \
.subclass = PCI_ANY_ID, .progif = PCI_ANY_ID, .driver_data = drv_data

#define PCI_ID_CLASS(c, s, p, drv_data) \
.device_id = PCI_ANY_ID, .vendor_id = PCI_ANY_ID, \
.pci_class = c, .subclass = s, .progif = p, \
.driver_data = drv_data

#ifdef __cplusplus
extern "C" {
#endif

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
uint16_t pci_get_intn(struct pci_device *dev);

struct pci_device *pci_get_dev(struct pci_device_address *addr);

void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch);
void pci_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size);
uint64_t pci_read(struct pci_device *dev, uint16_t off, size_t size);
void pci_enable_busmastering(struct pci_device *dev);
void pci_disable_busmastering(struct pci_device *dev);
void pci_disable_irq(struct pci_device *dev);
void pci_enable_irq(struct pci_device *dev);
size_t pci_find_capability(struct pci_device *dev, uint8_t cap, int instance);
int pci_enable_msi(struct pci_device *dev, irq_t handler, void *cookie);
void pci_bus_register_driver(struct driver *driver);
int pci_get_bar(struct pci_device *dev, int index, struct pci_bar *bar);
void *pci_map_bar(struct pci_device *device, int index, unsigned int caching);

int pci_enable_device(struct pci_device *device);
int pci_reset_device(struct pci_device *device);
uint16_t pci_get_subsys_id(struct pci_device *dev);

#ifdef __cplusplus
}
#endif

typedef void (*pci_callback_t)(struct pci_device *dev);
typedef struct
{
	uint16_t deviceID, vendorID;
	uint8_t pciClass, subClass, progIF;
	uint8_t driver_type;
	pci_callback_t cb;
} pci_driver_t;

#endif
