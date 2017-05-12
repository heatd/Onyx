/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PCI_H
#define _KERNEL_PCI_H
#include <stdint.h>
#include <kernel/portio.h>

typedef struct PCIDevice
{
	uint16_t deviceID, vendorID;
	char* vendor_string, *function_string;
	uint8_t slot, device, function;
	uint8_t pciClass, subClass, progIF;
	struct PCIDevice* next;
} PCIDevice;
typedef struct
{
	uint32_t address;
	_Bool isPrefetchable;
	_Bool isIO;
	size_t size;
} pcibar_t;

void pci_init();
uint16_t pci_config_read_word (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void pci_check_devices();
uint32_t pci_config_read_dword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
const char* pci_identify_common_vendors(uint16_t vendorID);
const char* pci_identify_device_type(uint16_t headerType);
const char* pci_identify_device_function(uint8_t pciClass, uint8_t subClass, uint8_t progIF);
pcibar_t* pci_get_bar(uint8_t slot, uint8_t device, uint8_t function, uint8_t barindex);
uint16_t pci_get_intn(uint8_t slot, uint8_t device, uint8_t function);
PCIDevice *get_pcidev_from_vendor_device(uint16_t deviceid, uint16_t vendorid);
PCIDevice *get_pcidev_from_classes(uint8_t class, uint8_t subclass, uint8_t progif);
void pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data);
void pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data);
void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch);
#define PCI_BAR0 0x10
#define PCI_BARx(index) (PCI_BAR0 + 0x4 * index)
#define PCI_INTN 0x3C
#define PCI_COMMAND 0x4
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

typedef void (*pci_callback_t)(PCIDevice *dev);
#define PCI_DRIVER_GENERIC 0
#define PCI_DRIVER_SPECIFIC 1
typedef struct
{
	uint16_t deviceID, vendorID;
	uint8_t pciClass, subClass, progIF;
	uint8_t driver_type;
	pci_callback_t cb;
} pci_driver_t;

void pci_initialize_drivers();
#endif
