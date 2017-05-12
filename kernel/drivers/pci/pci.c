/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>

#include <kernel/compiler.h>
#include <kernel/log.h>
#include <kernel/acpi.h>
#include <kernel/panic.h>

#include <drivers/pci.h>

const uint16_t CONFIG_ADDRESS = 0xCF8;
const uint16_t CONFIG_DATA = 0xCFC;


	/* A _HUGE_ function to identify the device's function using the device's class, subClass and progIF
	   Returns a pointer to a string that is the purpose of the device
	   Returns "Unknown" on error
	   */
	const char* IdentifyDeviceFunction(uint8_t pciClass, uint8_t subClass, uint8_t progIF)
	{
		switch(pciClass)
		{
			case 0:
			{
				switch(subClass)
				{
					case 1:
						return "VGA-compatible device";
					default:
						return "Legacy device";
				}
				break;
			}
			case CLASS_MASS_STORAGE_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						return "SCSI Bus Controller";
					}
					case 1:
					{
						return "IDE Controller";
					}
					case 2:
					{
						return "Floppy Disk Controller";
					}
					case 3:
					{
						return "IPI Bus Controller";
					}
					case 4:
					{
						return "RAID Controller";
					}
					case 5:
					{
						switch(progIF)
						{
							case 0x20:
								return "ATA Controller(Single DMA)";
							case 0x30:
								return "ATA Controller(Chained DMA)";
							default:
								return "ATA Controller";
						}
					}
					case 6:
					{
						switch(progIF)
						{
							case 0:
								return "Serial ATA(Vendor Specific Interface)";
							case 1:
								return "Serial ATA(AHCI 1.0)";
							default:
								return "Serial ATA";
						}
					}
					case 7:
					{
						return "Serial attached SCSI";
					}
					case 0x80:
					{
						return "Unknown Mass Storage Controller";
					}


				}
				break;
			}
			case CLASS_NETWORK_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						return "Ethernet Controller";
					}
					case 1:
					{
						return "Token Ring Controller";
					}
					case 2:
					{
						return "FDDI Controller";
					}
					case 3:
					{
						return "ATM Controller";
					}
					case 4:
					{
						return "ISDN Controller";
					}
					case 5:
					{
						return "WorldFip Controller";
					}
					case 6:
					{
						return "PICMG 2.14 Multi Computing";
					}
					case 0x80:
					{
						return "Unknown Ethernet Controller";
					}
				}
				break;
			}
			case CLASS_DISPLAY_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						if(progIF)
							return "8152-Compatible Controller";
						return "VGA-Compatible Controller";
					}
					case 1:
					{
						return "XGA Controller";
					}
					case 2:
					{
						return "3D Controller";
					}
					case 0x80:
					{
						return "Unknown Display Controller";
					}
				}
				break;
			}
			case CLASS_MULTIMEDIA_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						return "Video Device";
					}
					case 1:
					{
						return "Audio Device";
					}
					case 2:
					{
						return "Computer Telephony Device";
					}
					case 0x80:
					{
						return "Unknown Multimedia Device";
					}
				}
				break;
			}
			case CLASS_MEMORY_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						return "RAM Controller";
					}
					case 1:
					{
						return "Flash Controller";
					}
					case 0x80:
					{
						return "Unknown Memory Controller";
					}
				}
				break;
			}
			case CLASS_BRIDGE_DEVICE:
			{
				switch(subClass)
				{
					case 0:
					{
						return "Host Bridge";
					}
					case 1:
					{
						return "ISA Bridge";
					}
					case 2:
					{
						return "EISA Bridge";
					}
					case 3:
					{
						return "MCA Bridge";
					}
					case 4:
					{
						return "PCI-to-PCI Bridge";
					}
					case 5:
					{
						return "PCMCIA Bridge";
					}
					case 6:
					{
						return "NuBus Bridge";
					}
					case 7:
					{
						return "CardBus Bridge";
					}
					case 8:
					{
						return "RACEway Bridge";
					}
					case 9:
					{
						switch(progIF)
						{
							case 0x40:
								return "PCI-to-PCI Bridge (Semi-Transparent, Primary)";
							case 0x80:
								return "PCI-to-PCI Bridge (Semi-Transparent, Secondary)";
							default:
								return "PCI-to-PCI Bridge";
						}
					}
					case 0xA:
					{
						return "InfiniBrand-to-PCI Host Bridge";
					}
					case 0x80:
					{
						return "Unknown Bridge Device";
					}
				}
				break;
			}
			case CLASS_COMMUNICATIONS_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						switch(progIF)
						{
							case 0:
							{
								return "Generic XT-Compatible Serial Controller";
							}
							case 1:
							{
								return "16450-Compatible Serial Controller";
							}
							case 2:
							{
								return "16550-Compatible Serial Controller";
							}
							case 3:
							{
								return "16650-Compatible Serial Controller";
							}
							case 4:
							{
								return "16750-Compatible Serial Controller";
							}
							case 5:
							{
								return "16850-Compatible Serial Controller";
							}
							case 6:
							{
								return "16950-Compatible Serial Controller";
							}
						}
					}
					case 0x1:
					{
						switch(progIF)
						{
							case 0:
							{
								return "Parallel Port";
							}
							case 1:
							{
								return "Bi-directional Parallel Port";
							}
							case 2:
							{
								return "ECP 1.X Compliant Parallel Port";
							}
							case 3:
							{
								return "IEEE 1284 Controller";
							}
							case 0xFE:
							{
								return "IEEE 1284 Target Device";
							}
						}
					}
					case 0x2:
					{
						return "Multiport Serial Controller";
					}
					case 0x3:
					{
						switch(progIF)
						{
							case 0:
							{
								return "Generic Modem";
							}
							case 0x1:
							{
								return "Hayes Compatible Modem (16450-Compatible Interface)";
							}
							case 0x2:
							{
								return "Hayes Compatible Modem (16550-Compatible Interface)";
							}
							case 0x3:
							{
								return "Hayes Compatible Modem (16650-Compatible Interface)";
							}
							case 0x4:
							{
								return "Hayes Compatible Modem (16750-Compatible Interface)";
							}
						}
					}
					case 0x4:
					{
						return "IEEE 488.1/2 (GPIB) Controller";
					}
					case 0x5:
					{
						return "Smart Card";
					}
					case 0x80:
					{
						return "Unknown Communications Device";
					}
				}
				break;
			}
			case CLASS_BASE_SYSTEM_PERIPHERALS:
			{
				switch(subClass)
				{
					case 0:
					{
						switch(progIF)
						{
							case 0:
								return "Generic 8259 PIC";
							case 1:
								return "ISA PIC";
							case 2:
								return "EISA PIC";
							case 0x10:
								return "I/O APIC Interrupt Controller";
							case 0x20:
								return "I/O(x) APIC Interrupt Controller";
						}
					}
					case 1:
					{
						switch(progIF)
						{
							case 0:
								return "Generic 8237 DMA Controller";
							case 1:
								return "ISA DMA Controller";
							case 2:
								return "EISA DMA Controller";
						}
					}
					case 2:
					{
						switch(progIF)
						{
							case 0:
								return "Generic 8254 System Timer";
							case 1:
								return "ISA System Timer";
							case 2:
								return "EISA System Timer";
						}
					}
					case 3:
					{
						switch(progIF)
						{
							case 0:
								return "Generic RTC Controller";
							case 1:
								return "ISA RTC Controller";
						}
					}
					case 4:
					{
						return "Genetic PCI Hot-plug Controller";
					}
					case 0x80:
					{
						return "Unknown System Peripheral";
					}
				}
				break;
			}
			case CLASS_INPUT_DEVICES:
			{
				switch(subClass)
				{
					case 0:
						return "Keyboard Controller";
					case 1:
						return "Digitizer";
					case 2:
						return "Mouse Controller";
					case 3:
						return "Scanner Controller";
					case 4:
						return "Gameport Controller";
					case 0x80:
						return "Unknown Input Controller";
				}
			}
			case CLASS_DOCKING_STATIONS:
			{
				switch(subClass)
				{
					case 0:
						return "Generic Docking Station";
					case 0x80:
						return "Unknown Docking Station";
				}
			}
			case CLASS_PROCESSORS:
			{
				switch(subClass)
				{
					case 0:
						return "I386 Processor";
					case 1:
						return "I486 Processor";
					case 2:
						return "Pentium Processor";
					case 0x10:
						return "Alpha Processor";
					case 0x20:
						return "PowerPC Processor";
					case 0x30:
						return "MIPS Processor";
					case 0x40:
						return "Co-Processor";
				}
			}
			case CLASS_SERIAL_BUS_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
					{
						switch(progIF)
						{
							case 0:
								return "IEEE 1394 Controller (FireWire)";
							case 0x10:
								return "IEEE 1394 Controller (1394 OpenHCI Spec)";
						}
					}
					case 1:
						return "ACCESS.bus";
					case 2:
						return "SSA";
					case 3:
					{
						switch(progIF)
						{
							case 0:
								return "USB (Universal Host Controller Spec)";
							case 0x10:
								return "USB (Open Host Controller Spec)";
							case 0x20:
								return "USB2 Host Controller (Intel Enhanced Host Controller Interface)";
							case 0x30:
								return "USB3 XHCI Controller";
							case 0x80:
								return "Unspecified USB Controller";
							case 0xFE:
								return "USB (Not Host Controller)";

						}
					}
					case 4:
						return "Fibre Channel";
					case 5:
						return "SMBus";
					case 6:
						return "InfiniBand";
					case 7:
					{
						switch(progIF)
						{
							case 0:
								return "IPMI SMIC Interface";
							case 1:
								return "IPMI Kybd Controller Style Interface";
							case 2:
								return "IPMI Block Transfer Interface";
						}
					}
					case 8:
						return "SERCOS Interface Standard (IEC 61491)";
					case 9:
						return "CANbus";
				}
			}
			case CLASS_WIRELESS_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
						return "iRDA Compatible Controller";
					case 1:
						return "Consumer IR Controller";
					case 0x10:
						return "RF Controller";
					case 0x11:
						return "Bluetooth Controller";
					case 0x12:
						return "Broadband Controller";
					case 0x20:
						return "Ethernet Controller (802.11a)";
					case 0x21:
						return "Ethernet Controller (802.11b)";
					case 0x80:
						return "Unknown Wireless Controller";
				}
			}
			case CLASS_INTELIGENT_CONTROLLER:
			{
				switch(subClass)
				{
					switch(progIF)
					{
						case 0:
							return "Message FIFO";
						default:
							return "I20 Architecture";
					}
				}
			}
			case CLASS_SATELLITE_CONTROLLER:
			{
				switch(subClass)
				{
					case 1:
						return "TV Controller";
					case 2:
						return "Audio Controller";
					case 3:
						return "Voice Controller";
					case 4:
						return "Data Controller";
				}
			}
			case CLASS_ENCRYPTION_DECRYPTION_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
						return "Network and Computing Encrpytion/Decryption";
					case 0x10:
						return "Entertainment Encryption/Decryption";
					case 0x80:
						return "Other Encryption/Decryption";
				}
			}
			case CLASS_DATA_AND_SIGNAL_CONTROLLER:
			{
				switch(subClass)
				{
					case 0:
						return "DPIO Modules";
					case 1:
						return "Performance Counters";
					case 0x10:
						return "Communications Syncrhonization Plus Time and Frequency Test/Measurment";
					case 0x20:
						return "Management Card";
					case 0x80:
						return "Other Data Acquisition/Signal Processing Controller";
				}
			}
			default:
				return "Unknown";
		}
		return "Unknown";
	}
	/* Identify the Device type with the headerType as an argument
	    Possible return values are "PCI Device", "PCI-to-PCI Bridge" or "CardBus Bridge"
	    Returns a pointer to a device type string
	    Returns "Invalid" on error
	    */
	const char* IdentifyDeviceType(uint16_t headerType)
	{
		if(headerType == 0)
			return "PCI Device";
		else if(headerType == 1)
			return "PCI-to-PCI Bridge";
		else if(headerType == 2)
			return "CardBus Bridge";

		return "Invalid";
	}
	/* This function checks the vendorID against a bunch of common vendor strings
	   like nvidia, intel, etc...
	   Returns a pointer to a vendor string
	   */
	const char* IdentifyCommonVendors(uint16_t vendorID)
	{
		switch(vendorID)
		{
		case 0x10DE:
			return "NVIDIA";
		case 0x8086:
			return "Intel";
		case 0x1002:
		case 0x1022:
			return "AMD";
		case 0x10EC:
			return "Realtek";
		case 0x121A:
			return "3DFX"; // 3dfx isn't relevent anymore, but...
		case 0x5143:
			return "Qualcomm";
		default:
			return "Unknown vendor";
		}
	}
	uint16_t pci_config_read_word (uint8_t bus, uint8_t slot,
                                    uint8_t func, uint8_t offset)
        {
           uint32_t address;
           uint32_t lbus  = (uint32_t)bus;
           uint32_t lslot = (uint32_t)slot;
           uint32_t lfunc = (uint32_t)func;
           uint16_t tmp = 0;

           /* create configuration address as per Figure 1 */
           address = (uint32_t)((lbus << 16) | (lslot << 11) |
                     (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

           /* write out the address */
           outl (CONFIG_ADDRESS, address);
           /* read in the data */
           /* (offset & 2) * 8) = 0 will choose the first word of the 32 bits register */
           tmp = (uint16_t)((inl (CONFIG_DATA) >> ((offset & 2) * 8)) & 0xffff);
           return (tmp);
        }
	uint32_t pci_config_read_dword (uint8_t bus, uint8_t slot,
                                    uint8_t func, uint8_t offset)
        {
           uint32_t address;
           uint32_t lbus  = (uint32_t)bus;
           uint32_t lslot = (uint32_t)slot;
           uint32_t lfunc = (uint32_t)func;
           uint32_t tmp = 0;

           /* create configuration address as per Figure 1 */
           address = (uint32_t)((lbus << 16) | (lslot << 11) |
                     (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

           /* write out the address */
           outl (CONFIG_ADDRESS, address);
           /* read in the data */
           tmp = (uint32_t)((inl (CONFIG_DATA)));
           return (tmp);
        }
void pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outl(CONFIG_DATA, data);
}
void pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outw(CONFIG_DATA, data);
}
	PCIDevice *linked_list = NULL;
	PCIDevice* last = NULL;
	void* pci_check_function(uint8_t bus, uint8_t device, uint8_t function)
	{
		// Get vendorID
		uint16_t vendorID = (uint16_t)(pci_config_read_dword(bus, device, function,0) & 0x0000ffff);
		if(vendorID == 0xFFFF) //Invalid function
			return NULL;
		// Get vendor string from common vendors
		const char* vendor = IdentifyCommonVendors(vendorID);
		// Get device ID
		uint16_t deviceID = (pci_config_read_dword(bus, device, function,0) >> 16);
		// Get Device Class
		uint8_t pciClass = (uint8_t)(pci_config_read_word(bus, device, function , 0xA)>>8);
		// Get Device SubClass
		uint8_t subClass = (uint8_t)pci_config_read_word(bus,device, function, 0xB);
		// Get ProgIF
		uint8_t progIF = (uint8_t)(pci_config_read_word(bus, device, function,0xC)>>8);
		// What a nice variable name :D
		const char* function_function = IdentifyDeviceFunction(pciClass, subClass, progIF); /* Get the device's
		function */
		// Set up the meta-data
		PCIDevice* dev = malloc(sizeof(PCIDevice));
		if(!dev)
			panic("pci: early unrecoverable oom\n");
		memset(dev, 0 , sizeof(PCIDevice));
		dev->slot = bus;
		dev->function = function;
		dev->device = device;
		dev->function_string = (char*)function_function;
		dev->vendor_string = (char*)vendor;
		dev->vendorID = vendorID;
		dev->deviceID = deviceID;
		dev->pciClass = pciClass;
		dev->subClass = subClass;
		dev->progIF = progIF;
		// Put it on the linked list
		last->next = dev;
		last = dev;

		return dev;

	}
	void pci_check_devices()
	{
		for(uint16_t slot = 0; slot < 256; slot++)
		{
			for(uint16_t device = 0; device < 32; device++)
			{
				//uint8_t function = 0;
				// Get vendor
				uint16_t vendor = (uint16_t)(pci_config_read_dword(slot, device, 0,0) & 0x0000ffff);

				if(vendor == 0xFFFF) //Invalid, just skip this device
					break;

				//INFO("pci", "Found a device at slot %d, device %d, function %d: ",slot,device,0);

				// Check the vendor against a bunch of mainstream hardware developers
				//printf("Vendor: %s\n", IdentifyCommonVendors(vendor));
				//printf("DeviceID: %X\n", pci_config_read_dword(slot, device, 0,0) >> 16);

				// Get header type
				uint16_t header = (uint16_t)(pci_config_read_word(slot, device, 0,0xE));

				//printf("Device type: %s\n",IdentifyDeviceType(header & 0x7F));
				uint8_t pciClass = (uint8_t)(pci_config_read_word(slot, device, 0 , 0xA)>>8);
				uint8_t subClass = (uint8_t)pci_config_read_word(slot,device, 0, 0xB);
				uint8_t progIF = (uint8_t)(pci_config_read_word(slot, device, 0,0xC)>>8);
				//printf("Function of Device: %s\n", IdentifyDeviceFunction(pciClass, subClass, progIF));

				// Set up some meta-data
				PCIDevice* dev = malloc(sizeof(PCIDevice));
				if(!dev)
					panic("pci: early unrecoverable oom\n");
				memset(dev, 0 , sizeof(PCIDevice));
				dev->slot = slot;
				dev->function = 0;
				dev->device = device;
				dev->function_string = (char*)IdentifyDeviceFunction(pciClass, subClass, progIF);
				dev->vendor_string = (char*)IdentifyCommonVendors(vendor);
				dev->vendorID = vendor;
				dev->deviceID = (pci_config_read_dword(slot, device, 0,0) >> 16);
				dev->pciClass = pciClass;
				dev->subClass = subClass;
				dev->progIF = progIF;
				// If last is not NULL (it is at first), set this device as the last node's next
				if(likely(last))
					last->next = dev;
				else
					linked_list = dev;


				last = dev;
				if(header & 0x80)
				{
					for(int i = 1; i < 8;i++)
					{
						PCIDevice* dev = pci_check_function(slot, device, i);
						if(!dev)
							continue;
						//INFO("pci", "Found PCI device at bus %d, device %d, function %d\n", dev->slot, dev->device,
						//dev->function);
						//printf("Device function: %s\n",dev->function_string);

					}
				}
			}
		}
	}
pcibar_t* pci_get_bar(uint8_t slot, uint8_t device, uint8_t function, uint8_t barindex)
{
	uint8_t offset = 0x10 + 0x4 * barindex;
	uint32_t i = pci_config_read_dword(slot, device,function,offset);
	pcibar_t* pcibar = malloc(sizeof(pcibar_t));
	if(!pcibar)
		return NULL;
	pcibar->address = i & 0xFFFFFFF0;
	pcibar->isIO = i & 1;
	if(i & 1)
		pcibar->address = i & 0xFFFFFFFC;
	pcibar->isPrefetchable = i & 4;
	pci_write_dword(slot, device, function, offset, 0xFFFFFFFF);
	size_t size = (~((pci_config_read_dword(slot, device,function,offset) & 0xFFFFFFF0))) + 1;
	pcibar->size = size;
	pci_write_dword(slot, device,function,offset, i);
	return pcibar;
}
uint16_t pci_get_intn(uint8_t slot, uint8_t device, uint8_t function)
{
	return acpi_get_irq_routing_for_dev(slot, device, function);
}
void pci_init()
{
	//LOG("pci", "Initializing the PCI driver\n");
	//LOG("pci", "Enumerating PCI devices\n");
	pci_check_devices();
}
PCIDevice *get_pcidev_from_vendor_device(uint16_t deviceid, uint16_t vendorid)
{
	for(PCIDevice *i = linked_list; i;i = i->next)
	{
		if(i->deviceID == deviceid && i->vendorID == vendorid)
			return i;
	}
	return NULL;
}
PCIDevice *get_pcidev_from_classes(uint8_t class, uint8_t subclass, uint8_t progif)
{
	for(PCIDevice *i = linked_list; i;i = i->next)
	{
		if(i->pciClass == class && i->subClass == subclass && i->progIF == progif)
			return i;
	}
	return NULL;
}
void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch)
{
	uint32_t bar = address | is_io | (is_prefetch << 2);
	pci_write_dword(slot, device, function, PCI_BARx(index), bar);
}
/* All the PCI drivers' headers */
#include <drivers/e1000.h>
#include <drivers/ata.h>
pci_driver_t pci_drivers[] =
{
	{E1000_DEV, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{E1000_I217, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{E1000_82577LM, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{0, 0, CLASS_MASS_STORAGE_CONTROLLER, 1, 0, PCI_DRIVER_GENERIC, ata_init},
};

const size_t pci_driver_array_entries = sizeof(pci_drivers) / sizeof(pci_driver_t);
void pci_initialize_drivers()
{
	for(size_t i = 0; i < pci_driver_array_entries; i++)
	{
		if(pci_drivers[i].driver_type == PCI_DRIVER_GENERIC)
		{
			PCIDevice *dev = get_pcidev_from_classes(pci_drivers[i].pciClass, pci_drivers[i].subClass, pci_drivers[i].progIF);
			if(!dev)
				continue;
			pci_drivers[i].cb(dev);
		}	
		else
		{
			PCIDevice *dev = get_pcidev_from_vendor_device(pci_drivers[i].deviceID, pci_drivers[i].vendorID);
			if(!dev)
				continue;
			pci_drivers[i].cb(dev);
		}
			
	}
}