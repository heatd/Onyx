/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <drivers/pci.h>
#include <stdio.h>

namespace PCI
{
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
			case 1:
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
			case 2:
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
			case 3:
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
			case 4:
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
			case 5:
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
			case 6:
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
			case 7:
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
			case 8:
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
			case 9:
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
			case 0xA:
			{
				switch(subClass)
				{
					case 0:
						return "Generic Docking Station";
					case 0x80:
						return "Unknown Docking Station";
				}
			}
			case 0xB:
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
			case 0xC:
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
			case 0xD:
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
			case 0xE:
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
			case 0xF:
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
			case 0x10:
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
			case 0x11:
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
	const char* IdentifyDeviceType(uint16_t headerType)
	{
		if(headerType == 0)
			return "PCI Device";
		else if(headerType == 1)
			return "PCI-to-PCI Bridge";

		return "Invalid";
	}
	const char* IdentifyCommonVendors(uint16_t vendorID)
	{
		switch(vendorID)
		{
		case 0x10DE:
			return "NVIDIA";
		case 0x8086:
			return "Intel";
		case 0x1002 | 0x1022:
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
	uint16_t ConfigReadWord (uint8_t bus, uint8_t slot,
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
	uint32_t ConfigReadDword (uint8_t bus, uint8_t slot,
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
	void CheckDevices()
	{
		for(uint16_t slot = 0; slot < 256; slot++)
		{
			for(uint16_t device = 0; device < 32; device++)
			{
				// Get vendor
				uint16_t vendor = (uint16_t)(ConfigReadDword(slot, device, 0,0) & 0x0000ffff);
				if(vendor == 0xFFFF) //Invalid, just skip this device
					break;
				printf("Device: ");
				// Check the vendor against a bunch of mainstream hardware developers
				printf("Vendor: %s\n", IdentifyCommonVendors(vendor));
				printf("DeviceID: %x\n", ConfigReadDword(slot, device, 0,0) >> 16);
				// Get header type
				uint16_t header = (uint16_t)(ConfigReadDword(slot, device, 0,0xC) & 0x0000ffff);
				printf("Device type: %s\n",IdentifyDeviceType(header));
				// DON'T NAME THIS AS class, c++ recognizes this as a keyword
				uint8_t pciClass = (uint8_t)(ConfigReadWord(slot, device, 0 , 0xA)>>8);
				uint8_t subClass = (uint8_t)ConfigReadWord(slot,device, 0, 0xB);
				uint8_t progIF = (uint8_t)(ConfigReadWord(slot, device, 0,0xC)>>8);
				printf("Function of Device: %s\n", IdentifyDeviceFunction(pciClass, subClass, progIF));
			}
		}
	}
	void Init()
	{
		printf("Initializing the PCI driver\n");
		printf("Enumerating PCI devices\n");
		CheckDevices();
	}
};
