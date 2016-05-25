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
				printf("Vendor: ");
				switch(vendor)
				{
				case 0x10DE:
					printf("nvidia\n");
					break;
				case 0x8086:
					printf("intel\n");
					break;
				case 0x1002 | 0x1022:
					printf("amd\n");
					break;
				case 0x10EC:
					printf("realtek\n");
					break;
				case 0x121A:
					printf("3dfx\n");
					break;
				case 0x5143:
					printf("qualcomm\n");
					break;
				default:
					printf("Unknown vendor (%X)\n",vendor);
				}
				printf("DeviceID: %x\n", ConfigReadDword(slot, device, 0,0) >> 16);
				// Get header type
				uint16_t header = (uint16_t)(ConfigReadDword(slot, device, 0,0xC) & 0x0000ffff);
				printf("Device type: ");
				switch(header)
				{
				case 0:
					printf("PCI Device\n");
					break;
				case 1:
					printf("PCI-to-PCI bridge\n");
					break;
				}
				// DON'T NAME THIS AS class, c++ recognizes this as a keyword
				uint8_t pciClass = (uint8_t)(ConfigReadWord(slot, device, 0 , 0xA)>>8);
				uint8_t subClass = (uint8_t)ConfigReadWord(slot,device, 0, 0xB);
				switch(pciClass)
				{
					case 0:
					{
						switch(subClass)
						{
							case 1:
								printf("VGA-compatible device\n");
								break;
						}
						break;
					}
					case 1:
					{
						switch(subClass)
						{
							case 0:
							{
								printf("SCSI Bus Controller\n");
								break;
							}
							case 1:
							{
								printf("IDE Controller\n");
								break;
							}
							case 2:
							{
								printf("Floppy Disk Controller\n");
								break;
							}
							case 3:
							{
								printf("IPI Bus Controller\n");
								break;
							}
							case 4:
							{
								printf("RAID Controller\n");
								break;
							}
							case 5:
							{
								printf("ATA Controller\n");
								break;
							}
							case 6:
							{
								printf("Serial ATA\n");
								break;
							}
							case 7:
							{
								printf("Serial attached SCSI\n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Mass Storage Controller\n");
								break;
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
								printf("Ethernet Controller\n");
								break;
							}
							case 1:
							{
								printf("Token Ring Controller \n");
								break;
							}
							case 2:
							{
								printf("FDDI Controller \n");
								break;
							}
							case 3:
							{
								printf("ATM Controller \n");
								break;
							}
							case 4:
							{
								printf("ISDN Controller\n");
								break;
							}
							case 5:
							{
								printf("WorldFip Controller \n");
								break;
							}
							case 6:
							{
								printf("PICMG 2.14 Multi Computing \n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Ethernet Controller\n");
								break;
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
								printf("VGA-compatible Controller\n");
								break;
							}
							case 1:
							{
								printf("XGA Controller \n");
								break;
							}
							case 2:
							{
								printf("3D Controller\n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Display Controller \n");
								break;
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
								printf("Video Device \n");
								break;
							}
							case 1:
							{
								printf("Audio Device \n");
								break;
							}
							case 2:
							{
								printf("Computer Telephony Device \n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Multimedia Device \n");
								break;
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
								printf("RAM Controller\n");
								break;
							}
							case 1:
							{
								printf("Flash Controller\n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Memory Controller\n");
								break;
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
								printf("Host Bridge \n");
								break;
							}
							case 1:
							{
								printf("ISA Bridge \n");
								break;
							}
							case 2:
							{
								printf("EISA Bridge \n");
								break;
							}
							case 3:
							{
								printf("MCA Bridge \n");
								break;
							}
							case 4:
							{
								printf("PCI-to-PCI Bridge \n");
								break;
							}
							case 5:
							{
								printf("PCMCIA Bridge \n");
								break;
							}
							case 6:
							{
								printf("NuBus Bridge \n");
								break;
							}
							case 7:
							{
								printf("CardBus Bridge \n");
								break;
							}
							case 8:
							{
								printf("RACEway Bridge \n");
								break;
							}
							case 9:
							{
								printf("ENOTIMPLEMENTED \n");
								break;
							}
							case 0xA:
							{
								printf("InfiniBrand-to-PCI Host Bridge \n");
								break;
							}
							case 0x80:
							{
								printf("Unknown Bridge Device\n");
								break;
							}
						}
						break;
					}
					case 7:
					{
						//SKIP this because of heavy use of Prog.IF, which I still need to add support
						switch(subClass)
						{
						}
						break;
					}
					case 8:
					{
						switch(subClass)
						{
							case 4:
							{
								printf("Genetic PCI Hot-plug Controller\n");
								break;
							}
							case 0x80:
							{
								printf("Unknown System Peripheral\n");
								break;
							}
						}
						break;
					}
					case 9:
					{
						switch(subClass)
						{

						}
					}
					case 0xA:
					{
						switch(subClass)
						{

						}
					}
					case 0xB:
					{
						switch(subClass)
						{

						}
					}
					case 0xC:
					{
						switch(subClass)
						{

						}
					}
					case 0xD:
					{
						switch(subClass)
						{

						}
					}
					case 0xE:
					{
						switch(subClass)
						{

						}
					}
					case 0xF:
					{
						switch(subClass)
						{

						}
					}
					case 0x10:
					{
						switch(subClass)
						{

						}
					}
					case 0x11:
					{
						switch(subClass)
						{

						}
					}
					default:
						printf("Unknown function\n");
						break;
				}
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
