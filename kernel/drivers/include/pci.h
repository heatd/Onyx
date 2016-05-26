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
#ifndef _PCI_H
#define _PCI_H
#include <stdint.h>
#include <kernel/portio.h>

class PCIDevice
{
private:
	uint16_t deviceID, vendorID;
	char* vendorString, *functionString;
	uint8_t slot, device, function;
	uint8_t pciClass, subClass, progIF;
public:
	PCIDevice* next;
	PCIDevice(uint16_t deviceID, uint16_t vendorID, const char* vendorString, const char* functionString, uint8_t slot,
	uint8_t device, uint8_t function, uint8_t pciClass, uint8_t subClass, uint8_t progIF);
	uint8_t getSlot(){return slot;}
	uint8_t getDevice(){return device;}
	uint8_t getFunction(){return function;}
	uint8_t getPciClass(){return pciClass;}
	uint8_t getSubClass(){return subClass;}
	uint8_t getProgIF(){return progIF;}
	char* getVendorString(){return vendorString;}
	char* getFunctionString(){return functionString;}
	uint16_t getDeviceID(){return deviceID;}
	uint16_t getVendorID(){return vendorID;}
};
namespace PCI
{
	extern "C++"
	{
	const uint16_t CONFIG_ADDRESS = 0xCF8;
	const uint16_t CONFIG_DATA = 0xCFC;
	const uint16_t CLASS_MASS_STORAGE_CONTROLLER = 0x1;
	const uint16_t CLASS_NETWORK_CONTROLLER = 0x2;
	const uint16_t CLASS_DISPLAY_CONTROLLER = 0x3;
	const uint16_t CLASS_MULTIMEDIA_CONTROLLER = 0x4;
	const uint16_t CLASS_MEMORY_CONTROLLER = 0x5;
	const uint16_t CLASS_BRIDGE_DEVICE = 0x6;
	const uint16_t CLASS_COMMUNICATIONS_CONTROLLER = 0x7;
	const uint16_t CLASS_BASE_SYSTEM_PERIPHERALS = 0x8;
	const uint16_t CLASS_INPUT_DEVICES = 0x9;
	const uint16_t CLASS_DOCKING_STATIONS = 0xA;
	const uint16_t CLASS_PROCESSORS = 0xB;
	const uint16_t CLASS_SERIAL_BUS_CONTROLLER = 0xC;
	const uint16_t CLASS_WIRELESS_CONTROLLER = 0xD;
	const uint16_t CLASS_INTELIGENT_CONTROLLER = 0xE;
	const uint16_t CLASS_SATELLITE_CONTROLLER = 0xF;
	const uint16_t CLASS_ENCRYPTION_DECRYPTION_CONTROLLER = 0x10;
	const uint16_t CLASS_DATA_AND_SIGNAL_CONTROLLER = 0x11;
	void Init();
	uint16_t ConfigReadWord (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
	void CheckDevices();
	uint32_t ConfigReadDword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
	const char* IdentifyCommonVendors(uint16_t vendorID);
	const char* IdentifyDeviceType(uint16_t headerType);
	const char* IdentifyDeviceFunction(uint8_t pciClass, uint8_t subClass, uint8_t progIF);
	}
	typedef struct
	{
		uint32_t address;
		bool isPrefetchable;
		bool isIO;
	}PciBar_t;
};

#endif
