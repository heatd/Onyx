/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef DEVMGR_H
#define DEVMGR_H

#include <string>
#include <stdexcept>

#include <unistd.h>

enum class BusType
{
	PCI = 0,
	ACPI,
	USB
};

class Bus
{
private:
	std::string name;
	BusType type;
	int fd;
public:
	Bus(const std::string name, int fd) : name(name), fd(fd)
	{
		if(name == "pci" || name == "pcie")
			type = BusType::PCI;
		else if(name == "acpi")
			type = BusType::ACPI;
		else if(name == "usb")
			type = BusType::USB;
		else
			throw std::runtime_error("Unknown bus " + name);
	}

	virtual ~Bus()
	{
		if(fd)	close(fd);
	}

	virtual void EnumerateDevices() = 0;
};

#endif