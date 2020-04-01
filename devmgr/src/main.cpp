/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#define _BSD_SOURCE
#include <iostream>
#include <string>
#include <string.h>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <dirent.h>

#include <mutex>
#include <memory>

#include "../include/devmgr.hpp"
#include "../include/pci.hpp"
#include "../include/fd_wrapper.hpp"

class Device
{
private:
	std::string name;
public:
	Device(std::string name) : name(name)
	{
	}
	~Device()
	{}
};

void Bus::EnumerateDevices()
{
	DIR *nd = fdopendir(fd);
	if(!nd)
	{
		perror("fdopendir");
		throw std::runtime_error("Failed to create DIR");
	}

	struct dirent *d;
	while((d = readdir(nd)) != NULL)
	{
		
	}
}

namespace DeviceManager
{

std::vector<std::shared_ptr<Bus> > bus_list;


BusType BusNameToType(const std::string& name)
{
	BusType type;

	if(name == "pcie" || name == "pci")
		type = BusType::PCI;
	else if(name == "acpi")
		type = BusType::ACPI;
	else if(name == "usb")
		type = BusType::USB;
	else
		throw std::runtime_error("Unknown bus " + name);

	return type;
}

int EnumerateBuses(int fd)
{
	DIR *nd = fdopendir(fd);
	if(!nd)
	{
		perror("Error opening dir\n");
		return -1;
	}

	struct dirent *d;
	while((d = readdir(nd)) != NULL)
	{
		int bus_fd = openat(fd, d->d_name, O_DIRECTORY | O_RDWR);
		if(bus_fd < 0)
		{
			perror("openat");
			throw std::runtime_error("Failed to open /sys/bus/" + std::string(d->d_name));
		}

		const std::string name(d->d_name);
		auto type = BusNameToType(name);
	
		std::shared_ptr<Bus> dev;

		switch(type)
		{
			case BusType::PCI:
				dev = std::make_shared<PciBus>(name, bus_fd);
			default:
				continue;
		}

		bus_list.push_back(std::move(dev));

		dev->EnumerateDevices();
	}

	return 0;
}

};

int main(int argc, char **argv, char **envp)
{
	struct stat buf;
	int fd = open("/sys/bus", O_RDONLY | O_DIRECTORY);
	if(fd < 0)
	{
		perror("Could not open /sys/bus");
		return 1;
	}

	DeviceManager::EnumerateBuses(fd);
	

	while(1)
		sleep(10000);
}
