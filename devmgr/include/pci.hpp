/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _DEVMGR_PCI_HPP
#define _DEVMGR_PCI_HPP

#include "devmgr.hpp"

class PciBus : public Bus
{
private:

public:
	PciBus(const std::string& name, int fd) : Bus(name, fd)
	{}

	~PciBus();

	void EnumerateDevices() override;
};

#endif