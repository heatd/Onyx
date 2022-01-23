/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <onyx/driver.h>
#include <onyx/dev.h>
#include <onyx/memory.hpp>
#include <onyx/panic.h>

#include "ehci.hpp"

#include <pci/pci.h>


#define PCI_USB_HOST_CONTROLLER_SUBCLASS		0x3
#define PCI_USB2_HOST_CONTROLLER_PROGIF			0x20
#define PCI_USB2_HOST_CONTROLLER_REGISTER_SPACE_BAR	0

struct pci_id ehci_pci_ids[] = 
{
	{ PCI_ID_CLASS(CLASS_SERIAL_BUS_CONTROLLER,
		PCI_USB_HOST_CONTROLLER_SUBCLASS,
		PCI_USB2_HOST_CONTROLLER_PROGIF, NULL) },
	{ 0 }
};

void ehci_controller::stop_commands()
{
	auto reg = operational_reg_space.read<uint32_t>(ehci_op_regs::USBCMD);
	reg &= ~USBCMD_RUNSTOP;
	operational_reg_space.write<uint32_t>(ehci_op_regs::USBCMD, reg);
}

void ehci_controller::reset()
{
	stop_commands();

	while(!(operational_reg_space.read<uint32_t>(ehci_op_regs::USBSTS) & USBSTS_HCHALTED))
	{
		printk("%x\n", operational_reg_space.read<uint32_t>(ehci_op_regs::USBSTS));
		printk("%x\n", operational_reg_space.read<uint32_t>(ehci_op_regs::USBCMD));
		sched_sleep_ms(10);
	}

	operational_reg_space.write<uint32_t>(ehci_op_regs::FRINDEX, 0);

	auto reg = operational_reg_space.read<uint32_t>(ehci_op_regs::USBCMD);

	reg |= USBCMD_HCRESET;

	operational_reg_space.write<uint32_t>(ehci_op_regs::USBCMD, reg);
	/* Wait for the reset to be over */
	while(operational_reg_space.read<uint32_t>(ehci_op_regs::USBCMD) & USBCMD_HCRESET)
		sched_sleep_ms(10);
}

bool ehci_controller::init()
{
	printk("revision number: %04x\n", host_controller_space.read<uint16_t>(ehci_cap_regs::HCIVERSION));
	auto op_offset = host_controller_space.read<uint8_t>(ehci_cap_regs::CAPLENGTH);
	unsigned long operational_base = (unsigned long) host_controller_space.as_ptr() + op_offset;

	operational_reg_space.set_base(reinterpret_cast<volatile void *>(operational_base));

	printk("USBCMD: %x\n", operational_reg_space.read<uint32_t>(ehci_op_regs::USBSTS));
	reset();
	printk("USBCMD: %x\n", operational_reg_space.read<uint32_t>(ehci_op_regs::USBSTS));

	return true;
}

ehci_controller::~ehci_controller()
{}

int ehci_probe(struct device *__dev)
{
	auto dev = reinterpret_cast<pci::pci_device *>(__dev);

	auto addr = dev->addr();

	printk("EHCI device found at %04x:%02x:%02x:%02x!\n",
		addr.segment, addr.bus, addr.device, addr.function);
	
	void *buffer = dev->map_bar(PCI_USB2_HOST_CONTROLLER_REGISTER_SPACE_BAR, VM_NOCACHE);
	if(!buffer)
	{
		printk("ehci: failed to map bar\n");
		return -1;
	}

	auto ehci_drv = make_unique<ehci_controller>(dev, static_cast<volatile uint8_t *>(buffer));

	if(!ehci_drv)
	{
		panic("implement bar destruction");
		return -1;
	}

	if(!ehci_drv->init())
	{
		panic("implement bar destruction");
		printk("ehci: initialization failed\n");
		return -1;
	}

	ehci_drv.release();

	return 0;
}

struct driver ehci_driver_struct
{
	.name = "ehci",
	.devids = &ehci_pci_ids,
	.probe = ehci_probe,
	.bus_type_node = {&ehci_driver_struct}
};

int ehci_init()
{
	printk("ehci init\n");
	pci::register_driver(&ehci_driver_struct);
	return 0;
}
