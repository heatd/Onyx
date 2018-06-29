/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include <onyx/platform.h>
#include <onyx/idt.h>
#include <onyx/page.h>

#include <pci/pci.h>
#include <pci/pci-msi.h>

/* pci vector codes to number of vectors table */
unsigned int pci_to_num_vecs[] =
{
	1,
	2,
	4,
	8,
	16,
	32
};

extern char irq0_end;

int pci_enable_msi(struct pci_device *dev, irq_t handler)
{
	bool msix = false;
	(void) msix;
	/* TODO: Try to prioritize finding MSI-X capabiltiies */
	off_t offset = pci_find_capability(dev, PCI_CAP_ID_MSI);
	if(offset < 0)
	{
		msix = false;
		if((offset = pci_find_capability(dev, PCI_CAP_ID_MSI)) < 0)
			return -1; 
	}
	uint16_t message_control = pci_read(dev, offset + PCI_MSI_MESSAGE_CONTROL_OFF,
                                            sizeof(uint16_t));
	bool addr64 = message_control & PCI_MSI_MSGCTRL_64BIT;
	unsigned int num_vecs = pci_to_num_vecs[PCI_MSI_MSGCTRL_MMC(message_control)];
	struct pci_msi_data data;
	if(platform_allocate_msi_interrupts(num_vecs, addr64, &data) < 0)
		return -1;
	/* TODO: This is arch specific, and shouldn't be here */
	size_t irq_stub_size = (size_t) (&irq0_end - (char*) &irq0);
	unsigned int irq_offset = data.vector_start - 32;
	for(unsigned int i = 0; i < num_vecs; i++)
	{
		int vector = data.vector_start + i;
		void(*irq_stub_handler)() = (void*)((char*) &irq0 + irq_stub_size * 
		                            (irq_offset + i));
		x86_reserve_vector(vector, irq_stub_handler);
	}
	
	for(unsigned int i = 0; i < num_vecs; i++)
	{
		assert(install_irq(irq_offset + i, handler,
			(struct device *) dev, IRQ_FLAG_REGULAR, NULL) == 0);
	}

	message_control |= ilog2(num_vecs) << 4;
	message_control |= PCI_MSI_MSGCTRL_ENABLE;
	uint32_t message_addr = data.address;
	uint32_t message_addr_hi = data.address_high;
	uint32_t message_data = data.data;

	off_t message_data_off = addr64 ? offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 8 
                                 : offset + PCI_MSI_MESSAGE_ADDRESS_OFF + 4;
	/* Now write everything back */
	pci_write(dev, message_addr, offset + PCI_MSI_MESSAGE_ADDRESS_OFF, sizeof(uint16_t));
	if(addr64)	pci_write(dev, message_addr_hi, offset + 
	                          PCI_MSI_MESSAGE_ADDRESS_OFF + 4, sizeof(uint32_t));
	pci_write(dev, message_data, message_data_off, sizeof(uint16_t));
	pci_write(dev, message_control, offset + PCI_MSI_MESSAGE_CONTROL_OFF, sizeof(uint16_t));
	return 0;
}
